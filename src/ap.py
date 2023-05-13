"""
This is a self-contained, bare-bones access point using Scapy.

It can:
1) Respond to Probe requests
2) Allow a station to associate with WPA2 + CCMP
3) Send traffic to/from a TAP tunnel device

It has no protocol security -- use at your own risk.

This is built with snippets from several sources:
1) pyaes https://github.com/ricmoo/pyaes
2) libwifi https://github.com/vanhoefm/libwifi
3) https://github.com/rpp0/scapy-fakeap
4) hostapd's testing suite
"""

import random
import hmac, hashlib
import os
import fcntl

from itertools import count
import pyaes
import threading
import binascii
import subprocess


from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import *
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.dhcp import *
from scapy.fields import *
from scapy.arch import str2mac, get_if_raw_hwaddr

from time import time, sleep


class Level:
    CRITICAL = 0
    WARNING = 1
    INFO = 2
    DEBUG = 3
    BLOAT = 4


VERBOSITY = Level.BLOAT


def printd(string, level):
    if VERBOSITY >= level:
        print(string)


### Constants

# CCMP, PSK=WPA2
eRSN = Dot11EltRSN(
    ID=48,
    len=20,
    version=1,
    mfp_required=0,
    mfp_capable=0,
    group_cipher_suite=RSNCipherSuite(cipher="CCMP-128"),
    nb_pairwise_cipher_suites=1,
    pairwise_cipher_suites=RSNCipherSuite(cipher="CCMP-128"),
    nb_akm_suites=1,
    akm_suites=AKMSuite(suite="PSK"),
)
RSN = eRSN.build()

AP_RATES = b"\x0c\x12\x18\x24\x30\x48\x60\x6c"

DOT11_MTU = 4096

DOT11_TYPE_MANAGEMENT = 0
DOT11_TYPE_CONTROL = 1
DOT11_TYPE_DATA = 2

DOT11_SUBTYPE_DATA = 0x00
DOT11_SUBTYPE_PROBE_REQ = 0x04
DOT11_SUBTYPE_AUTH_REQ = 0x0B
DOT11_SUBTYPE_ASSOC_REQ = 0x00
DOT11_SUBTYPE_REASSOC_REQ = 0x02
DOT11_SUBTYPE_QOS_DATA = 0x28


IFNAMSIZ = 16
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA


def set_ip_address(dev, ip):
    if subprocess.call(["ip", "addr", "add", ip, "dev", dev]):
        printd("Failed to assign IP address %s to %s." % (ip, dev), Level.CRITICAL)

    if subprocess.call(["ip", "link", "set", "dev", dev, "up"]):
        printd("Failed to bring device %s up." % dev, Level.CRITICAL)


class TunInterface(threading.Thread):
    def __init__(self, ap, name=b"scapyap"):
        threading.Thread.__init__(self)

        if len(name) > IFNAMSIZ:
            raise Exception("Tun interface name cannot be larger than " + str(IFNAMSIZ))

        self.name = name
        self.daemon = True
        self.ap = ap

        # Virtual interface
        self.fd = os.open("/dev/net/tun", os.O_RDWR)
        ifr_flags = IFF_TAP | IFF_NO_PI  # Tun device without packet information
        ifreq = struct.pack("16sH", name, ifr_flags)
        fcntl.ioctl(self.fd, TUNSETIFF, ifreq)  # Syscall to create interface

        # Assign IP and bring interface up
        set_ip_address(name, self.ap.ip)

        print(
            "Created TUN interface %s at %s. Bind it to your services if needed."
            % (name, self.ap.ip)
        )

    def write(self, pkt):
        os.write(self.fd, pkt.build())

    def read(self):
        try:
            raw_packet = os.read(self.fd, DOT11_MTU)
            return raw_packet
        except Exception as e:
            print(e)

    def close(self):
        os.close(self.fd)

    def run(self):
        while True:
            raw_packet = self.read()
            self.ap.tun_data_incoming(raw_packet)


class Station:
    def __init__(self, mac):
        self.mac = mac
        self.associated = False


# Ripped from scapy-latest with fixes
class EAPOL_KEY(Packet):
    name = "EAPOL_KEY"
    fields_desc = [
        ByteEnumField("key_descriptor_type", 1, {1: "RC4", 2: "RSN"}),
        # Key Information
        BitField("reserved2", 0, 2),
        BitField("smk_message", 0, 1),
        BitField("encrypted_key_data", 0, 1),
        BitField("request", 0, 1),
        BitField("error", 0, 1),
        BitField("secure", 0, 1),
        BitField("has_key_mic", 1, 1),
        BitField("key_ack", 0, 1),
        BitField("install", 0, 1),
        BitField("key_index", 0, 2),
        BitEnumField("key_type", 0, 1, {0: "Group/SMK", 1: "Pairwise"}),
        BitEnumField(
            "key_descriptor_type_version",
            0,
            3,
            {1: "HMAC-MD5+ARC4", 2: "HMAC-SHA1-128+AES-128", 3: "AES-128-CMAC+AES-128"},
        ),
        #
        LenField("key_length", None, "H"),
        LongField("key_replay_counter", 0),
        XStrFixedLenField("key_nonce", b"\x00" * 32, 32),
        XStrFixedLenField("key_iv", b"\x00" * 16, 16),
        XStrFixedLenField("key_rsc", b"\x00" * 8, 8),
        XStrFixedLenField("key_id", b"\x00" * 8, 8),
        XStrFixedLenField("key_mic", b"\x00" * 16, 16),  # XXX size can be 24
        LenField("wpa_key_length", None, "H"),
        ConditionalField(
            XStrLenField(
                "key", b"\x00" * 16, length_from=lambda pkt: pkt.wpa_key_length
            ),
            lambda pkt: pkt.wpa_key_length and pkt.wpa_key_length > 0,
        ),
    ]

    def extract_padding(self, s):
        return s[: self.key_length], s[self.key_length :]

    def hashret(self):
        return struct.pack("!B", self.type) + self.payload.hashret()

    def answers(self, other):
        if (
            isinstance(other, EAPOL_KEY)
            and other.descriptor_type == self.descriptor_type
        ):
            return 1
        return 0


def pad_key_data(plain):
    pad_len = len(plain) % 8
    if pad_len:
        plain += b"\xdd" * (8 - pad_len)
    return plain


#### Helpers from maty van hoef's libwifi
def ccmp_pn(pn):
    return pn.PN0 + (pn.PN1 << 8) + (pn.PN2 << 16) + (pn.PN3 << 24)


def addr2bin(addr):
    return binascii.a2b_hex(addr.replace(":", ""))


def ccmp_get_nonce(priority, addr, pn):
    """
    CCMP nonce = 1 byte priority, 6 byte sender addr, 6 byte PN.
    """
    return struct.pack("B", priority) + addr2bin(addr) + pn2bin(pn)


def ccmp_get_aad(p, amsdu_spp=False):
    # FC field with masked values
    fc = raw(p)[:2]
    # data mask
    fc = struct.pack("<BB", fc[0] & 0x8F, fc[1] & 0xC7)

    # Sequence number is masked, but fragment number is included
    sc = struct.pack("<H", p.SC & 0xF)

    addr1 = addr2bin(p.addr1)
    addr2 = addr2bin(p.addr2)
    addr3 = addr2bin(p.addr3)
    aad = fc + addr1 + addr2 + addr3 + sc
    if Dot11QoS in p:
        if not amsdu_spp:
            # Everything except the TID is masked
            aad += struct.pack("<H", p[Dot11QoS].TID)
        else:
            # TODO: Mask unrelated fields
            aad += raw(p[Dot11QoS])[:2]
    return aad


def pn2bytes(pn):
    pn_bytes = [0] * 6
    for i in range(6):
        pn_bytes[i] = pn & 0xFF
        pn >>= 8
    return pn_bytes


def pn2bin(pn):
    return struct.pack(">Q", pn)[2:]


def dot11_get_seqnum(p):
    return p.SC >> 4


def dot11_is_encrypted_data(p):
    # All these different cases are explicitly tested to handle older scapy versions
    return (
        (p.FCfield & 0x40)
        or Dot11CCMP in p
        or Dot11TKIP in p
        or Dot11WEP in p
        or Dot11Encrypted in p
    )


def payload_to_iv(payload):
    iv0 = payload[0]
    iv1 = payload[1]
    wepdata = payload[4:8]

    # FIXME: Only CCMP is supported (TKIP uses a different IV structure)
    return orb(iv0) + (orb(iv1) << 8) + (struct.unpack(">I", wepdata)[0] << 16)


def dot11_get_priority(p):
    if not Dot11QoS in p:
        return 0
    return p[Dot11QoS].TID


def dot11_get_iv(p):
    # The simple and default case
    if Dot11CCMP in p:
        payload = raw(p[Dot11CCMP])
        return payload_to_iv(payload)
    # Scapy uses Dot11Encrypted if it couldn't determine how the frame was encrypted. Assume CCMP.
    elif Dot11Encrypted in p:
        payload = raw(p[Dot11Encrypted])
        return payload_to_iv(payload)
    # Couldn't determine the IV
    return None


def is_broadcast(ether):
    return ether == "ff:ff:ff:ff:ff:ff"

def is_multicast(ether):
    return int(ether[0:2], 16) & 0x1 == 1


### CCMP wrapper. See RFC 3610
class CCMPCrypto:
    @staticmethod
    def cbc_mac(key, plaintext, aad, nonce, iv=b"\x00" * 16, mac_len=8):
        assert len(key) == len(iv) == 16  # aes-128
        assert len(nonce) == 13
        iv = int.from_bytes(iv, byteorder="big")
        assert len(aad) < (2**16 - 2**8)

        q = L = 2
        Mp = (mac_len - 2) // 2
        assert q == L
        has_aad = len(aad) > 0
        flags = 64 * has_aad + 8 * Mp + (q - 1)
        b_0 = struct.pack("B", flags) + nonce + struct.pack(">H", len(plaintext))
        assert len(b_0) == 16

        a = struct.pack(">H", len(aad)) + aad
        if len(a) % 16 != 0:
            a += b"\x00" * (16 - len(a) % 16)
        blocks = b_0 + a
        blocks += plaintext

        if len(blocks) % 16 != 0:
            blocks += b"\x00" * (16 - len(blocks) % 16)

        encrypt = pyaes.AESModeOfOperationECB(key).encrypt
        prev = iv
        for i in range(0, len(blocks), 16):
            inblock = int.from_bytes(blocks[i : i + 16], byteorder="big")
            outblock = encrypt(int.to_bytes(inblock ^ prev, length=16, byteorder="big"))
            prev = int.from_bytes(outblock, byteorder="big")

        # xor tag with E(0) construction using nonce in CTR mode
        xn = struct.pack("B", q - 1) + nonce + b"\x00" * L
        ctr_nonce = int.from_bytes(xn, byteorder="big")
        xctr = pyaes.AESModeOfOperationCTR(
            key, counter=pyaes.Counter(ctr_nonce)
        ).encrypt
        xs0 = xctr(b"\x00" * 16)
        s_0 = int.from_bytes(xs0, byteorder="big")

        return int.to_bytes(s_0 ^ prev, length=16, byteorder="big")[:mac_len]

    @staticmethod
    def ctr_encrypt(key, nonce, plaintext, q=2, L=2):
        xn = struct.pack("B", q - 1) + nonce + b"\x00" * L
        ctr_nonce = int.from_bytes(xn, byteorder="big")
        xctr = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(ctr_nonce))
        # start ctr
        _ = xctr.encrypt(b"\x00" * 16)
        return xctr.encrypt(plaintext)

    @staticmethod
    def run_ccmp_encrypt(key, nonce, aad, plaintext):
        tag = CCMPCrypto.cbc_mac(key, plaintext, aad, nonce)
        encrypted = CCMPCrypto.ctr_encrypt(key, nonce, plaintext)
        return encrypted, tag

    @staticmethod
    def run_ccmp_decrypt(key, nonce, aad, ciphertext, known_tag):
        valid = False
        # ctr encrypt/decrypt is symmetric
        plaintext = CCMPCrypto.ctr_encrypt(key, nonce, ciphertext)
        tag = CCMPCrypto.cbc_mac(key, plaintext, aad, nonce)
        # constant time compare validity of tag
        valid = hmac.compare_digest(tag, known_tag)
        return plaintext, valid

    @staticmethod
    def test():
        k = b"k" * 16
        a = b"a" * 22
        n = b"n" * 13
        p = b"P" * 128
        cipher, tag = CCMPCrypto.run_ccmp_encrypt(k, n, a, p)
        p2, verified = CCMPCrypto.run_ccmp_decrypt(k, n, a, cipher, tag)
        assert p == p2
        assert verified
        return True

def if_hwaddr(iff):
    return str2mac(get_if_raw_hwaddr(iff)[1])

def aes_wrap(kek, plain):
    n = len(plain) // 8
    a = 0xA6A6A6A6A6A6A6A6
    enc = pyaes.AESModeOfOperationECB(kek).encrypt
    r = [plain[i * 8 : (i + 1) * 8] for i in range(0, n)]
    for j in range(6):
        for i in range(1, n + 1):
            b = enc(struct.pack(">Q", a) + r[i - 1])
            a = struct.unpack(">Q", b[:8])[0] ^ (n * j + i)
            r[i - 1] = b[8:]
    return struct.pack(">Q", a) + b"".join(r)


def customPRF512(key, amac, smac, anonce, snonce):
    """Source https://stackoverflow.com/questions/12018920/"""
    A = b"Pairwise key expansion"
    B = b"".join(sorted([amac, smac]) + sorted([anonce, snonce]))
    num_bytes = 64
    R = b""
    for i in range((num_bytes * 8 + 159) // 160):
        R += hmac.new(key, A + chb(0x00) + B + chb(i), hashlib.sha1).digest()
    return R[:num_bytes]


class AP:
    def __init__(self, iface, ssid, psk):
        self.IPS = []
        self.stations = {}
        self.interface = iface
        self.PSK = psk
        self.ssids = [ssid]
        self.current_ssid_index = 0
        self.mac = if_hwaddr(iface)
        self.channel = 1
        self.mutex = threading.Lock()
        self.sc = 0
        self.aid = 0
        self.boottime = time()
        self.bpffilter = "not ( wlan type mgt subtype beacon )"
        # " and ((ether dst host " + self.mac + ") or (ether dst host ff:ff:ff:ff:ff:ff))"
        self.hidden = False
        self.ip = "10.1.2.1/24"

        self.beaconTransmitter = self.BeaconTransmitter(self)
        self.tunnel = TunInterface(self)

    def get_radiotap_header(self):
        return RadioTap()

    def get_ssid(self):
        if len(self.ssids) > 0:
            return self.ssids[self.current_ssid_index]

    def next_sc(self):
        self.mutex.acquire()
        self.sc = (self.sc + 1) % 4096
        temp = self.sc
        self.mutex.release()

        return temp * 16  # Fragment number -> right 4 bits

    def next_aid(self):
        self.mutex.acquire()
        self.aid = (self.aid + 1) % 2008
        temp = self.aid
        self.mutex.release()
        return temp

    def current_timestamp(self):
        return int((time() - self.boottime) * 1000000)

    def gen_gtk(self):
        self.gtk_full = open("/dev/urandom", "rb").read(32)
        self.GTK = self.gtk_full[:16]
        self.MIC_AP_TO_GROUP = self.gtk_full[16:24]
        self.group_IV = count()

    def tun_data_incoming(self, incoming):
        p = Ether(incoming)
        self.enc_send(p.dst, p)

    def recv_pkt(self, packet):
        try:
            if len(packet.notdecoded[8:9]) > 0:  # Driver sent radiotap header flags
                # This means it doesn't drop packets with a bad FCS itself
                flags = ord(packet.notdecoded[8:9])
                if flags & 64 != 0:  # BAD_FCS flag is set
                    # Print a warning if we haven't already discovered this MAC
                    if not packet.addr2 is None:
                        printd(
                            "Dropping corrupt packet from %s" % packet.addr2,
                            Level.BLOAT,
                        )
                    # Drop this packet
                    return

            if EAPOL in packet:
                # send message 3
                self.create_eapol_3(packet)
            elif Dot11CCMP in packet:
                if packet[Dot11].FCfield == "to-DS+protected":
                    sta = packet[Dot11].addr2
                    decrypted = self.decrypt(sta, packet)
                    if decrypted:
                        # make sure that the ethernet src matches the station,
                        # otherwise block
                        if sta != decrypted[Ether].src:
                            print("[-] Invalid mac address for packet")
                            return
                        self.tunnel.write(decrypted)
                    return

            # Management
            if packet.type == DOT11_TYPE_MANAGEMENT:
                if packet.subtype == DOT11_SUBTYPE_PROBE_REQ:  # Probe request
                    if Dot11Elt in packet:
                        ssid = packet[Dot11Elt].info

                        printd(
                            "Probe request for SSID %s by MAC %s"
                            % (ssid, packet.addr2),
                            Level.DEBUG,
                        )

                        # Only send a probe response if one of our own SSIDs is probed
                        if ssid in self.ssids or (
                            Dot11Elt in packet and packet[Dot11Elt].len == 0
                        ):
                            if not (self.hidden and ssid != self.get_ssid()):
                                self.dot11_probe_resp(packet.addr2, self.get_ssid())
                elif packet.subtype == DOT11_SUBTYPE_AUTH_REQ:  # Authentication
                    if packet.addr1 == self.mac:  # We are the receivers
                        self.sc = -1  # Reset sequence number
                        self.dot11_auth(packet.addr2)
                elif (
                    packet.subtype == DOT11_SUBTYPE_ASSOC_REQ
                    or packet.subtype == DOT11_SUBTYPE_REASSOC_REQ
                ):
                    if packet.addr1 == self.mac:
                        self.dot11_assoc_resp(packet, packet.addr2, packet.subtype)
        except SyntaxError as err:
            print("Unknown error at monitor interface: %s" % repr(err))

    def dot11_probe_resp(self, source, ssid):
        probe_response_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=5,
                addr1=source,
                addr2=self.mac,
                addr3=self.mac,
                SC=self.next_sc(),
            )
            / Dot11ProbeResp(
                timestamp=self.current_timestamp(), beacon_interval=0x0064, cap=0x3101
            )
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=AP_RATES)
            / Dot11Elt(ID="DSset", info=chr(self.channel))
        )

        # If we are an RSN network, add RSN data to response
        probe_response_packet = probe_response_packet / RSN

        sendp(probe_response_packet, iface=self.interface, verbose=False)

    def dot11_auth(self, receiver):
        auth_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0x0B,
                addr1=receiver,
                addr2=self.mac,
                addr3=self.mac,
                SC=self.next_sc(),
            )
            / Dot11Auth(seqnum=0x02)
        )

        printd("Sending Authentication (0x0B)...", Level.DEBUG)
        sendp(auth_packet, iface=self.interface, verbose=False)

    def dot11_ack(self, receiver):
        ack_packet = self.get_radiotap_header() / Dot11(
            type="Control", subtype=0x1D, addr1=receiver
        )

        print("Sending ACK (0x1D) to %s ..." % receiver)
        sendp(ack_packet, iface=self.interface, verbose=False)

    def create_eapol_3(self, message_2):
        sta = message_2.getlayer(Dot11).addr2
        if sta == self.mac:
            return
        if sta not in self.stations:
            print("not there", sta)
            return

        if not self.stations[sta].eapol_ready:
            return

        self.stations[sta].eapol_ready = False
        eapol_key = EAPOL_KEY(message_2.getlayer(EAPOL).payload.load)
        snonce = eapol_key.key_nonce
        bssid = self.mac
        amac = bytes.fromhex(bssid.replace(":", ""))
        smac = bytes.fromhex(sta.replace(":", ""))

        stat = self.stations[sta]
        stat.PMK = PMK = hashlib.pbkdf2_hmac(
            "sha1", self.PSK.encode(), self.get_ssid().encode(), 4096, 32
        )
        stat.PTK = PTK = customPRF512(PMK, amac, smac, stat.ANONCE, snonce)
        stat.KCK = PTK[:16]
        stat.KEK = PTK[16:32]
        stat.TK = PTK[32:48]
        stat.MIC_AP_TO_STA = PTK[48:56]
        stat.MIC_STA_TO_AP = PTK[56:64]
        stat.client_iv = count()

        if self.GTK == b"":
            gen_gtk(self)

        stat.KEY_IV = bytes([0 for i in range(16)])

        gtk_kde = b"".join(
            [
                chb(0xDD),
                chb(len(self.GTK) + 6),
                b"\x00\x0f\xac",
                b"\x01\x00\x00",
                self.GTK,
                b"\xdd\x00",
            ]
        )
        plain = pad_key_data(RSN + gtk_kde)
        keydata = aes_wrap(stat.KEK, plain)

        ek = EAPOL(version="802.1X-2004", type="EAPOL-Key") / EAPOL_KEY(
            key_descriptor_type=2,
            key_descriptor_type_version=2,
            install=1,
            key_type=1,
            key_ack=1,
            has_key_mic=1,
            secure=1,
            encrypted_key_data=1,
            key_replay_counter=2,
            key_nonce=stat.ANONCE,
            key_mic=(b"\x00" * 16),
            key_length=16,
            key=keydata,
            wpa_key_length=len(keydata),
        )

        ek.key_mic = hmac.new(stat.KCK, ek.build(), hashlib.sha1).digest()[:16]

        m3_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0,
                FCfield="from-DS",
                addr1=sta,
                addr2=self.mac,
                addr3=self.mac,
                SC=self.next_sc(),
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E)
            / ek
        )

        sendp(m3_packet, iface=self.interface, verbose=False)
        stat.associated = True
        print("[+] New associated station", sta)

        self.stations[sta] = stat

    def create_message_1(self, sta):
        if sta not in self.stations:
            return
        stat = self.stations[sta]
        stat.ANONCE = anonce = bytes([random.randrange(256) for i in range(32)])
        m1_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=0,
                FCfield="from-DS",
                addr1=sta,
                addr2=self.mac,
                addr3=self.mac,
                SC=self.next_sc(),
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x888E)
            / EAPOL(version="802.1X-2004", type="EAPOL-Key")
            / EAPOL_KEY(
                key_descriptor_type=2,
                key_descriptor_type_version=2,
                key_type=1,
                key_ack=1,
                has_key_mic=0,
                key_replay_counter=1,
                key_nonce=anonce,
                key_length=16,
            )
        )
        stat.eapol_ready = True
        sendp(m1_packet, iface=self.interface, verbose=False)
        self.stations[sta] = stat

    def dot11_assoc_resp(self, packet, sta, reassoc):
        if sta not in self.stations:
            self.stations[sta] = Station(sta)

        self.sta = sta
        response_subtype = 0x01
        if reassoc == 0x02:
            response_subtype = 0x03
        self.eapol_ready = True
        assoc_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=response_subtype,
                addr1=sta,
                addr2=self.mac,
                addr3=self.mac,
                SC=self.next_sc(),
            )
            / Dot11AssoResp(cap=0x3101, status=0, AID=self.next_aid())
            / Dot11Elt(ID="Rates", info=AP_RATES)
        )

        print("Sending Association Response (0x01)...")
        sendp(assoc_packet, iface=self.interface, verbose=False)
        self.create_message_1(sta)

    def decrypt(self, sta, packet):
        ccmp = packet[Dot11CCMP]
        pn = ccmp_pn(ccmp)
        if sta not in self.stations:
            print("[-] Unknown station", sta)
            # TBD: deauth
            return None
        station = self.stations[sta]
        return self.decrypt_ccmp(packet, station.TK, self.GTK)

    def encrypt(self, sta, packet, key_idx):
        key = ""
        if key_idx == 0:
            pn = next(self.stations[sta].client_iv)
            key = self.stations[sta].TK
        else:
            pn = next(self.group_IV)
            key = self.GTK
        return self.encrypt_ccmp(packet, key, pn, key_idx)

    def enc_send(self, sta, packet):
        key_idx = 0
        if is_multicast(sta) or is_broadcast(sta):
            key_idx = 1
        elif sta not in self.stations or not self.stations[sta].associated:
            print("[-] Invalid station", sta)
            return
        new_packet = self.get_radiotap_header() / self.encrypt(sta, packet, key_idx)
        sendp(new_packet, iface=self.interface, verbose=False)

    def encrypt_ccmp(ap, p, tk, pn, keyid=0, amsdu_spp=False):
        # Takes a plaintext ethernet frame and encrypt and wrap it into a Dot11/DotCCMP
        # Add the CCMP header. res0 and res1 are by default set to zero.
        SA = p[Ether].src
        DA = p[Ether].dst
        newp = Dot11(
            type="Data",
            FCfield="from-DS+protected",
            addr1=DA,
            addr2=ap.mac,
            addr3=SA,
            SC=ap.next_sc(),
        )
        newp = newp / Dot11CCMP()

        pn_bytes = pn2bytes(pn)
        newp.PN0, newp.PN1, newp.PN2, newp.PN3, newp.PN4, newp.PN5 = pn_bytes
        newp.key_id = keyid
        newp.ext_iv = 1
        priority = 0  # ...
        ccm_nonce = ccmp_get_nonce(priority, newp.addr2, pn)
        ccm_aad = ccmp_get_aad(newp, amsdu_spp)
        header = LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / SNAP(OUI=0, code=p[Ether].type)
        payload = (header / p.payload).build()  # strip ethernet. wrap with LLC
        ciphertext, tag = CCMPCrypto.run_ccmp_encrypt(tk, ccm_nonce, ccm_aad, payload)

        newp.data = ciphertext + tag
        return newp

    def decrypt_ccmp(self, p, tk, gtk, verify=True):
        # Takes a Dot11CCMP frame and decrypts it
        keyid = p.key_id
        if keyid == 0:
            pass
        elif keyid == 1:
            tk = gtk
        else:
            raise Exception("unknown key id", key_id)

        priority = dot11_get_priority(p)
        pn = dot11_get_iv(p)

        ccm_nonce = ccmp_get_nonce(priority, p.addr2, pn)
        ccm_aad = ccmp_get_aad(p[Dot11])

        payload = p[Dot11CCMP].data
        tag = payload[-8:]
        payload = payload[:-8]
        plaintext, valid = CCMPCrypto.run_ccmp_decrypt(
            tk, ccm_nonce, ccm_aad, payload, tag
        )
        if verify and not valid:
            print("[-] ERROR on ccmp decrypt, invalid tag")
            return None
        llc = LLC(plaintext)
        # convert into an ethernet packet.
        return Ether(
            addr2bin(p.addr3)
            + addr2bin(p.addr2)
            + struct.pack(">H", llc.payload.code)
            + llc.payload.payload.build()
        )

    def dot11_beacon(self, ssid):
        # Create beacon packet
        beacon_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=self.mac, addr3=self.mac
            )
            / Dot11Beacon(cap=0x3101)
            / Dot11Elt(ID="SSID", info=ssid)
            / Dot11Elt(ID="Rates", info=AP_RATES)
            / Dot11Elt(ID="DSset", info=chr(self.channel))
        )

        beacon_packet = beacon_packet / RSN

        # Update timestamp
        beacon_packet[Dot11Beacon].timestamp = self.current_timestamp()

        # Send
        sendp(beacon_packet, iface=self.interface, verbose=False)

    class BeaconTransmitter(threading.Thread):
        def __init__(self, ap):
            threading.Thread.__init__(self)
            self.ap = ap
            self.daemon = True
            self.interval = 0.1

        def run(self):
            while True:
                for ssid in self.ap.ssids:
                    self.ap.dot11_beacon(ssid)
                # Sleep
                sleep(self.interval)

    def run(self):
        self.beaconTransmitter.start()
        self.tunnel.start()
        sniff(iface=self.interface, prn=self.recv_pkt, store=0, filter=self.bpffilter)


if __name__ == "__main__":
    ap = AP("mon0", "turtlenet", "password1234")
    ap.gen_gtk()
    ap.run()
