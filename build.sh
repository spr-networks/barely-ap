#!/bin/bash
docker kill barely-ap barely-sta
docker rm barely-ap barely-sta
docker build . -t barely-ap

