#!/bin/bash

set -v

WD=${PWD}/demo

cgmon daemon stop -w ${WD}

sleep 1

cgmon daemon start -w ${WD} -p ${WD}/cgmon-policy.py -l ${WD}/cgmon-limit.py

sleep 1

cgmon app list

sleep 1

# assuming total 2000 millicpus == 2 cpus
cgmon policy create -n challenger -p 4000
cgmon policy create -n master -p 3000
cgmon policy create -n diamond -p 2000
cgmon policy create -n platinum -p 1000
cgmon policy create -n gold -p 750
cgmon policy create -n silver -p 500
cgmon policy create -n bronze -p 250
cgmon policy create -n elastic -p 50
cgmon policy list

sleep 1

cgmon app spawn -p silver -e "stress -c 2" -n BANKDB
cgmon app spawn -p silver -e "stress -c 2" -n WEBDB
cgmon app spawn -p elastic -e "stress -c 2" -n VIDEOENC
cgmon app spawn -p elastic -e "stress -c 2" -n SPAMBOT
cgmon app spawn -p diamond -e "stress -c 2" -n MEDICAL -f
cgmon app list

sleep 5

# This should fail: not enough cpu
cgmon app spawn -p platinum -e "stress -c 2" -n MEDICALDB

sleep 1

# forcing it violates policies
cgmon app spawn -p platinum -e "stress -c 2" -n MEDICALDB -f

sleep 20
pkill -f stress
