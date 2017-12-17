#!/usr/bin/python
import sys, os
PATH = "/sys/fs/cgroup/cpu/"

list = []
line = sys.stdin.readline()
while line:
	line = line.split(":")
	if line[0] == "create":
		os.makedirs(PATH + line[1] + "/" + line[3][:-1])
	elif line[0] ==	"remove":
		os.removedirs(PATH + line[1] + "/" +  line[3][:-1])
	elif line[0] == "add":
		fd = open(PATH + line[1] + "/" + line[3] + "/" + "tasks", "w")
		fd.write(line[4][:-1])
		fd.close()
	elif line[0] == "set_limit":
		fd = open(PATH + line[1] + "/" + line[3] + "/" + "cpu.shares", "w")
		fd.write(line[5][:-1])
		fd.close()
	line = sys.stdin.readline()
	
