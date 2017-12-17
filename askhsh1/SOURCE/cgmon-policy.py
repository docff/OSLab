#!/usr/bin/python
import sys
mcpu = 2000
elastic = 50

lst = []
line = sys.stdin.readline()
while line:
  line = line.split(":")
  lst.append((line[1], int(line[-1][:-1])))
  line = sys.stdin.readline()

sum = 0
for x in lst:
  sum += x[1]

bond = -1.
flag = 0
if sum < mcpu:
  bond = 1.
  flag = 1

shares = []
sum1 = 0
for x in lst:
  if flag:
    shares.append((x[0], x[1]))
    if x[1] == elastic:
      sum1 += x[1]
  else:
    shares.append((x[0], float(x[1]) * mcpu / sum))

if flag:
  sum2 = mcpu - sum
  for i in range(len(lst)):
    if shares[i][1] == elastic:
      t = list(shares[i])
      t[1] += float(shares[i][1]) * sum2 / sum1
      shares[i] = tuple(t)

print("score:" + str(bond))
for x in shares:
  print("set_limit:" + x[0] + ":cpu.shares:" + str(int(x[1])))
