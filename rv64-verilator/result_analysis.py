import sys
import os

fw = open("soft_latency.txt", "w")
latency = 0
cycle = 0
for i in range(1000):
	if i % 100 == 0:
		print(i/100, "%")
	os.system("./exe_HW_sim +tohost > tmp_result.txt")
	fr = open("tmp_result.txt","r")
	while True:
		line = fr.readline()
		if not line:
			break
		sp_line = line.split(" ")
		if sp_line[0] == "Simulation":
			print(sp_line)
			latency = int(sp_line[4])
			cycle = int(sp_line[8])
			fw.write(str(latency)+"\n")
	fr.close()
fw.close()
