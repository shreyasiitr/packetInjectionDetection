from scapy.all import *
import csv
import time

init = time.time()
rowArr = []

def sendQuery(dest, blocked):
	result, ignore = sr(IP(dst=dest)/UDP(sport = RandShort())/DNS(id=RandShort(), rd=1, qd=DNSQR(qname = blocked)), verbose=0, timeout=2, multi=1)
	retObject = (result,ignore)
	return retObject
	
# cnDomains = ["60.247.18.3","162.105.131.198","202.120.224.115","157.185.154.31"
# 			,"211.151.94.194","61.54.243.203","106.39.41.16","211.84.228.203","42.247.3.122","202.199.128.81"]

def logResponses(blockedDoms, cnDomainFile):
	blocked = []
	cnIPS = []
	freq = []
	with open(blockedDoms, 'rb') as domFile_1:
		fileRdr = csv.reader(domFile_1)
		for domain in fileRdr:
			blocked.append(domain[0])
	with open(cnDomainFile, 'rb') as domFile_2:
		fileRdr = csv.reader(domFile_2)
		for domain in fileRdr:
			cnIPS.append(domain[0])
	for ip in cnIPS:
		for outIp in blocked:
			response = sendQuery(str(ip), str(outIp))
			time.sleep(0.5)
			for data in response[0]:
				print data
				#print data[1][IP].id
				#print data[1][IP].ttl
				#print data[1][IP].src
				temp = []
				dnsTemp = []
				timestamp = time.time()-init
		    	temp.append(str(ip))
		    	temp.append(str(outIp))
		    	temp.append(str(data[1][IP].id))
		    	temp.append(str(data[1][IP].ttl))
		    	temp.append(timestamp)
		    	rowArr.append(temp)
		    	dnsTemp.append(str(data[1][IP].src))
		    	dnsTemp.append(str(data[1][DNSRR].rdata))
		    	freq.append(dnsTemp)
		    	temp = []
		    	dnsTemp = []

	print rowArr
	with open('results_freq.csv', 'wb') as csvfile:
		spamwriter = csv.writer(csvfile,delimiter=',')
		for elem in freq:
			spamwriter.writerow(elem)
	with open('results.csv', 'wb') as csvfile:
		initArr = ["destIP","blockedDomain","id","ttl","timestamp"]
		spamwriter = csv.writer(csvfile,delimiter=',')
		spamwriter.writerow(initArr)
	with open('results.csv', 'wb') as csvfile:
		spamwriter = csv.writer(csvfile,delimiter=',')
		for elem in rowArr:
			spamwriter.writerow(elem)
	
def cnTraceroute(blockedDomain, cnDomainFile):
	cnIPS = []
	with open(cnDomainFile, 'rb') as domFile_2:
		fileRdr = csv.reader(domFile_2)
		for domain in fileRdr:
			cnIPS.append(domain[0])
	paths = []
	for ip in cnIPS:
		temp = []
		resPair = (0,"127.0.0.1")
		temp.append(resPair)
		counter = 1
		check = 1
		while check:
			result, ignore = sr(IP(dst = str(ip), ttl = counter)/UDP(sport = RandShort())/DNS(id=RandShort(), rd=1, qd=DNSQR(qname = str(blockedDomain))), verbose=0, timeout=2, multi=1)
			retObject = (result,ignore)
			time.sleep(1)
			for data in retObject[0]:
				if ICMP in data[1]:
					resPair = (counter,str(result[0][1][IP].src))
					print resPair
					temp.append(resPair)
					counter+=1
					break
					# if str(result[0][1][IP].src)==str(ip):
					# 	newTemp = []
					# 	for elem in temp:
					# 		if elem[1] not in newTemp:
					# 			newTemp.append(elem[1])
					# 	paths.append(newTemp)
					# 	temp = []
					# 	check = 0
					# 	break
					# else:
					# 	counter+=1
					# 	break
					
				else:
					resPair = (counter,str(result[0][1][IP].src))
					print resPair
					print "censor"
					temp.append(resPair)
					newTemp = []
					for elem in temp:
						if elem[1] not in newTemp:
							newTemp.append(elem[1])
					paths.append(newTemp)
					temp = []
					check = 0
					break
				
	print paths
	with open('traceroute.csv', 'wb') as csvfile:
		spamwriter = csv.writer(csvfile,delimiter=',')
		for elem in paths:
			spamwriter.writerow(elem)

logResponses("Domain_List.csv","cnDomains.csv")
logResponses("Domain_List.csv","cnDomains.csv")
cnTraceroute("dropbox.com","cnDomains.csv")

