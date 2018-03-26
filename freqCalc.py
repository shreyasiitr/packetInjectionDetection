import csv
import operator

def calcFeq(filename):
	blocked = []
	dictionary = {}
	res = []
	with open(filename, 'rb') as domFile_1:
		fileRdr = csv.reader(domFile_1)
		for domain in fileRdr:
			blocked.append(domain)
	for elem in blocked:
		if elem[1] not in dictionary:
			dictionary[elem[1]] = 1
		else:
			temp = dictionary[elem[1]]
			temp+=1
			dictionary[elem[1]]=temp
	sorted_x = sorted(dictionary.items(), key=operator.itemgetter(1),reverse=True)
	for keys in sorted_x:
		temp = []
		temp.append(keys[0])
		temp.append(keys[1])
		res.append(temp)
	print res
	with open('table.csv', 'wb') as csvfile:
		spamwriter = csv.writer(csvfile,delimiter=',')
		for elem in res:
			spamwriter.writerow(elem)

calcFeq("results_freq.csv")