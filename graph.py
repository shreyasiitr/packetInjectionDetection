import graphviz as gv
import csv

def graph(filename):
	dot = gv.Graph()
	traces = []
	with open(filename, 'rb') as domFile_2:
		fileRdr = csv.reader(domFile_2)
		for domain in fileRdr:
			traces.append(domain)
	for arr in traces:
		index = 0
		for elem in arr:
			dot.node(str(elem),str(elem))
			if index>0:
				dot.edge(str(arr[index-1]),str(elem))
			index+=1
	dot.render('round-table.gv', view=True)

graph("traceroute.csv")