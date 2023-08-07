from scapy.all import *

PORTS=[1,3,7,9,13,17,19,21,22,23,25,26,37,53,79,80,81,82,88,100,106,110,111,
113,119,135,139,143,144,179,199,254,255,280,311,389,427,443,444,445,464,
465,497,513,514,515,543,544,548,554,587,593,625,631,636,646,787,808,853,873,
902,990,993,995,1000,1022,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,
1035,1036,1037,1038,1039,1040,1041,1044,1048,1049,1050,1053,1054,1056,1058,
1059,1064,1065,1066,1069,1071,1074,1080,1110,1234,1433,1434,1494,1521,1720,
1723,1755,1761,1801,1900,1935,1998,2000,2001,2002,2003,2005,2049,2103,2105,
2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000,3001,3128,3268,3306,
3389,3689,3690,3703,3986,4000,4001,4045,4899,5000,5001,5003,5009,5050,5051,
5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900,5901,6000,6001,6002,
6004,6112,6646,6666,7000,7070,7937,7938,8000,8002,8008,8009,8010,8031,8080,
8081,8443,8888,9000,9001,9090,9100,9102,9999,10000,10001,10010,32768,32771,
49152,49153,49154,49155,49156,49157,50000]

def syn_scan(target,ports=PORTS,show_unfilt=1,show_filt=0):
	print('***Syn scan started***')
	ans,unans= sr(IP(dst=target)/TCP(sport=5555,dport=ports,flags='S')
	,timeout=2, verbose=0)
	print('Scan results:')
	ans.make_table(lambda s,r: (s.dst, s.dport,
	r.sprintf("{TCP:%TCP.flags%}{ICMP:%IP.src% - %ICMP.type%}")))
	if show_unfilt==1:
		print('Summary list of open ports of host', target,':')
		for s,r in ans:
			if s[TCP].dport == r[TCP].sport:
				print("%d is unfiltered" % s[TCP].dport)
	if show_filt==1:
		print('Summary list of filtered ports of host',target,':')
		for s in unans:
			print("%d is filtered" % s[TCP].dport)
	print('***End of syn scan***')
	return

def fin_scan(target,ports=PORTS):
	print('***fin scan started***')
	ans,unans= sr(IP(dst=target)/TCP(sport=5555,dport=ports,flags='F')
        ,timeout=2, verbose=0)
	print('Summary list of closed ports of host', target,':')
	for s,r in ans:
		if r[TCP].flags==20:
			print("%d is closed" % s[TCP].dport) 
	print('***End of fin scan***')
	return

def xmas_scan(target,ports=PORTS):
	print('***xmas scan started***')
	ans,unans= sr(IP(dst=target)/TCP(sport=5555,dport=ports,flags='FPU')
	,timeout=2, verbose=0)
	print('Summary list of closed ports of host', target,':')
	for s,r in ans:
		if r[TCP].flags==20:
			print("%d is closed" % s[TCP].dport) 
	print('***End of xmas scan***')
	return

def null_scan(target,ports=PORTS):
	print('***null scan started***')
	ans,unans= sr(IP(dst=target)/TCP(sport=5555,dport=ports,flags='')
	,timeout=2, verbose=0)
	print('Summary list of closed ports of host', target,':')
	for s,r in ans:
		if r[TCP].flags==20:
			print("%d is closed" % s[TCP].dport) 
	print('***End of null scan***')
	return

def std_dns_scan(target):
	print('***dns scan started at port 53***')
	ans,unans= sr(IP(dst=target)/UDP(sport=5555,dport=53)/DNS(rd=1,
	qd=DNSQR(qname='google.com')),timeout=2, verbose=0)
	if ans:
		print('DNS server found at: ',target)
	print('***End of scan***')
	return	

def driver():
	'''demo driver for scans'''
	'''shows different variations of arguments accepted by 
	different scan functions'''
	host='8.8.8.8'
	
	'''fin scan on 200 ports (PORTS list); shows closed ports''' 
	fin_scan(host)
	print()
	'''xmas scan on port 53 only; 
	shows if port 53 is closed, blank list otherwise'''
	xmas_scan(host,53)
	print()
	'''null scan on port 443; shows if it is closed'''
	null_scan(host,443)
	print()
	'''syn scan (TCP half-open) on PORTS list; 
	default args show unfiltered open ports only
	/ do not show filtered/closed ports; 
	to show filtered ports, pass show_filt=1;
	to hide open unfiltered ports, pass show_unfilt=0'''
	syn_scan(host)
	print()	
	'''dns scan: check if dns server exists at port 53'''
	std_dns_scan(host)
	return 


'''main'''
driver()
