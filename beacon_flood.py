from scapy.all import*
from threading import Thread

def send_fakeAP(ssid):
	SSID = ssid 
	iface = 'mon0'   

	dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=RandMAC(), addr3=RandMAC())
	beacon = Dot11Beacon(cap="ESS", timestamp=1)
	essid = Dot11Elt(ID='SSID',info=SSID, len=len(SSID))
	frame = RadioTap()/dot11/beacon/essid

	sendp(frame, iface=iface, inter=0.100, loop=1, count=1000)

def main():
	threads = []
	ssid = ['test1', 'test2', 'test3', 'test4' ,'test5' ,'test6', 'test7']

	for i in range (0, len(ssid)):
		ap = threading.Thread(target=send_fakeAP, args=(ssid[i],))
		threads.append(ap)

	for ap in threads:
		ap.start()

main()
