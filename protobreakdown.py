from kamene.all import * 
from kamene.utils import PcapReader
import socket

class PcapParser():
    def __init__(self):
        self.hosts = dict()
        self.services = {22: 'ssh', 53: 'dns', 80: 'http', 123: 'ntp', 443: 'https', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS'}

    def parsePcapFile(self, filename):
        print("Eating PCAP file")
        with PcapReader(filename) as pcap_reader:
          for pkt in pcap_reader:
            if pkt.haslayer(IP):
                try: 
                    self.addToDict(pkt[IP].src, pkt[IP].dst, pkt[IP].dport, pkt[IP].len)
                except AttributeError:
                    # some packets are missing these attrs?
                    # every IP packet should have them
                    # maybe my firewall would drop them
                    pass
        print("Nom") 

    def addToDict(self, srcip, dstip, dport, pktlen):
        # Ignore the high level ports
        if int(dport) > 1024:
            return

        if srcip in self.hosts:
            if dport in self.hosts[srcip]:
                length = self.hosts[srcip][dport] + pktlen
                self.hosts[srcip][dport] = length
            else:
                self.hosts[srcip][dport] = pktlen
        else:
            self.hosts[srcip] = dict()
            self.addToDict(srcip, dstip, dport, pktlen)
        # print(self.hosts)

    def printHosts(self):
        for host in self.hosts: 
            try:
                hostname = socket.gethostbyaddr(host)
            except socket.error as e:
                # print(e)
                hostname = ("Could not resolve hostname", "")
                
            print("Report for %-15s (%s)" % (host, hostname[0]))
            totalTraffic = 0
            for key in self.hosts[host]:
                totalTraffic = totalTraffic + self.hosts[host][key]

            for port in sorted(self.hosts[host]):
                percent = str(int(self.hosts[host][port] / totalTraffic * 100)) + "%"
                service = self.services[port] if port in self.services else ''
                print('port %-4d | %7s | %-4s | %s bytes' % (port, service, percent, self.hosts[host][port]))
            print()

if __name__ == '__main__':
    import argparse
    
    p = argparse.ArgumentParser(description="PCAP File analysis") 

    target = None
    p.add_argument('-v','--verbose', default=False, metavar="verbose")
    p.add_argument('-f','--file','--filename', required=True, metavar="file", help='Location of the PCAP file')
    # p.add_argument('-t', '--target', default=None, metavar="target", help="The IP Address under investigation")
    
    args = p.parse_args()
    
    parser = PcapParser()
    parser.parsePcapFile(args.file) # , target=args.targat)
    parser.printHosts()

