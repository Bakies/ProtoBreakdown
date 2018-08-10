# TrafficAnalysis
This script will break down the amount of traffic each host in a network is using for each protocol. This is to help identify traffic tunneled over other protocols. 

An example using a pcap file I captured from my firewalls internal interface
```
$ python3 protobreakdown.py -f ~/pfsense.pcap
WARNING: No route found for IPv6 destination :: (no default route?). This affects only IPv6
Eating PCAP file
Nom
Report for 192.168.1.79    (jon-laptop.norwood.baki.es)
port 22   |     ssh | 1%   | 10929 bytes
port 53   |     dns | 1%   | 12655 bytes
port 80   |    http | 7%   | 74976 bytes
port 123  |     ntp | 0%   | 380 bytes
port 443  |   https | 89%  | 884083 bytes

Report for 192.168.1.100   (storage.norwood.baki.es)
port 22   |     ssh | 0%   | 60 bytes
port 53   |     dns | 3%   | 494 bytes
port 67   |         | 2%   | 328 bytes
port 80   |    http | 3%   | 447 bytes
port 137  | NetBIOS | 4%   | 624 bytes
port 138  | NetBIOS | 16%  | 2180 bytes
port 443  |   https | 69%  | 9314 bytes

Report for 192.168.1.4     (Chromecast-Audio.norwood.baki.es)
port 53   |     dns | 12%  | 1202 bytes
port 123  |     ntp | 0%   | 76 bytes
port 443  |   https | 87%  | 8627 bytes

Report for 192.168.1.76    (Tripod.norwood.baki.es)
port 53   |     dns | 1%   | 4631 bytes
port 80   |    http | 0%   | 1286 bytes
port 137  | NetBIOS | 0%   | 702 bytes
port 138  | NetBIOS | 0%   | 229 bytes
port 443  |   https | 97%  | 254010 bytes

...
```
