# Network Host Scanner
network host scanner for scanning Host[Ipv4] address in netowrk


Python based network scanner to scan network [IPv4] and gives list of current Hosts [available[free]/allocated[up]] present in network.



**What network scanner does ?**

- Preforms scan on given network and mark status as [free/down| up/allocated]

- Validates IP given address

- Gives available/free and current up /allocated IP address.

- Make CSV file based on status.

**Note:** network  scanner do not preform port scanning.

**Prerequisite:**

- python3,pip3,git,nmap  installed on system

- pip3 install bcolors python-nmap

**Steps to Run:**

- git clone https://github.com/sandeshk06/network_host_scanner.git

- cd network_host_scanner
 
- python3 network_host_scan.py -n [IP] -s [SUBNET]

  example: python3 network_host_scan.py -n '192.168.2.0' -s '24'

**Note:** -n [network] and -s[subnet] are compulsary for running network_scanner


**Using Docker Image:**

- git clone https://github.com/sandeshk06/network_host_scanner.git

- cd network_host_scanner

- docker build -t network_host_scan  . 

- docker run --rm -v data:/opt/myapp/  network_host_scan   -n [IP] -s [SUBNET]

- csv file report  available in **/var/lib/docker/volumes/data/_data**
