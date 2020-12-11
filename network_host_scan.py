#!/usr/bin/python3
import argparse
import bcolors as b
import ipaddress
import sys
import nmap
import time
import csv
from datetime import datetime,timedelta
import logging

logging.basicConfig(filename="network_host_scanner.log",level = logging.INFO,format = '%(levelname)s %(asctime)s %(message)s',datefmt = '%Y-%m-%d %H:%M:%S',filemode = 'a')
logger = logging.getLogger()

HOST_STATUS={}
OVERALL_STATUS={}

DATE=datetime.now().strftime('%Y-%m-%d-%H_%M_%S')

CSV_NAME="IP_REPORT_"+DATE

def prepare_csv(row_list):
    try:
        
        with open(CSV_NAME,'w') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "STATUS"])
            writer.writerows(row_list)
        
        print("{}[+] CSV File created :{} {}".format(b.OKMSG,CSV_NAME,b.END)) 
        logger.info("CSV File created :{}".format(CSV_NAME)) 

    except Exception as e:
        print("{}[-] Problem while generating CSV list{}".format(b.ERRMSG,b.END))
        logger.error("Problem while generating CSV list".format(e))


def format_doc(host_list,all_address):

    print(r"{}[+] Preparing IP wise status list {}".format(b.OKMSG,b.END))
    try:
    
        for ip in range(0,len(host_list)):
            host=host_list[ip][0]
            status=host_list[ip][1]
            HOST_STATUS[host]=status

        for ip in all_address:
            if ip in HOST_STATUS.keys():
                status='up'
                OVERALL_STATUS[ip]=status

            else:
                status='down'
                OVERALL_STATUS[ip]=status

        row_list=[ (host,ip) for host,ip in OVERALL_STATUS.items()]
        return row_list

    except Exception as e:
        print("{}[-] Problem while preparing IP wise status list {}".format(b.ERRMSG,b.END))
        logger.error("Problem while preparing IP wise status list".format(e))
        sys.exit(2) 


def all_available_host(network_to_scan):
    try:

        ALL_ADDRESS=[str(ip) for ip in ipaddress.IPv4Network(network_to_scan,False)]
        print(r"{}[+] Total IP address in range {} {}".format(b.OKMSG,len(ALL_ADDRESS),b.END))
        logger.info("Total IP address in range:{}".format(len(ALL_ADDRESS)))
        return ALL_ADDRESS

    except Exception as e:
        print("{}[-]Unable to find IP address,check IP/Subnet {}".format(b.ERRMSG,b.END))
        logger.error("Unable to find IP address,check IP/Subnet".format(e))
        sys.exit(2)

def host_discovery(network_to_scan):
    print(r"{}[+] Host scanning is in progress ...{}".format(b.WARN,b.END)) 
    try:
        
        nm = nmap.PortScanner()
        nm.scan(hosts=network_to_scan, arguments="-sn")
        host_list=[(x,nm[x]['status']['state']) for x in nm.all_hosts()]
        
        return host_list

    except Exception as e:
        print("{}[-]Please enter valid subnet mask{}".format(b.ERRMSG,b.END))
        logger.error("host_discovery error :{}".format(e))
        sys.exit(2)

def get_argument():
    try:
    
        parser=argparse.ArgumentParser()
        parser.add_argument('-n','--network',dest='network_scan',help='enter network to scan')
        parser.add_argument('-s','--subnet',dest='subnet_mask',help='enter the subnet for scanning')
        option=vars(parser.parse_args())
       
        if not option['network_scan']:
            parser.error("\n{}[-] Plase specify network to  scan {}".format(b.ERRMSG,b.END))
        
        if not option['subnet_mask']:
            parser.error("\n{}[-] Plase specify subnet mask to above network scan {}".format(b.ERRMSG,b.END))
        
    
        
        return option
    except Exception as e:
        print("Specify an arguemnt correctly")
        logger.error("arguments are not correctly  specified")

def valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False

    
def Main():
    try:
        logger.info("#######################")        
        print("""{}{}
======================================================================\n
| \ | | ___| |___      _____  _ __| | __         | | | | ___  ___| |_
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /  _____  | |_| |/ _ \/ __| __|
| |\  |  __/ |_ \ V  V / (_) | |  |   <  |_____| |  _  | (_) \__ \ |_
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\         |_| |_|\___/|___/\__|


 ___  ___ __ _ _ __  _ __   ___ _ __
/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
\__ \ (_| (_| | | | | | | |  __/ |
|___/\___\__,_|_| |_|_| |_|\___|_|  v.0.1
======================================================================\n

{}""".format(b.BLUE,b.BOLD,b.END))
        
        option=get_argument()
        network_scan=option['network_scan']
        subnet_mask=option['subnet_mask']
        valid=valid_ip(network_scan)
        if valid== True:
            print("{}[+] Ip address is valid {}".format(b.OKMSG,b.END))
        else:
            print("{}[-] Ip address is invalid,please enter valid IP address {}".format(b.ERRMSG,b.END))
            logger.error("Ip address is invalid".format(b.ERRMSG,b.END))
            sys.exit(2)
        
        network_to_scan=network_scan+'/'+subnet_mask
        host_list=host_discovery(network_to_scan)
        all_address=all_available_host(network_to_scan)
       
        print(r"{}[+] UP hosts address in range {} {}".format(b.OKMSG,len(host_list),b.END))
        logger.info("UP hosts address in range {}".format(len(host_list)))
        free=len(all_address)-len(host_list)
        print(r"{}[+] Available / Free hosts address in range {} {}".format(b.OKMSG,free,b.END))
        logger.info("Available / Free hosts address in range {}".format(free))
        if len(all_address) > 0:
            row_list=format_doc(host_list,all_address)

            prepare_csv(row_list)


        logger.info("#######################")        

    except Exception as e:
        logger.error("Error:{}".format(e))

if __name__=='__main__':
    Main()
