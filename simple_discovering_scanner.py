#!/usr/bin/python3

# run so:   $ sudo python3 Scanner.py

import subprocess
import os
import nmap

def arp_scan(ip_addr: str, left_index: int, right_index: int):
    for n in range(left_index, right_index):
        subnet = ip_addr[0:len(ip_addr)-len(str(right_index-left_index))]
        ip = subnet+'{0}'.format(n)
        os.system('nmap -PR ' + ip_addr)


def icmp_host_disc(ip_addr: str, left_index: int, right_index: int):
    for n in range(left_index, right_index):
        subnet = ip_addr[0:len(ip_addr)-len(str(right_index-left_index))]
        ip = subnet+'{0}'.format(n)
        os.system('nmap -PE ' + ip)


def port_scan(ip_addr: str, port_range: str,  args: str):
        port_scanner.scan(ip_addr, port_range, args)
        print(port_scanner.scaninfo())
        print("\nIP Status: ", port_scanner[ip_addr].state())
        protocols = port_scanner[ip_addr].all_protocols()
        print(protocols)
        for protocol in protocols:
            print("\n["+protocol+"] open ports: ", port_scanner[ip_addr][protocol].keys())



def scan():
    resp_1 = input("""\nWhat is your target?"
                    1) an host 
                    2) a network\n""")
    if resp_1 == '1':
        resp_2 = input("""\nWhat do you want to do?"
                1) ARP scan
                2) ICMP Host discovering 
                3) Port scanning\n""")
        ip_addr = '127.0.0.1'  # default ip address
        prompt_str = input('\nPlease enter the target address IP ['+ip_addr+']: \n')
        ip_addr = prompt_str or ip_addr
        print("\nSelected address IP: ", ip_addr)
        type(ip_addr)
        left_index = right_index = 0
    else:
        resp_2 = input("""\nWhat do you want to do?"
                1) ARP scan
                2) ICMP Host discovering\n""")
        ip_addr = '192.168.1.0'  # default subnet ip address
        prompt_str = input('\nPlease enter the target subnet IP ['+ip_addr+']: \n')
        ip_addr = prompt_str or ip_addr
        print("\nSelected subnet IP: ", ip_addr)
        type(ip_addr)
        print('\nPlease enter the subnet IP you want to scan ['+ip_addr+']:\n')
        left_index = int(input('\nGive me the left index of range of hosts to scan:\n'))
        right_index = int(input('\nGive me the right index of range of hosts to scan:\n'))
    

    if resp_2 == '1':
        if left_index == right_index:
            os.system('nmap -sn -PR ' + ip_addr)
        else:
            arp_scan(ip_addr, left_index, right_index)
    elif resp_2 == '2':
        if left_index == right_index:
            os.system('nmap -sn -PE ' + ip_addr)
        else:
            icmp_host_disc(ip_addr, left_index, right_index)
    else:
        if resp_1 == '1': 
            resp_3 = input("""\nEnter the port scan type you want to run:
                            1) SYN scan
                            2) ACK scan
                            3) RST scan
                            4) FIN scan
                            5) UDP scan
                            6) OS detection (stack fingerprinting)
                            7) Aggressive scan(OS and version detection)
                            8) Services versions scan \n""")
            
            resp_4 = input("""\nWhat ports you want to scan?"
                            1) particular port    
                            2) Fast scan (scan only the most important port)                    
                            3) particular range of ports\n""")

            
            if resp_4 == '1':
                port = input('\nGive me the particular port:')
                print('\nPort chosen: {0}'.format(port))
                if resp_3 == '1':
                    os.system('nmap -Pn -sS ' + ip_addr)
                elif resp_3 == '2':
                    os.system('nmap -Pn -sA ' + ip_addr)
                elif resp_3 == '3':
                    os.system('nmap -Pn -sR ' + ip_addr)
                elif resp_3 == '4':
                    os.system('nmap -Pn -sF ' + ip_addr)
                elif resp_3 == '5':
                    os.system('nmap -Pn -sU ' + ip_addr)
                elif resp_3 == '6':
                    os.system('nmap -Pn -sO ' + ip_addr)
                elif resp_3 == '7':
                    os.system('nmap -Pn -sA ' + ip_addr)
                else:
                    os.system('nmap -Pn -sV ' + ip_addr)
            elif resp_4 == '2':
                os.system('nmap -F ' + ip_addr)
            else:
                ports = '1-1024'
                prompt_ports = input('\nGive me the port range [1-1024]:')
                ports = prompt_ports or ports
                print('\nSelected port range: {0}'.format(ports))

                # -v verbose
                if resp_3 == '1':
                    port_scan(ip_addr, ports, '-v -Pn -sS ')
                elif resp_3 == '2':
                    port_scan(ip_addr, ports, '-v -Pn -sA ')
                elif resp_3 == '3':
                    port_scan(ip_addr, ports, '-v -Pn -sR ')
                elif resp_3 == '4':
                    port_scan(ip_addr, ports, '-v -Pn -sF ')
                elif resp_3 == '5':
                    port_scan(ip_addr, ports, '-v -Pn -sU ')
                elif resp_3 == '6':
                    port_scan(ip_addr, ports, '-v -Pn -sO ')
                elif resp_3 == '7':
                    port_scan(ip_addr, ports, '-v -Pn -sA ')
                else:
                    port_scan(ip_addr, ports, '-v -Pn -sV ')
    

#this function asks for user if he want to do a new scan
def again():
    choice = input('\n\nDo you want to make a new scan? Type 1 for yes, type 2 for no.\n')

    if choice.upper() == '1':
        return 1
    elif choice.upper() == "2":
        return 2
    else:
        print('Please choose a valid symbol.\n')
        again()



def start():
    scan()
    while again() ==  True:
        scan()
    print('Thanks for using my script, see you soon!!\n')


def welcome():
    print("Welcome, this is a simple discovering and scanning automation script")
    print("<-------------------------------------------------------->")


port_scanner = nmap.PortScanner()
welcome()
start()
