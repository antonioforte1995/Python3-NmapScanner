#!/usr/bin/python3

# run so:   $ sudo python3 Scanner.py

import subprocess
import os
import nmap


#this function is used to make an ARP scan on a particular network
def arp_scan(ip_addr: str, left_index: int, right_index: int):
    for n in range(left_index, right_index+1):
        subnet = ip_addr[0:12]
        ip = subnet+'{0}'.format(n)
        os.system('nmap -PR ' + ip)


#this function is used to make ports scan of a particular host
def port_scan(resp_3: int, ip_addr: str):
		if resp_3 == '1':
			os.system('nmap -Pn -sS ' + ip_addr)
		elif resp_3 == '2':
			os.system('nmap -Pn -sA ' + ip_addr)
		elif resp_3 == '3':
			os.system('nmap -Pn -sF ' + ip_addr)
		elif resp_3 == '4':
			os.system('nmap -Pn -sU ' + ip_addr)
		elif resp_3 == '5':
			os.system('nmap -Pn -sO ' + ip_addr)
		elif resp_3 == '6':
			os.system('nmap -Pn -sA ' + ip_addr)
		else:
			os.system('nmap -Pn -sV ' + ip_addr)
	



def scan():
	resp_1 = input("""\nWhat is your target?"
	1) an host 
	2) a network\n""")
	if resp_1 == '1':
		# if the target is an host then I'm here
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
		# if the target is a network then I'm here.
		# The port scanning option is not avaible in this case for performance reason
		resp_2 = input("""\nWhat do you want to do?"
		1) ARP scan
		2) ICMP Host discovering\n""")
		ip_addr = '192.168.1.0'  # default subnet ip address
		prompt_str = input('\nPlease enter the target subnet IP ['+ip_addr+']: \n')
		ip_addr = prompt_str or ip_addr
		print("\nSelected subnet IP: ", ip_addr)
		type(ip_addr)
    

	if resp_2 == '1':
		# if I want to do an ARP scan then I'm here
		if resp_1 == '1':
			os.system('nmap -sn -PR ' + ip_addr)
		else:
			arp_scan(ip_addr, left_index, right_index)
	elif resp_2 == '2':
		# if I want to do an ICMP scan then I'm here
		if resp_1 == '1':
			os.system('fping '+ ip_addr)
		else:
			print('\nThe following hosts are alive:')
			os.system('fping -a -g -r 1 '+ ip_addr +'/24 2> /dev/null')
			
	else:
		# if I want to do a port scanning then I'm here
		if resp_1 == '1': 
			# if I want to do a port scanning and the target is an host then I'm here
			resp_3 = input("""\nEnter the port scan type you want to run:
			1) SYN scan
			2) ACK scan
			3) FIN scan
			4) UDP scan
			5) OS detection (stack fingerprinting)
			6) Aggressive scan(OS and version detection)
			7) Versions of services scan \n""")

			resp_4 = input("""\nWhat ports you want to scan?"
			1) particular port    
			2) Fast scan (scan only the most important ports. SYN flag is used..)                    
			3) particular range of ports [1-1024]
			4) all 65.536 ports\n""")

			if resp_4 == '1':
				# if I want to scan a particular port then I'm here
				port = input('\nGive me the particular port:')
				print('\nPort chosen: {0}'.format(port))
				if resp_3 == '1':
					os.system('nmap -p' + port + ' -sS ' + ip_addr)
				elif resp_3 == '2':
					os.system('nmap -p' + port + ' -sA ' + ip_addr)
				elif resp_3 == '3':
					os.system('nmap -p' + port + ' -sF ' + ip_addr)
				elif resp_3 == '4':
					os.system('nmap -p' + port + ' -sU ' + ip_addr)
				elif resp_3 == '5':
					os.system('nmap -p' + port + ' -sO ' + ip_addr)
				elif resp_3 == '6':
					os.system('nmap -p' + port + ' -sA ' + ip_addr)
				else:
					os.system('nmap -p' + port + ' -sV ' + ip_addr)
			elif resp_4 == '2':
				# if I want to scan only the most important ports then I'm here
				os.system('nmap -Pn -F ' + ip_addr)
			elif resp_4 == '3':
				# if I want to scan a particular range of ports [1-1024] then I'm here
				port_scan(resp_3, ip_addr)
			else:
				# if I want to scan all 65.536 ports then I'm here
				resp_4 = input("""\nWhat ports do you want to scan?:
				1) TCP ports
				2) UDP ports
				3) TCP and UDP ports\n""")
				if resp_4 == '1':
					os.system('nmap -p- ' + ip_addr)
				elif resp_4 == '2': 
					os.system('nmap -sU -p- ' + ip_addr)
				else:  
					os.system('nmap -sU -sT -p- ' + ip_addr)

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


#this is the program start function
def start():
    welcome()
    scan()
    while again() ==  True:
        scan()
    print('Thanks for using my script, see you soon!!\n')


#this is the program welcome function
def welcome():
    print("Welcome, this is a simple discovering and scanning automation script")
    print("<-------------------------------------------------------->")


#here the execution starts
port_scanner = nmap.PortScanner()
start()
