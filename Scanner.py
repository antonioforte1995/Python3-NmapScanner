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


#this function is used to make an ICMP scan on a particular network
def icmp_host_disc(ip_addr: str, left_index: int, right_index: int):
    for n in range(left_index, right_index+1):
        subnet = ip_addr[0:12]
        ip = subnet+'{0}'.format(n)
        os.system('ping -c 2 ' + ip)



#this function is used to make ports scan of a particular host
def port_scan(resp_3: int, left_index: int, right_index: int, ip_addr: str):
	for n in range(left_index, right_index):
		if resp_3 == '1':
			os.system('nmap -p' + str(n) +' -Pn -sS ' + ip_addr)
		elif resp_3 == '2':
			os.system('nmap -p' + str(n) +' -Pn -sA ' + ip_addr)
		elif resp_3 == '3':
			os.system('nmap -p' + str(n) +' -Pn -sF ' + ip_addr)
		elif resp_3 == '4':
			os.system('nmap -p' + str(n) +' -Pn -sU ' + ip_addr)
		elif resp_3 == '5':
			os.system('nmap -p' + str(n) +' -Pn -sO ' + ip_addr)
		elif resp_3 == '6':
			os.system('nmap -p' + str(n) +' -Pn -sA ' + ip_addr)
		else:
			os.system('nmap -p' + str(n) +' -Pn -sV ' + ip_addr)
	



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
		print('\nPlease enter the subnet IP you want to scan ['+ip_addr+']:\n')
		left_index = int(input('\nGive me the left index of range of hosts to scan:\n'))
		right_index = int(input('\nGive me the right index of range of hosts to scan:\n'))
    

	if resp_2 == '1':
		# if I want to do an ARP scan then I'm here
		if left_index == right_index:
			os.system('nmap -sn -PR ' + ip_addr)
		else:
			arp_scan(ip_addr, left_index, right_index)
	elif resp_2 == '2':
		# if I want to do an ICMP scan then I'm here
		if left_index == right_index:
			os.system('ping -c 2 ' + ip_addr)
		else:
			icmp_host_disc(ip_addr, left_index, right_index)
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
			7) Services versions scan \n""")

			resp_4 = input("""\nWhat ports you want to scan?"
			1) particular port    
			2) Fast scan (scan only the most important ports. SYN flag is used..)                    
			3) particular range of ports\n""")


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
			else:
				# if I want to scan a particular range of ports then I'm here
				left_index_default = '1'
				right_index_default = '1024'
				left_index = int(input('\nGive me the left index of range of ports to scan:\n'))
				right_index = int(input('\nGive me the right index of range of ports to scan:\n'))
				left_index = left_index or left_index_default
				right_index = (right_index + 1) or right_index_default
				#print('\nSelected port range: ' + left_index + '-' + right_index'\n)
				port_scan(resp_3, left_index, right_index, ip_addr)
	    

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
