**一、metasploit目录**

**modules目录**

**auxiliary**:辅助模块，辅助渗透（端口扫描，登录密码爆破，漏洞验证等）

**exploits:**漏洞利用模块，包含主流的漏洞利用脚本，通常是对某些可能存在漏洞的目标进行漏洞利用。命名规则：操作系统.各种应用协议分类。

**payloads：**攻击载荷，主要是攻击成功后在目标机器执行等代码，比如反弹shell的代码。

**post:**后渗透阶段模块，漏洞利用成功获得meterpreter之后，向目标发送的一些功能性指令，如：提权等。

**encoders:**编码器模块，主要包含各种编码工具，对payload进行编码加密，以便绕过入侵检测和过滤系统。

**evasion:**躲避模块，用来生成免杀payload

**nops:**由于IDS/IPS会检查数据包中不规则的数据，在某些情况下，比如针对溢出攻击，某些特殊滑行字符串(NOPS x90x90)则会因为被拦截而导致攻击失效

**二、Metasploit体系结构**

armitage图形化界面，msfnevom生成shellcode用到的命令

初始化数据库service postgresql start;msfdb init

**三、常见数据库默认端口**

sqlserver默认端口1433

oracle默认端口1521

DB2默认端口5000

Postgresql默认端口5432

**四、metasploit内网主机发现**

db_nmap:nmap扫描

-PA：TCP ACK PING扫描

-PS: TCP SYN PING扫描

-PR: ARP扫描，尤其在内网的情况下，防火墙不会禁止ARP请求

-T【0-5】：默认为T3，T4表示最大TCP扫描延迟为10秒

-sS：TCP SYN扫描

-sA:TCP ACK扫描

-sY:TCP SYN扫描

-A：打开操作系统探测和版本探测

--script=vuln

**五、metasploit使用**

search:搜索msf中相关组件

search platform:windows cve:2009 type:exploit