**Windows C盘共享的命令：**

net share查看

net share c$=C\  /grant:everyone,full共享C盘

net share c$  /delete删除共享

**能对Windows进行本地扫描的前提：**

1.共享C盘

2.server服务打开

3.组策略里面网络访问：本地账户的共享和安全模式改为经典——对本地用户进行身份验证，不改变其未来身份

Windows的常见cmd命令：

services.msc打开服务

compmgmt.msc打开电脑管理器

gpedit.msc打开组策略

**此次实验对Windows2003的操作：**

1.先共享

2.打开电脑管理器

3.安全选项，有个共享，打开共享向导，里面改为经典

**漏扫如果扫不出来弱口令:**

新建密码字典并导入进去，然后扫

**分析误报：**

看详细版本

**带内管理的意思：**

业务口和管理口共用一个接口

**Linux系统修改IP地址的文件：**

/etc/sysconfig/network-scripts eth*