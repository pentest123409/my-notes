**获取MAC的两种方式：**

![image-20250103123311718](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123311718.png)

**SecureCRT更改编码的方式：**右键单击

![image-20250103123320008](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123320008.png)

在会话选项里

![image-20250103123331029](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123331029.png)

**账号**

admin\admin

auditor\auditor

**工作原理** 基于漏洞数据库

存活判断

端口扫描

系统、服务识别

弱口令扫描插件

精确扫描插件

版本扫描插件

本地扫描插件

**扫描存活判断的方式**

ICMP ping

TCP ping

UDP ping

口令猜测需要开启登录验证

登录扫描

windows支持SMB RDP

linux支持SSH telnet

**镜像扫描 V6.0R03F01 最低配置四核8G**

即公有镜像仓库，如国内公有镜像仓库。 

 https://c.163.com/hub#/m/home/ 网易仓库     

 https://hub.daocloud.io Daocloud仓库

仓库扫描，即私有镜像仓库，指得客户自己搭建的仓库

串行执行

镜像扫描仅在S，E和A型号中运行；X和P型号中无法运行镜像扫描

Q1：下发镜像扫描任务需要注意什么？  A: 不管是公有镜像扫描还是私有仓库扫描（域名或者是IP格式的仓库），都需要确保网络可达。因为在扫描的过程中，会连接仓库获取信息。如果是域名格式的仓库，需要配置DNS，确保扫描器到仓库是可达的。

Q2：获取域名仓库镜像列表时，已配置域名仓库DNS，为什么不能获取到镜像列表？

A: 目前域名仓库DNS仅支持配置在首选DNS里，如果配置在备选DNS，域名可能没有被解析，所以不能访问；请调整首选/备选DNS顺序后再尝试。

Agent扫描V6.0R04新增

**Agent数据管理**

Agent会定期（每4小时）收集客户端数据上报至server，server端保存最近24小时数据

**Agent删除仍有数据原因数据**

由于Agent联动的特殊，RSAS删除不能操控远程Agent客户端，因此Agent删除操作只能针对RSAS Server端已有数据，在线的agent依旧会给Server端上报信息。

SERVER端根据客户端上传的心跳数据判断是否是最新版本，非最新版本时，触发升级

**代码审计的四种方式**

正则表达式

抽象语法树（词法，语法）

数据流

控制流

**使用代码审计的前提条件：**

系统版本：V6.0R04F00及以上

设备证书：包含代码审计

设备资源：CPU>=8核，内存>=16G；RSAS A型号/E型号/满足资源要求的VM型号

**代码审计任务操作**

支持的任务操作：

重扫/批量重扫，删除/批量删除/全部删除，暂停/批量暂停，停止/批量停止，导出/批量导出，导入

不支持的任务操作：

断点续扫，汇总查看

**代码审计注意**

代码审计任务的并发数为1，若新建了多个代码审计任务，同时只会对1个代码审计任务进行扫描，其他任务为等待状态

支持对三种来源的代码进行安全缺陷扫描或编码规范扫描，SVN获取和GIT获取，支持连通测试，可测试仓库地址是否可达，认证信息是否正确

通过GTI获取的代码支持四种认证方式，可根据具体待审计的Git仓库地址支持的认证方式进行选择

代码来源仅支持svn获取和GIT获取，不支持手动上传需要证书同时包含代码审计和数据接口模块，才可以使用此接口

支持输出的报表类型：Word，Excel，HTML

**漏扫支持导出的报表类型**

pdf/xml/word/excel，仅支持html的发送到邮箱

**清空已使用IP方法：**

​	1.试用证书切换成正式证书，授权会被清空

2.正式证书过期，用户续证，正式证书起始时间发生变化，清空授权

​	3.申请清空包 注：任何时候导入试用证书都不清空授权

测试证书有效期内：只能同步修改系统时间

**Linux端口与进程查询**

进程查看ps aux

端口查询netstat  -antu

查询端口与进程的关系lsof –i tcp:port

**Windows端口与进程查询**

当前连接查询	netstat –ano

当前进程列表	tasklist /svc

netstat -ano | findstr "8081"

tasklist /svc | findstr "488"

**虚拟化**

虚拟化镜像要求的硬盘空间必须大于100G

**认证方式**

![image-20250103123346356](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123346356.png)

**云端认证：**

域名地址为：auth.api.nsfocus.com(主要);espp.api.nsfocus.com