**实验：**

一、串联部署

- - 带内管理
  - 本机网关网关写对端地址

二、旁路部署 

- - - 注意不要选择bypass口，即为上下，选择了就是一根网线，不起任何防护作用
    - 重置

- - - 起VLAN，dis this检查加没加进去
    - 

![image-20250103123414877](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123414877.png)

- - 思路：

  - - SW1（上）和SW2（下）写路由，目的地分别是202.0.2.0/24和2.2.2.0/24。
    - 在WAF上写回注路由，目的地202.0.2.10/32，下一跳3.3.3.6。
    - 在SW1上写目的地为202.0.2.10/32,下一跳为3.3.3.2。

三、反向代理

四、镜像监听

 **system-view**

**进入全局模式**

**[Quidway] observe-port 1 interface** **e****thernet 0/0/****4**

**设置监听口**

**[Quidway] interface** **e****thernet 0/0/****1**

 **[Quidway-Ethernet0/0/****1****] port-mirroring to observe-port 1** **both**

**设置被监听口**

**display port-mirroring**

**查看监听口配置**

**注意点：**

- - - 交换机清空
    - WAF路由/接口清空
    - 先画图，画接口再连线
    - 每给接口配一个IP都要检验有没有生效
    - 接口是哪个口就起与他相关的好记忆的VLANID

查看所有接口信息

dis ip int b

![image-20250103123429522](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103123429522.png)

五、单臂旁路

 跟反向代理不同，会环路。

六、安全防护

**sql注入防护**

\1. 进入靶场http://192.168.29.176/DVWA-master  用户名/密码：**admin/password**

\2. 左侧进入DVWA Security设置安全等级为Low

\3. 停用WAF站点防护，左侧进入SQL Injection选项页，尝试在User ID键入1，提交; 返回正常值，键入1'并提交,可以看到存在注入点。：

\4. 在User ID 输入1' union select version(),database()#发现可以查询当前的数据库，以及版本。

\5. 启用WAF站点防护并进行配置，重新进行SQL注入，动作被阻断。

\6. 点击日志报表的安全防护日志，查看阻断请求的规则详情。

\7. 站点防护策略中“web通用防护”的动作选择“阻断”，虚拟站点防护策略中“web通用防护”的动作选择“放过”，观察SQL注入是被放过还是被阻断。点击日志报表的安全防护日志，查看相应告警，分析SQL注入攻击被放过的原因。

**XSS防护**

\1. 停用WAF站点防护，左侧进入XSS(reflected)选项页，在搜索框输入，点击搜索，发现触发了反射型跨站脚本的alert弹窗：

\2. 开启站点防护并确认启用跨站脚本防护，重复操作，WAF进行了阻断。并检查日志可以看到阻断记录。

\3. 停用WAF站点防护，左侧进入XSS(stored)选项页，在Name中键入123，在Message中键入点提交；页面触发存储性跨站脚本漏洞弹出alert。且在clear之前，弹窗会在刷新页面时总是弹出。

\4. 开启站点防护并重复操作，WAF进行了阻断。并检查日志可以看到阻断记录。

**扫描防护**

\1. 停用站点防护，开启WVS，用户名nsfocus@nsfocus.com 密码nsfocus@123;对站点http://192.168.29.176/DVWA-master 进行扫描，扫描成功。

\2. 开启站点防护，设置扫描防护策略

\3. 重复扫描操作，扫描被WAF拦截，查看扫描结果：查看waf日志显示拦截：

**信息泄露防护：curl在虚拟机客户端的C盘根目录**

1、 停用WAF的站点防护功能，执行curl –I 192.168.29.176， 对服务器进行请求提交后，服务器返回server类型； 

2、 启用站点防护功能，配置策略，修改server名为123123，再次执行操作，查看结果。

3、 停用WAF的站点防护功能，使用curl提交一个不存在的页面，服务器返回404报错；

4、 启用站点防护功能，通过信息泄露防护来修改服务器名、404报错为500，查看返回信息。

curl命令：curl –I 页面的URI

**盗链防护**

1、 停用WAF的站点防护功能

2、 使用curl构造带Referer的请求，Referer的源为www.nsfocus.com，资源目标为http://192.168.29.176/DVWA-master/hackable/uploads/dvwa_email.png

CURL命令：curl -A "Firefox" -e "http://www.nsfocus.comww[w.nsfocus.com" http://192.168.29.176/DVWA-master/hackable/uploads](http://192.168.29.176/DVWA-master/hackable/uploads/dvwa_email.png)/dvwa_email.png > null

3、 启用WAF的站点防护功能，使用WAF盗链防护策略来阻断Referer为非可信站点的请求；

4、 查看被WAF阻断后的效果和相关告警日志。

**非法下载**

\1. 停用WAF的站点防护，在浏览器中输入http://192.168.29.176/DVWA-master/db.sql，下载该文件；

\2. 启用WAF的站点防护，配置非法下载策略，重复上述操作，阻断该下载

\3. 查看告警日志：

**非法上传**

\1. 关闭站点防护，点击左侧File Upload选项页，将upload.php进行上传，成功，显示上传的路径

\2. 启用WAF的站点防护功能，配置非法上传防护策略，重复上述操作，阻断上传该文件；

\3. 查看防护后的效果和阻断日志。

**webshell防护**

\1. 停用WAF的站点防护；利用上传实验的操作，上传Phpma.php

\2. 在浏览器访问此路径文件http://192.168.29.173/DVWA-master/hackable/uploads/Phpma.php 成功获取服务器banner信息

\3. 打开菜刀工具，输入之前上传的upload.php路径：发现可以对服务器资源进行操作

\4. 开启webshell防护策略，重新访问操作，waf阻断访问该webshell

\5. 继续使用菜刀工具访问服务器路径，操作无响应，被WAF拦截：

\6. 查看相关日志：