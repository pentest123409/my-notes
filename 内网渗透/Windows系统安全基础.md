一、账号安全

1.1 Windows系统账号概述及安全解析

**内置用户**local service、network service、Guest、Administrator、System

说明：system权限比Administrator高，local service和network service都相当于Users没有什么权限，不同的是在域中，这两个账户有区分。

**动态包含成员的内置组**Interactive、Authenticated Users、Everyone

说明：Interactive动态包含在本地登录的用户，Authenticated Users动态包含了通过验证的用户，不包含来宾用户。

**Windows账号克隆及超级隐藏**

方式一：通过注册表

查看某个账户的详细信息 net user guest

创建隐藏用户 net user test$ /add，在命令行看不到，用户界面可以看到

![image-20250103124100602](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124100602.png)

![image-20250103124105788](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124105788.png)

加入管理员 net localgroup administrators test$ /add

打开管理的命令 compmgmt.msc

打开本地策略的命令secpol.msc

让所有人可以展开键值

![image-20250103124117647](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124117647.png)

将administrator的用户注册表的F值替换到test$

net user test$ /del删除test$用户

重新导入test$的两个注册表

效果

![image-20250103124128356](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124128356.png)

![image-20250103124135039](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124135039.png)

![image-20250103124140612](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124140612.png)

清理方式是删除注册表中的用户和权限信息

方式二：Rootkit超级隐藏账户(没生效）

![image-20250103124151850](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124151850.png)

RootKit的程序进程往往是隐藏或者嵌入的，通过Windows的“任务管理器”是无法看到的。可以利用强大的进程工具lceSword (冰刃)查看。

修改密码

![image-20250103124204129](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124204129.png)

sysdm.cpl开启远程连接登录尝试

lceSword (冰刃)能够在注册表里看到隐藏用户

**Windows11清除密码**

![image-20250103124214705](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124214705.png)

![image-20250103124223947](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124223947.png)

![image-20250103124230420](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124230420.png)

将辅助程序替换成命令行程序

先备份辅助程序

![image-20250103124240686](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124240686.png)

![image-20250103124245559](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124245559.png)

运行成功后，重启计算机，点击右下角辅助程序已被替换为命令行

![image-20250103124255864](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124255864.png)

**mimikatz获取密码**

以管理员打开猕猴桃工具

输入privilege::debug

输入sekurlsa::logonpasswords

![image-20250103124306080](C:\Users\test\AppData\Roaming\Typora\typora-user-images\image-20250103124306080.png)