# 1、介绍

```shell-session
shaokaka@htb[/htb]$  xfreerdp /v:10.129.43.36 /u:htb-student
```

## 1.1工具

[Seatbelt ](https://github.com/GhostPack/Seatbelt) 用于执行各种本地权限提升检查的 C# 项目

[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) WinPEAS 是一个脚本，用于搜索可能的路径以提升 Windows 主机上的权限

[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) PowerShell 脚本，用于查找依赖于错误配置的常见 Windows 权限提升向量。它还可用于利用发现的一些问题

[SharpUp](https://github.com/GhostPack/SharpUp) C# 版本的 PowerUp 

[JAWS](https://github.com/411Hall/JAWS) 用于枚举在 PowerShell 2.0 中编写的权限提升向量的 PowerShell 脚本

[SessionGopher](https://github.com/Arvanaghi/SessionGopher) SessionGopher 是一个 PowerShell 工具，用于查找和解密远程访问工具的已保存会话信息。它提取 PuTTY、WinSCP、SuperPuTTY、FileZilla 和 RDP 保存的会话信息

[Watson](https://github.com/rasta-mouse/Watson) Watson 是一个 .NET 工具，旨在枚举丢失的知识库并建议针对权限提升漏洞的漏洞

[LaZagne  ](https://github.com/AlessandroZ/LaZagne)用于从 Web 浏览器、聊天工具、数据库、Git、电子邮件、内存转储、PHP、系统管理工具、无线网络配置、内部 Windows 密码存储机制等检索存储在本地计算机上的密码的工具

[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng) WES-NG 是一个基于 Windows 的 `systeminfo` 实用程序输出的工具，它提供了作系统易受攻击的漏洞列表，包括针对这些漏洞的任何漏洞。支持 Windows XP 和 Windows 10 之间的每个 Windows 作系统，包括它们的 Windows Server 对应版本

[Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 我们将在枚举中使用 Sysinternals 中的多个工具，包括 [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk)、[PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist) 和 [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice)

<!--工具可能是一把双刃剑。虽然它们有助于加快枚举过程并为我们提供高度详细的输出，但如果我们不知道如何读取输出或将其缩小到最有趣的数据点，我们的工作效率可能会降低。工具也会产生误报，因此我们必须深入了解许多可能的权限升级技术，以便在出现问题或看起来不像那样时进行故障排除。手动学习枚举技术将有助于确保我们不会因工具问题（如误报或误报）而遗漏明显的缺陷。-->

<!--假设他们正在寻找尽可能多的问题，并且不打算在这个阶段测试他们的防守。-->

# 2、了解情况

## 2.1态势感知

### 2.1.1网络信息

接口、IP 地址、DNS 信息

```cmd-session
C:\htb> ipconfig /all
```

ARP 表

```cmd-session
C:\htb> arp -a
```

路由表

```cmd-session
C:\htb> route print
```

检查 Windows Defender 状态

```powershell-session
PS C:\htb> Get-MpComputerStatus
```

列出 AppLocker 规则

```powershell-session
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

测试 AppLocker 策略

```powershell-session
PS C:\htb> Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```