- 本地端口转发

  - client（攻击机）->jump-server（目标机）

  - 示例 `ssh -L 2121:1.1.1.10:21 root@192.168.1.11`

  - 实战

    - 1.配置跳板机的SSH配置文件

      - AllowTcpForwarding

      - GatewayPorts

      - PermitRootLogin

      - PasswordAuthentication

      - TCPKeepAlive

    - 2.在攻击机上执行命令 ssh -CfNg -L 2121:1.1.1.10:3389 root@192.168.1.11
      命令参数:C/压缩传输;f/后台执行不占用shell;N/建立连接看不到会话;g/运行远程主机连接到本地用于转发的端口

    - 3.输入rdesktop 127.0.0.1:2121

- 远程端口转发

  - 应用场景：都是内网主机，外网的攻击机不能访问内网的主机，但是内网的主机可以访问外网

  - 示例 `ssh -R 2121:1.1.1.10:21 root@192.168.1.10
  - 动态端口转发也称SOCKS代理
    - 示例`ssh -D 1080 user@remoteserver`
  - 防范
    - 对SSH的配置文件设置白名单，限制只允许特定IP连接SSH