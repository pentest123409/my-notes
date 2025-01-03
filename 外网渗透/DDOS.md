- Slowloris攻击
  - 针对HTTP协议头部的攻击
    在正常的HTTP通信中，请求头部以两个CLRF（Carriage Return and Line Feed）序列结束，表示HTTP Headers部分的结束。如果服务器只收到一个CLRF，它会认为头部未结束，并保持连接开放，继续等待完整的请求。攻击者利用这个机制，发送不完整头部信息的请求，并保持这些连接处于半开放状态
- HTTP Post攻击（CC攻击）
  对任何一个开放了HTTP访问的服务器[HTTP服务器](https://so.csdn.net/so/search?q=HTTP服务器&spm=1001.2101.3001.7020)，先建立了一个连接，指定一个比较大的content-length，然后以非常低的速度发包，比如1-10s发一个字节，然后维持住这个连接不断开。
- Server Limit DoS
  Cookie也能造成一种拒绝服务，称为Server Limie DOS。Web Server对HTTP包头都有长度限制，以Apache举例，默认是8192字节。也就是说，Apache所能接受的最大HTTP包头大小为8192字节(这里指的是Request Header,如果是Request Body，则默认的大小限制是2GB)。如果客户端发送的HTTP包头超过这个大小，服务器就会返回一个4xx错误，提示信息为：
  Your browser sent a request that this server could not understand.
  Size of a request header field exceeds server limit.
  假如攻击者通过XSS攻击，恶意地往客户端写入了一个超长的Cookie，则该客户端在清空Cookie之前，将无法再访问该Cookie所在域的任何页面。这是因为Cookie也是放在HTTP包头里发送的，而Web Server默认会认为这是一个超长的非正常请求，从而导致“客户端”的拒绝服务。