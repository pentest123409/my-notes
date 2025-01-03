- 防止嗅探重放的方式：加入时间戳和password一起加密（APP程序加密或浏览器JS加密）
- 防范接口不被篡改的方式：接口签名
  http://www.enjoylife.com/recharge?phone=12345&money=100&sign=ffsadhffgfg 加盐
  ​