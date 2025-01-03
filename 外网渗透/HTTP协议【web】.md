**第一章 HTTP概述**

- 媒体类型MIME

- - HTML格式的文本文档 text/html
  - 普通ASCII文本文档 text/plain
  - JPEG版本图片image/jpeg
  - GIF格式图片image/gif
  - Apple的电影video/quiktime
  - 微软的powerpoint application/vnd.ms-powerpoint
  - ...数百个

**第二章 URL与资源**

通用格式

<scheme>://<user>:<password>@<host>:<port>/<path>;<params>?<query>#<frag>

片段的含义

浏览器从服务器获取了整个包括该路径的资源后，根据片段，定位到片段的部分进行显示。