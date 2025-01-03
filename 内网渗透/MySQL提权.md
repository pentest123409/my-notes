- UDF提权

  - 条件

    - Server 2003、Windows XP、Windows 7及以下版本

    - mysql的root用户密码

    - UDF存放目录：mysql<5.2，存在于系统目录c:/windows/system32/，mysql>5.2，存在于安装目录MySQL\Lib\Plugin\

    - 配置项secure_file_priv为空，可写文件

  - 原理

    - 利用root权限，导入带有调用cmd函数的udf.dll（动态链接库）

    - 将udf.dll引入Mysql，即可调用其中的函数进行使用

  - 利用：python3 cloak.py -d -i ../../data/udf/mysql/windows/64/lib_mysqludf_sys.dll_ -o udf.dll

- MOF提权

  - 条件:Windows Server 2003

  - 原理：C:/Windows/system32/wbem/mof/目录下的mof文件每隔一段时间（几秒钟左右）都会被系统执行，因为这个MOF里有一部分是VBS脚本，所以可以利用这个VBS脚本来调用CMD来执行系统命令，如果Mysql有权限操作mof目录的话，就可以来执行任意命令。

- 启动项提权

  - 原理：当Windows开机的时候都会有一些开机启动的程序，在不同Windows版本中，开启启动程序除了可以在注册表中写入，还可以通过将程序放入指定目录中达到开机启动的效果。

  - 利用：在知道了路径的情况下，我们需要往启动项中写入脚本，脚本支持vbs和exe类型