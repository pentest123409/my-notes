- 按照大小列出当前目录所有文件 **find . -type  f -exec ls -s {} \;**  
- 清除全部历史记录命令和屏幕 **history -c ;clear ；****> ~/.bash_history；kali是**.zsh_history，因为不同的shell使用不同的历史命令，Fish使用~/.config/fish/fish_history
- 编辑**~/.bashrc，source ~/.bashrc** 使其生效
- **alias**  设置别名
- **grep -v** 反向操作 
- **ps -ef** 查找所有的进程
- **wc -l** 计算个数
- **shopt -s cdspell** 目录纠错命令
- **set +o ignoreeof** 按ctrl+D按键失败

常见排查命令 **lastlog**

**/dev/zero是Linux中的一个特殊文件，从文件dev/zero读出的内容均为空字符，它的一个典型用途就是提供用于初始化数据存储器的字符流。**

**/dev/null也是linux中的一个特殊文件，它可以接受所有向它写入的数据，而从这个文件中读不出任何数据。**

- **dd命令测试读写速度**

测试写速度time dd if=/dev/zero of=/tmp/test bs=8k count=1000000

测试读速度time dd if=/tmp/test of=/dev/null bs=8k

测试读写速度time dd if=/tmp/test of=/var/test bs=64k

①、time有计时作用，dd用于复制，从if读出，写到of；

②、if=/dev/zero不产生IO，因此可以用来测试纯写速度；

③、同理of=/dev/null不产生IO，可以用来测试纯读速度；

④、将/tmp/test拷贝到/var则同时测试了读写速度；

⑤、bs是每次读或写的大小，即一个块的大小，count是读写块的数量。

- **echo** 

echo -e 对后面的字符进行转义

**特殊符号**

$$——-shell本身的pid

$()与“——-命令替换(command subsititution)

$(())——-数学运算（arithmetical operation）

${}——-用做变量的替换（variable subsititution）

0、1、2指的是[文件描述符](https://so.csdn.net/so/search?q=文件描述符&spm=1001.2101.3001.7020)。

0：[stdin](https://so.csdn.net/so/search?q=stdin&spm=1001.2101.3001.7020)

1：stdout

2：stderr

“&”:用来指明其后跟的是文件描述符

$0 对应 "./test.sh" 这个值。如果执行的是 ./work/test.sh， 则对应 ./work/test.sh 这个值，而不是只返回文件名本身的部分。

$1 会获取到 a，即 $1 对应传给脚本的第一个参数。

$2 会获取到 b，即 $2 对应传给脚本的第二个参数。

$3 会获取到 c，即 $3 对应传给脚本的第三个参数。$4、$5 等参数的含义依此类推。

$# 会获取到 3，对应传入脚本的参数个数，统计的参数不包括 $0。

$@ 会获取到 "a" "b" "c"，也就是所有参数的列表，不包括 $0。

$* 也会获取到 "a" "b" "c"， 其值和 $@ 相同。但 "$*" 和 "$@" 有所不同。"$*" 把所有参数合并成一个字符串，而 "$@" 会得到一个字符串参数数组。

$? 可以获取到执行 ./test.sh a b c 命令后的返回值。在执行一个前台命令后，可以立即用 $? 获取到该命令的返回值。该命令可以是系统自身的命令，可以是 shell 脚本，也可以是自定义的 bash 函数。

$!是Shell最后运行的后台进程Id

- **正则表达式**

*

.

^

$

[ ]

匹配一串数字 ^[0-9]+$

匹配email     ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+.[A-Za-z]{2,4}$

匹配IPV4     ^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$

匹配IPV6     ^[A-Fa-z0-9:]+$

- 随机生成7位密码

tr -dc A-Za-z0-9_ < /dev/urandom | head -c7 | xargs

grep -i忽略大小写

head -n 5 显示前5行

head -c 5 显示前5个字节

echo front | sed 's/front/back/' 将front 替换为back cat -n .bashrc | sed '3,10d' 显示.bashrc里除第3行到第10行的内容 cat -n .bashrc | sed -n '3,10p'  只显示.bashrc里第3到10行的内容