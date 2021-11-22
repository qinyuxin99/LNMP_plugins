#!/bin/bash
#2021-7-21 14:35:50
#By Author xiaoyao
#Auto Install Init Server

#source /etc/rc.d/init.d/functions
#禁用SELINUX
function selinuxset() {
selinux_status=`grep "SELINUX=disabled" /etc/sysconfig/selinux | wc -l`
echo "========================禁用SELINUX========================"
if [ $selinux_status -eq 0 ];then
	sed -i.bak 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
else
	echo 'SELINUX已处于关闭状态'
fi
echo "==========================================================="
sleep 2
}
#修改sshd配置
function modify_ssh (){
echo "========================修改sshd配置========================"
#add qqc user
read -p "请输入主机名：" name
hostnamectl set-hostname $name
/usr/sbin/useradd zeus
usermod -G wheel zeus
read -p "请输入zeus用户的密码：" password
echo "$password" | passwd zeus --stdin
echo "4tfCC8HL12a" | passwd root --stdin
sed -i.bak 's/^%wheel/#&/' /etc/sudoers
echo "%wheel  ALL=(ALL)       NOPASSWD: ALL" >>/etc/sudoers
ssh_cf="/etc/ssh/sshd_config"
cp $ssh_cf $ssh_cf.$DATE
read -p "请输入远程端口：" port
sed -i "s/#Port 22/Port $port/" $ssh_cf
sed -i "s/#UseDNS yes/UseDNS no/" $ssh_cf
sed -i "/X11Forwarding yes/d" $ssh_cf
sed -i "s/#X11Forwarding no/X11Forwarding no/g" $ssh_cf
sed -i "s/#PrintMotd yes/PrintMotd no/g" $ssh_cf
sed -i "s/#PrintLastLog yes/PrintLastLog no/g" $ssh_cf
#sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' $ssh_cf
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' $ssh_cf
sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' $ssh_cf
sed -i 's/PasswordAuthentication no/PasswordAuthentication  yes/g' $ssh_cf

systemctl restart sshd
echo "==========================================================="
sleep 2
}

#历史记录优化
function historyset (){
echo "========================历史记录优化========================"
cat >>/etc/bashrc<<EOF
USER_IP=\`who -u am i 2>/dev/null | awk '{print \$NF}' | sed -e 's/[()]//g'\`
if [ "\$USER_IP" = "" ]
then
USER_IP=hostname
fi
export HISTTIMEFORMAT="%F %T \$USER_IP \`whoami\` "
shopt -s histappend
export PROMPT_COMMAND="history -a"
EOF
source /etc/bashrc
sed -i 's/^HISTSIZE=1000/HISTSIZE=3000/g' /etc/profile
source /etc/profile
echo "==========================================================="
sleep 2
}

#添加jumpserver登录用户
function jumpserver_user() {
if cat /etc/*release | grep ^NAME | grep CentOS; then
    echo "add user on CentOS"
    echo "==============================================="
    /usr/sbin/useradd admin
	usermod -G wheel admin
	echo "oqKb5U9m52vWceLa" | passwd admin --stdin
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
    echo "add user on Ubuntu"
    echo "==============================================="
	/usr/sbin/useradd -r -m -s /bin/bash admin
	usermod -G wheel admin
	echo "admin:oqKb5U9m52vWceLa" | chpasswd
fi
sleep 2
}


#修改时区
function timezonesset() {
echo "========================修改时区========================"
timedatectl set-timezone Asia/Shanghai
echo 'ZONE="Asia/Shanghai"' >/etc/sysconfig/clock
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime 
echo "##### update server time #####" >> /var/spool/cron/root
echo "*/10 * * * * /usr/sbin/ntpdate cn.pool.ntp.org > /dev/null 2>&1 && /sbin/clock -w > /dev/null 2>&1" >> /var/spool/cron/root
echo "==========================================================="
sleep 2
}

function menu() {
cat << eof
----------------------------------------------
|*******please enter your choice:[1-4]*******|
*   `echo -e "\033[34m 1)系统一键初始化\033[0m"`
*   `echo -e "\033[34m 2)自定义初始化\033[0m"`
*   `echo -e "\033[34m 3)jumpserver添加登录用户\033[0m"`
*   `echo -e "\033[34m 4)退出\033[0m"`
eof
read -p "`echo -e "\033[36m please input your optios[1-4]:\033[0m"` " num
case $num in
	1)
	selinuxset
	modify_ssh
	historyset
	timezonesset
	menu
	;;
	2)
	init_menu
	menu
	;;
	3)
	jumpserver_user
	menu
	;;
	4)
	echo -e "\033[31m--------退出--------- \033[0m"
	exit 0
	;;
	*)
	echo -e "\033[31mUsage: Please input Specify number\033[0m"
	exit 1
esac
}
function init_menu () {
cat << eof
----------------------------------------------
|*******please enter your choice:[1-9]*******|
*   `echo -e "\033[34m 1)禁用selinux\033[0m"`
*   `echo -e "\033[34m 2)调整sshd服务参数\033[0m"`
*   `echo -e "\033[34m 3)历史记录优化\033[0m"`
*   `echo -e "\033[34m 4)系统时区调整\033[0m"`
*   `echo -e "\033[34m 5)返回主菜单\033[0m"`
eof

read -p "`echo -e "\033[36m please input your optios[1-5]:\033[0m"` " num
case $num in
	1)
	selinuxset
	init_menu
	;;
	2)
	modify_ssh
	init_menu
	;;
	3)
	historyset
	init_menu
	;;
	4)
	timezonesset
	init_menu
	;;
	5)
	menu
	;;
	*)
	echo -e "\033[31mUsage: Please input Specify number\033[0m"
	exit 1
esac
}
menu
