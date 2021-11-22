#!/bin/bash
# 切片初始化脚本
# 使用方法
# bash init_slice.sh  init_slice  非交互式安装
# bash init_slice.sh  init_vsftp 非交互式安装
# bash init_slice.sh 交互式安装



local_ip=`curl -s ifconfig.me`

init_ubuntu20_04(){
    # 设置登录用户，时区
    apt update -y
    apt upgrade -y
    echo "root:4tfCC8HL12a" | chpasswd
    useradd -r -m -s /bin/bash zeus
    read -p "请输入zeus用户的密码：" password
    echo "zeus:$password" | chpasswd
    if [ `cat /etc/group|grep "wheel"|wc -l` -eq 0 ];then
		groupadd wheel
    fi
    usermod -G wheel zeus
    echo '%wheel  ALL=(ALL)   NOPASSWD: ALL' >>/etc/sudoers
    # ssh设置 关闭root登录  修改登录端口
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    echo "Port 2233" >>/etc/ssh/sshd_config
    echo "PermitRootLogin no" >>/etc/ssh/sshd_config
	systemctl restart sshd
    # 设置时区
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    export DEBIAN_FRONTEND=noninteractive
    dpkg-reconfigure --frontend noninteractive tzdata
}

init_vsftp(){
# vsftp 初始化
apt install vsftpd -y
apt install -y curl
# rm -rf /etc/vsftpd.conf
cat >/etc/vsftpd.conf <<EOF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
allow_writeable_chroot=YES
pasv_enable=YES
pasv_address=${local_ip}
pasv_min_port=30000
pasv_max_port=31000
local_root=/opt/video/
EOF
inet=`ip a|grep "global" | awk '{print $2}' |awk -F / '{print $1}'`
for i in $inet
do
        if [ "$local_ip" != "$i" ];then
                echo "pasv_address=$i" >>/etc/vsftpd.conf
        fi
done

systemctl restart vsftpd
systemctl enable vsftpd
}

init_slice() {
    # 切片环境安装
    apt update -y
    apt install ffmpeg -y
    apt install python3-pip -y
    pip3 install --upgrade pip
    pip3 install ffmpy3
    pip3 install opencv-python
    pip3 install pymysql
	
	#设置ufw防火墙
	ufw allow 22/tcp
	ufw allow 2233/tcp
	ufw allow 20:21/tcp
	ufw allow 30000:31000/tcp
	ufw enable
    
	# 建立切片用户
	id zeus
	if [ $? -ne 0 ];then
		useradd -r -m -s /bin/bash zeus
		read -p "请输入zeus用户的密码：" password
		echo "zeus:${password}" | chpasswd
	fi
	useradd -r -m -s /bin/bash xvideo
    echo "xvideo:aikW6mcfTejbwCd1" | chpasswd
    mkdir /opt/video/ /opt/video/v_origin /opt/video/v_upload/ -p
    mkdir /opt/tmp /opt/tmp/runtime /opt/tmp/v_error
    mkdir /opt/tmp/v_proed /opt/tmp/v_rate /opt/tmp/v_slice
    chown -R xvideo:xvideo /opt/video
    chown -R zeus:zeus /opt/tmp -R
}

if [ $# -eq 0 ];then
	echo -e "\033[36m 非交互式一键初始化安装:\033[0m"
	init_ubuntu20_04
	init_slice
	init_vsftp
else
	case $1 in
	"init_ubuntu20_04")
	    init_ubuntu20_04
	    ;;
        "init_slice")
            init_slice
            ;;
        "init_vsftp")
            init_vsftp
            ;;
        *)
	    echo -e "\033[36m Usage:sh init_slice.sh 'init_ubuntu20_04|init_vsftp|init_slice'\033[0m"
            ;;
        esac
fi