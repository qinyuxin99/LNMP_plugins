#!/bin/bash
#2021-7-21 14:35:50
#By Author xiaoyao
#Auto Install PHP Server
 
source /etc/rc.d/init.d/functions
 
#Define PHP path variables
PHP_FILE=php-7.3.28.tar.gz
PHP_PREFIX=/usr/local/php
FILE_DIR=/data/package
INSTALL_DIR=/usr/local
USER=www

#Define Nginx path variables
Nginx_FILE=nginx-1.20.1.tar.gz
Nginx_FILE_DIR=/data/${Nginx_FILE%.*.*}
Nginx_PREFIX=/usr/local/nginx
 
#Define Nginx path variables
Mysql_FILE=mariadb-10.5.10-linux-systemd-x86_64.tar.gz
Mysql_PREFIX=/usr/local/mariadb
Mysql_user=mysql

ftp="34.219.76.249"
ftp_user="Operation"
ftp_pass="5fwTYHOYEFNxJV75"
DATE=`date +%Y%m%H`
if [ ! -d ${FILE_DIR} ];then mkdir -p ${FILE_DIR};fi
###安装常用软件
cmd="vim git wget unzip net-tools lsof htop nmap iotop telnet iptraf iftop logrotate bind-utils sysstat irqbalance microcode_ctl dstat net-snmp rsync ntpdate"
function install_softcmd (){
###检测操作系统版本
if cat /etc/*release | grep ^NAME | grep CentOS; then
    echo "==============================================="
    echo "Installing packages $cmd on CentOS"
    echo "==============================================="
    yum install -y $cmd > /dev/null
elif cat /etc/*release | grep ^NAME | grep Ubuntu; then
    echo "==============================================="
    echo "Installing packages $cmd on Ubuntu"
    echo "==============================================="
    apt-get update > /dev/null
    apt-get install -y $cmd > /dev/null
fi
sleep 2
}
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
	action "完成禁用SELINUX" /bin/true
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
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' $ssh_cf
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
#修改文件描述符
function limitset() {
echo "========================修改文件描述符========================"
#set ulimit
echo -e "* soft nproc 1000000\n* hard nproc 1000000\n* soft nofile 1000000\n* hard nofile 1000000" >> /etc/security/limits.conf
ulimit -a
echo "==========================================================="
sleep 2
}

#优化系统内核
function kernelset() {
echo "========================优化系统内核========================"
sysconf="/etc/sysctl.conf"
/usr/sbin/modprobe nf_conntrack
/usr/sbin/modprobe nf_conntrack_ipv4
echo "options nf_conntrack hashsize=131072" > /etc/modprobe.d/nf_conntrack.conf
###脚本向/etc/sysctl.conf写入配置前插入识别字符串INITOSSCRIPTINSEREDIT,脚本执行时如果检测到文件中包含此字符串，跳过此步骤
grep "INITOSSCRIPTINSEREDIT" ${sysconf} > /dev/null 2>&1
if [ $? -ne 0 ]
then
		cp ${sysconf} ${sysconf}.$DATE
		echo "start set sysctl"
		echo "###INITOSSCRIPTINSEREDIT" >> ${sysconf}
		echo "net.ipv4.ip_forward = 1" >> ${sysconf}
		echo "net.ipv4.tcp_tw_reuse = 1" >> ${sysconf}
		echo "net.ipv4.tcp_tw_recycle = 1" >> ${sysconf}
		echo "net.ipv4.tcp_sack = 1" >> ${sysconf}
		echo "net.ipv4.tcp_window_scaling = 1" >> ${sysconf}
		echo "net.ipv4.tcp_rmem = 4096 87380 4194304" >> ${sysconf}
		echo "net.ipv4.tcp_wmem = 4096 16384 4194304" >> ${sysconf}
		echo "fs.file-max=1000000" >> ${sysconf}
		echo "net.ipv4.tcp_max_tw_buckets = 6000" >> ${sysconf}
		echo "net.ipv4.tcp_sack = 1" >> ${sysconf}
		echo "net.ipv4.tcp_window_scaling = 1" >> ${sysconf}
		echo "net.ipv4.tcp_rmem = 4096 87380 4194304" >> ${sysconf}
		echo "net.ipv4.tcp_wmem = 4096 16384 4194304" >> ${sysconf}
		echo "net.ipv4.tcp_max_syn_backlog = 16384" >> ${sysconf}
		echo "net.core.netdev_max_backlog = 32768" >> ${sysconf}
		echo "net.core.somaxconn = 32768" >> ${sysconf}
		echo "net.core.wmem_default = 8388608" >> ${sysconf}
		echo "net.core.rmem_default = 8388608" >> ${sysconf}
		echo "net.core.rmem_max = 16777216" >> ${sysconf}
		echo "net.core.wmem_max = 16777216" >> ${sysconf}
		echo "net.ipv4.tcp_timestamps = 1" >> ${sysconf}
		echo "net.ipv4.tcp_fin_timeout = 20" >> ${sysconf}
		echo "net.ipv4.tcp_synack_retries = 2" >> ${sysconf}
		echo "net.ipv4.tcp_syn_retries = 2" >> ${sysconf}
		echo "net.ipv4.tcp_syncookies = 1" >> ${sysconf}
		echo "net.ipv4.tcp_tw_reuse = 1" >> ${sysconf}
		echo "net.ipv4.tcp_mem = 94500000 915000000 927000000" >> ${sysconf}
		echo "net.ipv4.tcp_max_orphans = 3276800" >> ${sysconf}
		echo "net.ipv4.ip_local_port_range = 1024 65000" >> ${sysconf}
		echo "net.nf_conntrack_max = 6553500" >> ${sysconf}
		echo "net.netfilter.nf_conntrack_max = 6553500" >> ${sysconf}
		echo "net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60" >> ${sysconf}
		echo "net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120" >> ${sysconf}
		echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120" >> ${sysconf}
		echo "net.netfilter.nf_conntrack_tcp_timeout_established = 3600" >> ${sysconf}

        /usr/sbin/sysctl -p
else
        echo "sysctl has configured,skip..."
fi
echo "==========================================================="
sleep 2
}

function Install_php (){
echo "========================install PHP========================"
yum -y install net-tools wget git
yum -y install libxml2 libxml2-devel bzip2 bzip2-devel libcurl libcurl-devel libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel gmp gmp-devel libmcrypt libmcrypt-devel readline readline-devel libxslt libxslt-devel zlib zlib-devel glibc glibc-devel glib2 glib2-devel ncurses curl gdbm-devel db4-devel libXpm-devel libX11-devel gd-devel gmp-devel expat-devel xmlrpc-c xmlrpc-c-devel libicu-devel libmcrypt-devel libmemcached-devel gcc-c++ openldap openldap-devel autoconf >/dev/null
\cp -frp /usr/lib64/libldap* /usr/lib/
wget -P ${FILE_DIR}/ ftp://${ftp}/libzip-last-1.1.3-1.el7.remi.x86_64.rpm --ftp-user=${ftp_user} --ftp-password=${ftp_pass} >/dev/null
wget -P ${FILE_DIR}/ ftp://${ftp}/libzip-last-devel-1.1.3-1.el7.remi.x86_64.rpm --ftp-user=${ftp_user} --ftp-password=${ftp_pass} >/dev/null
rpm -ivh ${FILE_DIR}/libzip-last-1.1.3-1.el7.remi.x86_64.rpm
rpm -ivh ${FILE_DIR}/libzip-last-devel-1.1.3-1.el7.remi.x86_64.rpm
if [ ! -d ${FILE_DIR} ];then mkdir -p ${FILE_DIR};fi
#Install Package
id ${USER}
if [ $? -ne 0 ];then
	useradd -M -s /sbin/nologin ${USER}
fi

wget -P ${FILE_DIR}/ --no-check-certificate https://www.openssl.org/source/old/1.1.1/openssl-1.1.1k.tar.gz
tar zxf ${FILE_DIR}/openssl-1.1.1k.tar.gz -C /data/ && cd /data/openssl-1.1.1k
./config >/dev/null
make >/dev/null && make install >/dev/null
wget -P ${FILE_DIR}/ ftp://${ftp}/${PHP_FILE} --ftp-user=${ftp_user} --ftp-password=${ftp_pass}  >/dev/null && tar xf ${FILE_DIR}/${PHP_FILE} -C ${INSTALL_DIR}/
cat >>/etc/ld.so.conf <<EOF
/usr/local/lib64
/usr/local/lib
/usr/lib
/usr/lib64
EOF
ldconfig -v

echo "========================Config PHP========================"
sed -i '/max_execution_time/s/120/600/g' ${PHP_PREFIX}/etc/php.ini
sed -i '/upload_max_filesize/s/2/50/g' ${PHP_PREFIX}/etc/php.ini
cat >${PHP_PREFIX}/etc/php-fpm.conf <<EOF
;;;;;;;;;;;;;;;;;;;;;
; FPM Configuration ;
;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;
; Global Options ;
;;;;;;;;;;;;;;;;;;

[global]
pid = run/php-fpm.pid
error_log = log/php-fpm.log
log_level = warning

emergency_restart_threshold = 30
emergency_restart_interval = 60s
process_control_timeout = 5s
daemonize = yes

;;;;;;;;;;;;;;;;;;;;
; Pool Definitions ;
;;;;;;;;;;;;;;;;;;;;

[www]
listen = 127.0.0.1:9000 
listen.backlog = -1
listen.allowed_clients = 127.0.0.1
listen.owner = www
listen.group = www
listen.mode = 0666
user = www
group = www

pm = dynamic
pm.max_children = 500
pm.start_servers = 70
pm.min_spare_servers = 50
pm.max_spare_servers = 80
pm.max_requests = 2048
pm.process_idle_timeout = 10s
request_terminate_timeout =3600
request_slowlog_timeout = 0

pm.status_path = /php-fpm_status
slowlog = var/log/slow.log
rlimit_files = 51200
rlimit_core = 0

catch_workers_output = yes
;env[HOSTNAME] = api1-hk-54
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
EOF
cat >/usr/lib/systemd/system/php-fpm.service <<EOF
[Unit]
Description=The PHP FastCGI Process Manager
After=network.target

[Service]
Type=simple
PIDFile=${PHP_PREFIX}/var/run/php-fpm.pid
ExecStart=${PHP_PREFIX}/sbin/php-fpm --nodaemonize --fpm-config ${PHP_PREFIX}/etc/php-fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl enable php-fpm.service && systemctl start php-fpm.service && sleep 5
if [ `netstat -anpt|grep 9000|wc -l` -eq 0 ];then
	echo "PHP Server 启动失败，正在重新启动"
	systemctl restart php-fpm.service
else
	echo "PHP Server 启动成功"	
fi
sed -i '$a\#set php\n\export PATH=$PATH:'${PHP_PREFIX}'/bin' /etc/profile
#刷新环境变量
source /etc/profile
}
 
function Install_php_redis (){
echo "========================install phpredis========================"
wget -P ${FILE_DIR}/ https://pecl.php.net/get/redis-5.3.3.tgz >/dev/null
tar xf ${FILE_DIR}/redis-5.3.3.tgz -C /data
cd /data/redis-5.3.3/
${PHP_PREFIX}/bin/phpize
./configure --with-php-config=${PHP_PREFIX}/bin/php-config
if [ $? -eq 0 ];then
	make && make install
	action "The PHP_redis Install Sussess..." /bin/true
else
	action "The PHP_redis Install Failed..." /bin/false
	exit 1
fi
sed -i '$a\extension=redis.so' ${PHP_PREFIX}/etc/php.ini
systemctl restart php-fpm
}
function Install_php_psr (){
echo "========================install phpyaf========================"
cd /data/ && git clone https://github.com/jbboehr/php-psr.git
cd /data/php-psr/
${PHP_PREFIX}/bin/phpize
./configure --with-php-config=${PHP_PREFIX}/bin/php-config
if [ $? -eq 0 ];then
	make && make install
	action "The PHP_redis Install Sussess..." /bin/true
else
	action "The PHP_redis Install Failed..." /bin/false
	exit 1
fi
sed -i '$a\extension=psr.so' ${PHP_PREFIX}/etc/php.ini
systemctl restart php-fpm
}

function Install_php_yaf (){
echo "========================install phpyaf========================"
wget -P ${FILE_DIR}/ https://pecl.php.net/get/yaf-3.3.3.tgz >/dev/null
tar xf ${FILE_DIR}/yaf-3.3.3.tgz -C /data
cd /data/yaf-3.3.3/
${PHP_PREFIX}/bin/phpize
./configure --with-php-config=${PHP_PREFIX}/bin/php-config
if [ $? -eq 0 ];then
	make && make install
	action "The PHP_yaf Install Sussess..." /bin/true
else
	action "The PHP_yaf Install Failed..." /bin/false
	exit 1
fi
sed -i '$a\extension=yaf.so' ${PHP_PREFIX}/etc/php.ini
systemctl restart php-fpm
}
function Install_php_imagick () {
echo "========================install phpimagick========================"
yum -y install ImageMagick-devel
wget -P ${FILE_DIR}/ https://pecl.php.net/get/imagick-3.5.0.tgz >/dev/null
tar xf ${FILE_DIR}/imagick-3.5.0.tgz -C /data
cd /data/imagick-3.5.0/
${PHP_PREFIX}/bin/phpize
./configure --with-php-config=${PHP_PREFIX}/bin/php-config
if [ $? -eq 0 ];then
	make && make install
	action "The PHP_imagick Install Sussess..." /bin/true
else
	action "The PHP_imagick Install Failed..." /bin/false
	exit 1
fi
#添加配置
sed -i '$a\extension=imagick.so' ${PHP_PREFIX}/etc/php.ini
systemctl restart php-fpm
}
 
function Install_Nginx (){
echo "========================install Nginx========================"
yum -y install epel-release >/dev/null
yum install -y gcc gcc-c++ zlib zlib-devel jemalloc jemalloc-devel >/dev/null
if [ ! -d /data/openssl-1.1.1k ];then 
	wget -P ${FILE_DIR}/ --no-check-certificate https://www.openssl.org/source/old/1.1.1/openssl-1.1.1k.tar.gz
	tar zxf ${FILE_DIR}/openssl-1.1.1k.tar.gz -C /data/ && cd /data/openssl-1.1.1k
	./config >/dev/null
	make >/dev/null && make install >/dev/null
fi
wget -P ${FILE_DIR}/ --no-check-certificate https://ftp.exim.org/pub/pcre/pcre-8.44.tar.gz >/dev/null
tar xf ${FILE_DIR}/pcre-8.44.tar.gz -C /data/ && cd /data/pcre-8.44
./configure
make && make install
 
if [ `cat /etc/passwd|grep "www"|wc -l` -eq 0 ];then useradd -M www -s /sbin/nologin;fi
wget -P ${FILE_DIR}/ http://nginx.org/download/${Nginx_FILE} >/dev/null
tar xf ${FILE_DIR}/${Nginx_FILE} -C /data/ && cd ${Nginx_FILE_DIR}
./configure --prefix=${Nginx_PREFIX} --user=${USER} --group=${USER} --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_ssl_module --with-http_gzip_static_module --with-http_realip_module --with-http_flv_module --with-http_mp4_module --with-openssl=../openssl-1.1.1k --with-pcre=../pcre-8.44 --with-pcre-jit --with-ld-opt=-ljemalloc
if [ $? -eq 0 ];then
	make && make install
	action "The Nginx Install Sussess..." /bin/true
else
	action "The Nginx Install Failed..." /bin/false
	exit 1
fi
ln -s ${Nginx_PREFIX}/sbin/nginx /usr/sbin/
 
#修改配置文件
cp ${Nginx_PREFIX}/conf/nginx.conf{,.bak}
cat >${Nginx_PREFIX}/conf/nginx.conf <<EOF
user www www;
worker_processes auto;

error_log logs/error_nginx.log crit;
pid /var/run/nginx.pid;
worker_rlimit_nofile 51200;

events {
  use epoll;
  worker_connections 51200;
  multi_accept on;
}

http {
  include mime.types;
  default_type application/octet-stream;
  server_names_hash_bucket_size 128;
  client_header_buffer_size 32k;
  large_client_header_buffers 4 32k;
  client_max_body_size 1024m;
  client_body_buffer_size 10m;
  sendfile on;
  tcp_nopush on;
  keepalive_timeout 120;
  server_tokens off;
  tcp_nodelay on;

  fastcgi_connect_timeout 300;
  fastcgi_send_timeout 300;
  fastcgi_read_timeout 300;
  fastcgi_buffer_size 64k;
  fastcgi_buffers 4 64k;
  fastcgi_busy_buffers_size 128k;
  fastcgi_temp_file_write_size 128k;
  fastcgi_intercept_errors on;

  #Gzip Compression
  gzip on;
  gzip_buffers 16 8k;
  gzip_comp_level 6;
  gzip_http_version 1.1;
  gzip_min_length 256;
  gzip_proxied any;
  gzip_vary on;
  gzip_types
    text/xml application/xml application/atom+xml application/rss+xml application/xhtml+xml image/svg+xml
    text/javascript application/javascript application/x-javascript
    text/x-json application/json application/x-web-app-manifest+json
    text/css text/plain text/x-component
    font/opentype application/x-font-ttf application/vnd.ms-fontobject
    image/x-icon;
  gzip_disable "MSIE [1-6]\.(?!.*SV1)";

  ##Brotli Compression
  #brotli on;
  #brotli_comp_level 6;
  #brotli_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript application/javascript image/svg+xml;

  ##If you have a lot of static files to serve through Nginx then caching of the files' metadata (not the actual files' contents) can save some latency.
  #open_file_cache max=1000 inactive=20s;
  #open_file_cache_valid 30s;
  #open_file_cache_min_uses 2;
  #open_file_cache_errors on;

  log_format json escape=json '{"@timestamp":"$time_iso8601",'
                      '"server_addr":"$server_addr",'
                      '"remote_addr":"$remote_addr",'
                      '"scheme":"$scheme",'
                      '"request_method":"$request_method",'
                      '"request_uri": "$request_uri",'
                      '"request_length": "$request_length",'
                      '"uri": "$uri", '
                      '"request_time":$request_time,'
                      '"body_bytes_sent":$body_bytes_sent,'
                      '"bytes_sent":$bytes_sent,'
                      '"status":"$status",'
                      '"upstream_time":"$upstream_response_time",'
                      '"upstream_host":"$upstream_addr",'
                      '"upstream_status":"$upstream_status",'
                      '"host":"$host",'
                      '"http_referer":"$http_referer",'
                      '"http_user_agent":"$http_user_agent"'
                      '}';

######################## default ############################
  server {
    listen 80;
    server_name _;
    access_log logs/access_nginx.log combined;
    root /data/wwwroot/default;
    index index.html index.htm index.php;
    #error_page 404 /404.html;
    #error_page 502 /502.html;
    location /nginx_status {
      stub_status on;
      access_log off;
      allow 127.0.0.1;
      deny all;
    }
    location ~ [^/]\.php(/|$) {
      #fastcgi_pass remote_php_ip:9000;
      fastcgi_pass unix:/dev/shm/php-cgi.sock;
      fastcgi_index index.php;
      include fastcgi.conf;
    }
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|flv|mp4|ico)$ {
      expires 30d;
      access_log off;
    }
    location ~ .*\.(js|css)?$ {
      expires 7d;
      access_log off;
    }
    location ~ ^/(\.user.ini|\.ht|\.git|\.svn|\.project|LICENSE|README.md) {
      deny all;
    }
  }
########################## vhost #############################
  include vhost/*.conf;
}
EOF
#测试nginx联调php
cat >${Nginx_PREFIX}/html/test.php <<EOF
<?php
phpinfo();
?>
EOF
#开机自启
cat >/usr/lib/systemd/system/nginx.service<<EOF
[Unit]
Description=nginx
After=network.target
  
[Service]
Type=forking
ExecStart=${Nginx_PREFIX}/sbin/nginx
ExecReload=${Nginx_PREFIX}/sbin/nginx -s reload
ExecStop=${Nginx_PREFIX}/sbin/nginx -s quit
PrivateTmp=true
  
[Install]
WantedBy=multi-user.target
EOF
#启动
systemctl enable nginx && systemctl start nginx
if [ $? -eq 0 ];then
	echo "Nginx Server 启动成功"
else
	echo "Nginx Server 启动失败"
fi
}
 
function Install_Mysql (){
echo "========================install Mysql========================"
yum -y install bison bison-devel zlib-devel libcurl-devel libarchive-devel boost-devel gcc gcc-c++ cmake ncurses-devel gnutls-devel libxml2-devel  libevent-devel libaio-devel >/dev/null
wget -P ${FILE_DIR}/ https://downloads.mariadb.com/MariaDB/mariadb-10.5.10/bintar-linux-systemd-x86_64/mariadb-10.5.10-linux-systemd-x86_64.tar.gz
tar xf ${FILE_DIR}/${Mysql_FILE} -C ${INSTALL_DIR} && mv ${INSTALL_DIR}/mariadb-10.5.10-linux-systemd-x86_64 ${Mysql_PREFIX}
cd ${Mysql_PREFIX}/
id ${Mysql_user}
if [ $? -ne 0 ];then
	useradd -M -s /sbin/nologin ${Mysql_user}
fi
chown -R mysql:mysql ${Mysql_PREFIX}
 
#find / -name libssl.so.1.1
#ln -s /usr/local/lib64/libssl.so.1.1  /usr/lib64/libssl.so.1.1
#ln -s /usr/local/lib64/libcrypto.so.1.1  /usr/lib64/libcrypto.so.1.1
cp /etc/my.cnf{,.bak}
cat >/etc/my.cnf <<EOF
[client]
port = 3306
socket = /tmp/mysql.sock
default-character-set = utf8mb4

[mysqld]
port = 3306
socket = /tmp/mysql.sock

basedir = ${Mysql_PREFIX}
datadir = /data/mariadb
pid-file = /data/mariadb/mysql.pid
user = mysql
bind-address = 0.0.0.0
server-id = 1

init-connect = 'SET NAMES utf8mb4'
character-set-server = utf8mb4

skip-name-resolve
#skip-networking
back_log = 300

max_connections = 2573
max_connect_errors = 6000
open_files_limit = 65535
table_open_cache = 1024
max_allowed_packet = 500M
binlog_cache_size = 1M
max_heap_table_size = 8M
tmp_table_size = 128M

read_buffer_size = 2M
read_rnd_buffer_size = 8M
sort_buffer_size = 8M
join_buffer_size = 8M
key_buffer_size = 256M

thread_cache_size = 64

query_cache_type = 1
query_cache_size = 64M
query_cache_limit = 2M

ft_min_word_len = 4

log_bin = mysql-bin
binlog_format = mixed
expire_logs_days = 7

log_error = /data/mariadb/mysql-error.log
slow_query_log = 1
long_query_time = 1
slow_query_log_file = /data/mariadb/mysql-slow.log

performance_schema = 0

#lower_case_table_names = 1

skip-external-locking

default_storage_engine = InnoDB
innodb_file_per_table = 1
innodb_open_files = 500
innodb_buffer_pool_size = 1024M
innodb_write_io_threads = 4
innodb_read_io_threads = 4
innodb_purge_threads = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 2M
innodb_log_file_size = 32M
innodb_max_dirty_pages_pct = 90
innodb_lock_wait_timeout = 120

bulk_insert_buffer_size = 8M
myisam_sort_buffer_size = 64M
myisam_max_sort_file_size = 10G
myisam_repair_threads = 1

interactive_timeout = 28800
wait_timeout = 28800

[mysqldump]
quick
max_allowed_packet = 500M

[myisamchk]
key_buffer_size = 256M
sort_buffer_size = 8M
read_buffer = 4M
write_buffer = 4M
EOF
mkdir /data/mariadb/
chown -R mysql. /data/mariadb/
./scripts/mysql_install_db --basedir=${Mysql_PREFIX} --datadir=/data/mariadb/ --user=mysql
cp support-files/mysql.server /etc/init.d/mysqld
chkconfig --list mysqld
chkconfig --add mysqld
/sbin/chkconfig mysqld on
systemctl daemon-reload
systemctl start mysqld
if [ $? -eq 0 ];then
	echo "Mysql Server 启动成功"
else
	echo "Mysql Server 启动失败"
fi
sed -i '$a\#set mysql\n\export PATH='${Mysql_PREFIX}'/bin:$PATH' /etc/profile && source /etc/profile
}

function menu() {
cat << eof
----------------------------------------------
|*******please enter your choice:[1-5]*******|
*   `echo -e "\033[34m 1)系统一键初始化\033[0m"`
*   `echo -e "\033[34m 2)自定义初始化\033[0m"`
*   `echo -e "\033[34m 3)服务安装管理\033[0m"`
*   `echo -e "\033[34m 4)jumpserver添加登录用户\033[0m"`
*   `echo -e "\033[34m 5)退出\033[0m"`
eof
read -p "`echo -e "\033[36m please input your optios[1-5]:\033[0m"` " num
case $num in
	1)
	install_softcmd
	selinuxset
	modify_ssh
	historyset
	timezonesset
	limitset
	#kernelset
	menu
	;;
	2)
	init_menu
	menu
	;;
	3)
	service_menu
	menu
	;;
	4)
	jumpserver_user
	menu
	;;
	5)
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
|*******please enter your choice:[1-8]*******|
*   `echo -e "\033[34m 1)常用命令安装\033[0m"`
*   `echo -e "\033[34m 2)禁用selinux\033[0m"`
*   `echo -e "\033[34m 3)调整sshd服务参数\033[0m"`
*   `echo -e "\033[34m 4)历史记录优化\033[0m"`
*   `echo -e "\033[34m 5)系统时区调整\033[0m"`
*   `echo -e "\033[34m 6)设置文件描述符\033[0m"`
*   `echo -e "\033[34m 7)内核参数优化\033[0m"`
*   `echo -e "\033[34m 8)返回主菜单\033[0m"`
eof

read -p "`echo -e "\033[36m please input your optios[1-8]:\033[0m"` " num
case $num in
	1)
	install_softcmd
	init_menu
	;;
	2)
	selinuxset
	init_menu
	;;
	3)
	modify_ssh
	init_menu
	;;
	4)
	historyset
	init_menu
	;;
	5)
	timezonesset
	init_menu
	;;
	6)
	limitset
	init_menu
	;;
	7)
	kernelset
	init_menu
	;;
	8)
	menu
	;;
	*)
	echo -e "\033[31mUsage: Please input Specify number\033[0m"
	exit 1
esac
}
function service_menu () {
cat << eof
----------------------------------------------
|*******please enter your choice:[1-7]*******|
*   `echo -e "\033[34m 1)PHP install\033[0m"`
*   `echo -e "\033[34m 2)php_expand\033[0m"`
*   `echo -e "\033[34m 3)Nginx install\033[0m"`
*   `echo -e "\033[34m 4)Mysql install\033[0m"`
*   `echo -e "\033[34m 5)LNMP install\033[0m"`
*   `echo -e "\033[34m 6)删除安装所下载的文件\033[0m"`
*   `echo -e "\033[34m 7)返回主菜单\033[0m"`
eof

read -p "`echo -e "\033[36m please input your optios[1-7]:\033[0m"` " num
case $num in
	1)
	install_php
	Install_php_psr
	service_menu
	;;
	2)
	php_expand_menu
	service_menu
	;;
	3)
	Install_Nginx
	service_menu
	;;
	4)
	Install_Mysql
	service_menu
	;;
	5)
	Install_php
	Install_php_psr
	Install_Nginx
	Install_Mysql
	service_menu
	;;
	6)
	rm -rf /data/*
	;;
	7)
	menu
	;;
	*)
	echo -e "\033[31mUsage: Please input Specify number\033[0m"
	exit 1
esac
}
function php_expand_menu () {
cat << eof
----------------------------------------------
|*******please enter your choice:[1-5]*******|
*   `echo -e "\033[34m 1)php_redis\033[0m"`
*   `echo -e "\033[34m 2)php_imagick\033[0m"`
*   `echo -e "\033[34m 3)php_yaf\033[0m"`
*   `echo -e "\033[34m 4)php_psr\033[0m"`
*   `echo -e "\033[34m 5)返回主菜单\033[0m"`
eof

read -p "`echo -e "\033[36m please input your optios[1-5]:\033[0m"` " num
case $num in
	1)
	Install_php_redis
	php_expand_menu
	;;
	2)
	Install_php_yaf
	php_expand_menu
	;;
	3)
	Install_php_imagick
	php_expand_menu
	;;
	4)
	Install_php_psr
	php_expand_menu
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
