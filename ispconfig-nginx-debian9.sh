#!/bin/bash

# Debemos ser root
if [[ $EUID -ne 0 ]]; then
echo "You must run the script as root or using sudo"
   exit 1
fi

apt-get update && apt-get install -y lsb-release

OSRELEASE=$(lsb_release -si | awk '{print tolower($0)}')

## Reconfigure Dash
echo "dash dash/sh boolean false" | debconf-set-selections
dpkg-reconfigure -f noninteractive dash > /dev/null 2>&1

MY_IP=$(ip a s|sed -ne '/127.0.0.1/!{s/^[ \t]*inet[ \t]*\([0-9.]\+\)\/.*$/\1/p}' | tr '\n' ' ')

echo -e "Set Server Name Ex: mail.dominio.com []: \c "
read  SERVER_FQDN

echo -e "Introduce la IP Ex: $MY_IP []: \c "
read  SERVER_IP

echo "" >>/etc/hosts
echo "$SERVER_IP  $SERVER_FQDN" >>/etc/hosts
hostnamectl set-hostname $SERVER_FQDN
echo "$SERVER_FQDN" > /proc/sys/kernel/hostname

# Configuración repositorios
mv /etc/apt/sources.list /etc/apt/sources.list_$$.bkp
echo "deb http://ftp.es.debian.org/debian/ stretch main contrib non-free
deb-src http://ftp.es.debian.org/debian/ stretch main contrib non-free
deb http://security.debian.org/ stretch/updates main contrib non-free
deb-src http://security.debian.org/ stretch/updates main contrib non-free
deb http://ftp.es.debian.org/debian/ stretch-updates main contrib non-free
deb-src http://ftp.es.debian.org/debian/ stretch-updates main contrib non-free
deb http://ftp.es.debian.org/debian/ stretch-backports main contrib non-free
deb-src http://ftp.es.debian.org/debian/ stretch-backports main contrib non-free" > /etc/apt/sources.list

# Actualziación sistema
apt-get update && apt-get upgrade -y

# Instalación herramientas generales
apt-get -y install ssh openssh-server ntp binutils sudo ntpdate curl dirmngr wget nano vim git htop dialog dnsutils geoip-database fail2ban ufw

# Instalar MYSQL/MARIDB
apt-get -y install mariadb-client mariadb-server

sed -i 's|bind-address|#bind-address|' /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i 's|# this is only for embedded server|sql_mode=NO_ENGINE_SUBSTITUTION|' /etc/mysql/mariadb.conf.d/50-server.cnf
echo "update mysql.user set plugin = 'mysql_native_password' where user='root';" | mysql -u root
echo "mysql soft nofile 65535
mysql hard nofile 65535" >> /etc/security/limits.conf
mkdir -p /etc/systemd/system/mysql.service.d/
echo "[Service]
LimitNOFILE=infinity" > /etc/systemd/system/mysql.service.d/limits.conf
systemctl daemon-reload
mysql_secure_installation
service mysql restart

# Instalar NGINX y PHP
apt-get -y install daemon nginx nginx-extras unzip zip
apt-get -y install php php-common php-gd php-mysql php-imap php-cli php-cgi 
apt-get -y install php-pear php-mcrypt php-imagick php-mbstring php-ldap php7.0-opcache php-apcu
apt-get -y install php-curl php-intl php-memcache php-memcached php-pspell php7.0-zip php7.0-soap
apt-get -y install php-recode php-sqlite3 php-tidy php-xmlrpc php-xsl php-xml php-fpm phpmyadmin memcached php-gettext
apt-get -y install mcrypt imagemagick ssl-cert certbot python-certbot-nginx

# Optimizar NGINX
mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.original
cat >> /etc/nginx/nginx.conf << N0deNet
user www-data;
worker_processes auto;
pid /run/nginx.pid;
worker_rlimit_nofile 30000;

# Carga de Módulos
load_module "modules/ngx_http_geoip_module.so";
load_module "modules/ngx_http_uploadprogress_module.so";

events {
        use epoll;
        worker_connections 40960;
        multi_accept on;
}

http {
        ##
        # CloudFlare y Proxys
        ##
        
        set_real_ip_from 103.21.244.0/22;
        set_real_ip_from 103.22.200.0/22;
        set_real_ip_from 103.31.4.0/22;
        set_real_ip_from 104.16.0.0/12;
        set_real_ip_from 108.162.192.0/18;
        set_real_ip_from 131.0.72.0/22;
        set_real_ip_from 141.101.64.0/18;
        set_real_ip_from 162.158.0.0/15;
        set_real_ip_from 172.64.0.0/13;
        set_real_ip_from 173.245.48.0/20;
        set_real_ip_from 188.114.96.0/20;
        set_real_ip_from 190.93.240.0/20;
        set_real_ip_from 197.234.240.0/22;
        set_real_ip_from 198.41.128.0/17;
        set_real_ip_from 199.27.128.0/21;
        set_real_ip_from 2400:cb00::/32;
        set_real_ip_from 2606:4700::/32;
        set_real_ip_from 2803:f800::/32;
        set_real_ip_from 2405:b500::/32;
        set_real_ip_from 2405:8100::/32;
        set_real_ip_from 2c0f:f248::/32;
        set_real_ip_from 2a06:98c0::/29;
        set_real_ip_from 127.0.0.1;
        real_ip_header CF-Connecting-IP;
        
        ##
        # Básico
        ##
        
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 2;
        types_hash_max_size 2048;
        client_body_buffer_size  1m;
        client_max_body_size 32m;
        client_header_buffer_size 3m;
        client_body_timeout   3m;
        client_header_timeout 3m;
        large_client_header_buffers 4 256k;
        open_file_cache          max=5000  inactive=20s;
        open_file_cache_valid    30s;
        open_file_cache_min_uses 2;
        open_file_cache_errors   on;
        
        
        ##
        # Headers
        ##
        
        server_tokens off;
        ssl_stapling on;
        ssl_stapling_verify on;
        resolver 8.8.4.4 8.8.8.8 valid=300s;
        resolver_timeout 5s;
        add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload";
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Content-Security-Policy "default-src https: data: 'unsafe-inline' 'unsafe-eval'" always;
        add_header X-Xss-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        
        ##
        # Logs
        ##
        
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        
        ##
        # Mitigación DOS
        ##
        
        limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;
        limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=5r/s;
        server {
            listen 80;
            limit_conn conn_limit_per_ip 10;
            limit_req zone=req_limit_per_ip burst=10 nodelay;
        }
        
        
        ##
        # Performance
        ##
        
        aio threads;
        fastcgi_cache_path /var/cache/nginx levels=1:2 keys_zone=microcache:10m max_size=1000m inactive=60m;
        fastcgi_cache_key \$scheme\$request_method\$host\$request_uri;
        fastcgi_cache_lock on;
        fastcgi_cache_use_stale error timeout invalid_header updating http_500;
        fastcgi_cache_valid 5m;
        fastcgi_ignore_headers Cache-Control Expires Set-Cookie;
        
        ##
        # PHP
        ##
        
        fastcgi_buffers 256 32k;
        fastcgi_buffer_size 256k;
        fastcgi_connect_timeout 4s;
        fastcgi_send_timeout 120s;
        fastcgi_read_timeout 120s;
        fastcgi_busy_buffers_size 512k;
        fastcgi_temp_file_write_size 512K;
        reset_timedout_connection on;
        
        ##
        # Extra
        ##
       
        upload_progress upload 1m;

        ##
        # Gzip
        ##
        
        gzip on;
        gzip_disable "msie6";
        gzip_static on;
        gzip_vary on;
        gzip_proxied any;
        gzip_comp_level 6;
        gzip_buffers 16 8k;
        gzip_http_version 1.1;
        gzip_types text/plain application/javascript application/x-javascript text/javascript text/xml text/css application/atom+xml application/json application/rss+xml application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/svg+xml image/x-icon image/bmp image/png image/gif image/jpeg image/jpg text/x-component;
        
        ##
        # SSL - TLS
        ##
        
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_session_tickets off;
        ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305-D:ECDHE-RSA-CHACHA20-POLY1305-D:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA384';
        ssl_prefer_server_ciphers on;
        
        ##
        # GeoIP
        ##
        
        geoip_country /usr/share/GeoIP/GeoIP.dat;
        map \$geoip_country_code \$allowed_country {
                default yes;
                CN no;
                Ru no;
                BR no;
            }

        
        ##
        # Ficheros extra de configuración
        ##
        
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}
N0deNet

# Optimizar PHP
sed -i 's|;cgi.fix_pathinfo=1|cgi.fix_pathinfo=0|' /etc/php/7.0/fpm/php.ini
sed -i 's|upload_max_filesize = 2M|upload_max_filesize = 2048M|' /etc/php/7.0/fpm/php.ini
sed -i 's|post_max_size = 8M|post_max_size = 64M|' /etc/php/7.0/fpm/php.ini
sed -i 's|error_reporting = E_ALL & ~E_DEPRECATED|error_reporting =  E_ERROR|' /etc/php/7.0/fpm/php.ini
sed -i 's|short_open_tag = Off|short_open_tag = On|' /etc/php/7.0/fpm/php.ini
sed -i "s|;date.timezone =|date.timezone = 'Europe\/Madrid'|" /etc/php/7.0/fpm/php.ini
sed -i "s|; max_input_vars = 1000|max_input_vars = 1000|" /etc/php/7.0/fpm/php.ini
sed -i "s|;emergency_restart_threshold = 0|emergency_restart_threshold = 10|" /etc/php/7.0/fpm/php-fpm.conf 
sed -i "s|;emergency_restart_interval = 0|emergency_restart_interval = 1m|" /etc/php/7.0/fpm/php-fpm.conf 
sed -i "s|;process_control_timeout = 0|process_control_timeout = 5|" /etc/php/7.0/fpm/php-fpm.conf 
service php7.0-fpm reload

# Instalar Jailkit
apt-get -y install build-essential autoconf automake libtool flex bison debhelper binutils
cd /tmp
wget http://olivier.sessink.nl/jailkit/jailkit-2.19.tar.gz
tar xvfz jailkit-2.19.tar.gz
cd jailkit-2.19
echo 5 > debian/compat
./debian/rules binary
cd ..
dpkg -i jailkit_2.19-1_*.deb
rm -rf jailkit-2.19*

# Instalar FTP y quotas
apt-get -y install pure-ftpd-common pure-ftpd-mysql quota quotatool

sed -i 's|VIRTUALCHROOT=false|VIRTUALCHROOT=true|' /etc/default/pure-ftpd-common
echo 1 > /etc/pure-ftpd/conf/TLS
mkdir -p /etc/ssl/private/

openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem
chmod 600 /etc/ssl/private/pure-ftpd.pem && service pure-ftpd-mysql restart

## Instalar panel
cd /tmp
get_isp=https://www.ispconfig.org/downloads/ISPConfig-3-stable.tar.gz
wget -c ${get_isp}
tar xvfz $(basename ${get_isp})
cd ispconfig3_install/install && php -q install.php