#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}警告${plain}] 本脚本必须以root权限运行!" && exit 1

cur_dir=$( pwd )
software=(Shadowsocks-Python ShadowsocksR Shadowsocks-Go Shadowsocks-libev)

libsodium_file="libsodium-stable"
libsodium_url="https://download.libsodium.org/libsodium/releases/LATEST.tar.gz"

mbedtls_file="mbedtls-2.16.3"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.16.3-gpl.tgz"


shadowsocks_python_file="shadowsocks-master"
shadowsocks_python_url="https://github.com/shadowsocks/shadowsocks/archive/master.zip"
shadowsocks_python_init="/etc/init.d/shadowsocks-python"
shadowsocks_python_config="/etc/shadowsocks-python/config.json"
shadowsocks_python_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks"
shadowsocks_python_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-debian"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
shadowsocks_r_init="/etc/init.d/shadowsocks-r"
shadowsocks_r_config="/etc/shadowsocks-r/config.json"
shadowsocks_r_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR"
shadowsocks_r_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian"

shadowsocks_go_file_64="shadowsocks-server-linux64-1.2.2"
shadowsocks_go_url_64="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux64-1.2.2.gz"
shadowsocks_go_file_32="shadowsocks-server-linux32-1.2.2"
shadowsocks_go_url_32="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux32-1.2.2.gz"
shadowsocks_go_init="/etc/init.d/shadowsocks-go"
shadowsocks_go_config="/etc/shadowsocks-go/config.json"
shadowsocks_go_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go"
shadowsocks_go_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go-debian"

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev"
shadowsocks_libev_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev-debian"

# Stream Ciphers
common_ciphers=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
xchacha20-ietf-poly1305
chacha20-ietf-poly1305
chacha20-ietf
chacha20
salsa20
rc4-md5
)
go_ciphers=(
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
salsa20
rc4-md5
)
r_ciphers=(
none
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-cfb8
aes-192-cfb8
aes-128-cfb8
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
salsa20
xchacha20
xsalsa20
rc4-md5
)
# Reference URL:
# https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
# Protocol
protocols=(
origin
verify_deflate
auth_sha1_v4
auth_sha1_v4_compatible
auth_aes128_md5
auth_aes128_sha1
auth_chain_a
auth_chain_b
auth_chain_c
auth_chain_d
auth_chain_e
auth_chain_f
)
# obfs
obfs=(
plain
http_simple
http_simple_compatible
http_post
http_post_compatible
tls1.2_ticket_auth
tls1.2_ticket_auth_compatible
tls1.2_ticket_fastauth
tls1.2_ticket_fastauth_compatible
)
# libev obfuscating
obfs_libev=(http tls)
# initialization parameter
libev_obfs=""

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version(){
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

check_kernel_headers(){
    if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
            return 0
        else
            return 1
        fi
    elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
    return 1
}

getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

autoconf_version(){
    if [ ! "$(command -v autoconf)" ]; then
        echo -e "[${green}Info${plain}] 开始编译安装包"
        if check_sys packageManager yum; then
            yum install -y autoconf > /dev/null 2>&1 || echo -e "[${red}错误:${plain}]  安装包编译失败"
        elif check_sys packageManager apt; then
            apt-get -y update > /dev/null 2>&1
            apt-get -y install autoconf > /dev/null 2>&1 || echo -e "[${red}错误:${plain}] 安装包编译失败"
        fi
    fi
    local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
    if version_ge ${autoconf_ver} 2.67; then
        return 0
    else
        return 1
    fi
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver(){
    libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${libev_ver} ] && echo -e "[${red}错误${plain}] 获取shadowsocks-libev最新版本失败" && exit 1
}

get_opsy(){
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

is_64bit(){
    if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
        return 0
    else
        return 1
    fi
}

debianversion(){
    if check_sys sysRelease debian;then
        local version=$( get_opsy )
        local code=${1}
        local main_ver=$( echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ];then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

download(){
    local filename=$(basename $1)
    if [ -f ${1} ]; then
        echo "${filename} [found]"
    else
        echo "${filename} 未找到，现在下载"
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [ $? -ne 0 ]; then
            echo -e "[${red}错误${plain}]  ${filename} 下载失败"
            exit 1
        fi
    fi
}

download_files(){
    cd ${cur_dir}

    if   [ "${selected}" == "1" ]; then
        download "${shadowsocks_python_file}.zip" "${shadowsocks_python_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_python_init}" "${shadowsocks_python_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_python_init}" "${shadowsocks_python_debian}"
        fi
    elif [ "${selected}" == "2" ]; then
        download "${shadowsocks_r_file}.tar.gz" "${shadowsocks_r_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_debian}"
        fi
    elif [ "${selected}" == "3" ]; then
        if is_64bit; then
            download "${shadowsocks_go_file_64}.gz" "${shadowsocks_go_url_64}"
        else
            download "${shadowsocks_go_file_32}.gz" "${shadowsocks_go_url_32}"
        fi
        if check_sys packageManager yum; then
            download "${shadowsocks_go_init}" "${shadowsocks_go_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_go_init}" "${shadowsocks_go_debian}"
        fi
    elif [ "${selected}" == "4" ]; then
        get_libev_ver
        shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

        download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
        fi
    fi

}

get_char(){
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

error_detect_depends(){
    local command=$1
    local depend=`echo "${command}" | awk '{print $4}'`
    echo -e "[${green}Info${plain}] 开始安装 ${depend}"
    ${command} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "[${red}错误${plain}] 安装失败 ${red}${depend}${plain}"
        exit 1
    fi
}

config_firewall(){
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] 端口 ${green}${shadowsocksport}${plain} 已经开启."
            fi
        else
            echo -e "[${yellow}警告${plain}] iptables并未运行或安装, 请手动开启端口 ${shadowsocksport} "
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            default_zone=$(firewall-cmd --get-default-zone)
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}警告${plain}] 并未运行或安装, 请手动开启端口 ${shadowsocksport}"
        fi
    fi
}

config_shadowsocks(){

if check_kernel_version && check_kernel_headers; then
    fast_open="true"
else
    fast_open="false"
fi

if   [ "${selected}" == "1" ]; then
    if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_python_config})
    fi
    cat > ${shadowsocks_python_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
elif [ "${selected}" == "2" ]; then
    if [ ! -d "$(dirname ${shadowsocks_r_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_r_config})
    fi
    cat > ${shadowsocks_r_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":120,
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":${fast_open},
    "workers":1
}
EOF
elif [ "${selected}" == "3" ]; then
    if [ ! -d "$(dirname ${shadowsocks_go_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_go_config})
    fi
    cat > ${shadowsocks_go_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "timeout":300
}
EOF
elif [ "${selected}" == "4" ]; then
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_libev_config})
    fi

    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${shadowsocklibev_obfs}"
}
EOF
    else
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
    fi

fi
}

install_dependencies(){
    if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] 正在检查EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release > /dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] EPEL repository安装失败." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel > /dev/null 2>&1
        echo -e "[${green}Info${plain}] EPEL repository检查完成"

        yum_depends=(
            unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
            autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
            libev-devel c-ares-devel git qrencode
        )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend}"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            gettext build-essential unzip gzip python python-dev python-setuptools curl openssl libssl-dev
            autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
        )

        apt-get -y update
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt-get -y install ${depend}"
        done
    fi
}

install_check(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_select(){
    if ! install_check; then
        echo -e "[${red}错误${plain}] 您的系统不支持本程序!"
        echo "请使用CentOS 6+/Debian 7+/Ubuntu 12+ 重试"
        exit 1
    fi

    clear
    while true
    do
    echo "|"
    echo "|"
    echo " ==================================================================="
    echo "             Shadowsocks安装程序（秋水逸冰四合一汉化安装指引)          "
    echo " ==================================================================="
    echo "|"
    echo "|"
    echo "请选择您要安装的版本:"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p " 请输入一个数字 (Default ${software[0]}):" selected
    [ -z "${selected}" ] && selected="1"
    case "${selected}" in
        1|2|3|4)
        echo
        echo "您的选择 = ${software[${selected}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}错误${plain}] 请输入一个数字 [1-4]"
        ;;
    esac
    done
}

install_prepare_password(){
    echo "请为 ${software[${selected}-1]}设置密码"
    read -p "(默认密码: 1345678):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="12345678"
    echo
    echo "密码 = ${shadowsockspwd}"
    echo
}

install_prepare_port() {
    while true
    do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "请为 ${software[${selected}-1]} 选择一个端口[1-65535]"
    read -p "(默认端口: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo
            echo "端口 = ${shadowsocksport}"
            echo
            break
        fi
    fi
    echo -e "[${red}Error${plain}] 请输入正确的数字 [1-65535]"
    done
}

install_prepare_cipher(){
    while true
    do
    echo -e "请为${software[${selected}-1]}选择加密方式:"

    if   [[ "${selected}" == "1" || "${selected}" == "4" ]]; then
        for ((i=1;i<=${#common_ciphers[@]};i++ )); do
            hint="${common_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "选择加密方式(默认: ${common_ciphers[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] 请选择一个数字"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] 请输入一个 1 到 ${#common_ciphers[@]}的数字"
            continue
        fi
        shadowsockscipher=${common_ciphers[$pick-1]}
    elif [ "${selected}" == "2" ]; then
        for ((i=1;i<=${#r_ciphers[@]};i++ )); do
            hint="${r_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "选择加密方式(默认: ${r_ciphers[1]}):" pick
        [ -z "$pick" ] && pick=2
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] 请输入一个数字"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#r_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] 请输入一个 1 到 ${#r_ciphers[@]}的数字"
            continue
        fi
        shadowsockscipher=${r_ciphers[$pick-1]}
    elif [ "${selected}" == "3" ]; then
        for ((i=1;i<=${#go_ciphers[@]};i++ )); do
            hint="${go_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "选择加密方式(默认: ${go_ciphers[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] 请输入一个数字"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#go_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] 输入一个 1 到 ${#go_ciphers[@]}的数字"
            continue
        fi
        shadowsockscipher=${go_ciphers[$pick-1]}
    fi

    echo
    echo "加密方式 = ${shadowsockscipher}"
    echo
    break
    done
}

install_prepare_protocol(){
    while true
    do
    echo -e "请为 ${software[${selected}-1]}选择网络传输协议:"
    for ((i=1;i<=${#protocols[@]};i++ )); do
        hint="${protocols[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "请选择网络传输协议(默认: ${protocols[0]}):" protocol
    [ -z "$protocol" ] && protocol=1
    expr ${protocol} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] 请输入一个数字"
        continue
    fi
    if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
        echo -e "[${red}Error${plain}] 输入一个 1 到 ${#protocols[@]}的数字"
        continue
    fi
    shadowsockprotocol=${protocols[$protocol-1]}
    echo
    echo "protocol = ${shadowsockprotocol}"
    echo
    break
    done
}

install_prepare_obfs(){
    while true
    do
    echo -e "请为 ${software[${selected}-1]}选择obfs方式:"
    for ((i=1;i<=${#obfs[@]};i++ )); do
        hint="${obfs[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "选择obfs方式t(默认: ${obfs[0]}):" r_obfs
    [ -z "$r_obfs" ] && r_obfs=1
    expr ${r_obfs} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] 请输入一个数字"
        continue
    fi
    if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
        echo -e "[${red}Error${plain}] 输入一个 1 到 ${#obfs[@]}的数字"
        continue
    fi
    shadowsockobfs=${obfs[$r_obfs-1]}
    echo
    echo "obfs = ${shadowsockobfs}"
    echo
    break
    done
}

install_prepare_libev_obfs(){
    if autoconf_version || centosversion 6; then
        while true
        do
        echo -e "是否需要为${software[${selected}-1]}simple-obfs? [y/n]"
        read -p "(default: n):" libev_obfs
        [ -z "$libev_obfs" ] && libev_obfs=n
        case "${libev_obfs}" in
            y|Y|n|N)
            echo
            echo "You choose = ${libev_obfs}"
            echo
            break
            ;;
            *)
            echo -e "[${red}Error${plain}] 仅能输入 [y/n]"
            ;;
        esac
        done

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
            while true
            do
            echo -e "请为obfs 选择 simple-obfs:"
            for ((i=1;i<=${#obfs_libev[@]};i++ )); do
                hint="${obfs_libev[$i-1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "选择obfs方式(默认: ${obfs_libev[0]}):" r_libev_obfs
            [ -z "$r_libev_obfs" ] && r_libev_obfs=1
            expr ${r_libev_obfs} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}错误${plain}] 请输入一个数字"
                continue
            fi
            if [[ "$r_libev_obfs" -lt 1 || "$r_libev_obfs" -gt ${#obfs_libev[@]} ]]; then
                echo -e "[${red}错误${plain}] 输入一个 1 到 ${#obfs_libev[@]}的数字"
                continue
            fi
            shadowsocklibev_obfs=${obfs_libev[$r_libev_obfs-1]}
            echo
            echo "obfs = ${shadowsocklibev_obfs}"
            echo
            break
            done
        fi
    else
        echo -e "[${green}Info${plain}] autoconf 版本低于 2.67, simple-obfs 在 ${software[${selected}-1]} 下的安装已跳过"
    fi
}

install_prepare(){

    if  [[ "${selected}" == "1" || "${selected}" == "3" || "${selected}" == "4" ]]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        if [ "${selected}" == "4" ]; then
            install_prepare_libev_obfs
        fi
    elif [ "${selected}" == "2" ]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        install_prepare_protocol
        install_prepare_obfs
    fi

    echo
    echo "按下任意键开始或按下 Ctrl+C 取消"
    char=`get_char`

}

install_libsodium(){
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${libsodium_file} 安装完成"
    fi
}

install_mbedtls(){
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtls_file} 安装失败"
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${mbedtls_file} 安装完成"
    fi
}

install_shadowsocks_python(){
    cd ${cur_dir}
    unzip -q ${shadowsocks_python_file}.zip
    if [ $? -ne 0 ];then
        echo -e "[${red}Error${plain}] unzip ${shadowsocks_python_file}.zip 失败, 请检查 unzip 命令"
        install_cleanup
        exit 1
    fi

    cd ${shadowsocks_python_file}
    python setup.py install --record /usr/local/shadowsocks_python.log

    if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
        chmod +x ${shadowsocks_python_init}
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}错误${plain}] ${software[0]} 安装失败"
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_r(){
    cd ${cur_dir}
    tar zxf ${shadowsocks_r_file}.tar.gz
    mv ${shadowsocks_r_file}/shadowsocks /usr/local/
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x ${shadowsocks_r_init}
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}错误${plain}] ${software[1]} 安装失败"
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_go(){
    cd ${cur_dir}
    if is_64bit; then
        gzip -d ${shadowsocks_go_file_64}.gz
        if [ $? -ne 0 ];then
            echo -e "[${red}Error${plain}] 解压缩 ${shadowsocks_go_file_64}.gz 失败"
            install_cleanup
            exit 1
        fi
        mv -f ${shadowsocks_go_file_64} /usr/bin/shadowsocks-server
    else
        gzip -d ${shadowsocks_go_file_32}.gz
        if [ $? -ne 0 ];then
            echo -e "[${red}错误${plain}] 解压缩 ${shadowsocks_go_file_32}.gz 失败"
            install_cleanup
            exit 1
        fi
        mv -f ${shadowsocks_go_file_32} /usr/bin/shadowsocks-server
    fi

    if [ -f /usr/bin/shadowsocks-server ]; then
        chmod +x /usr/bin/shadowsocks-server
        chmod +x ${shadowsocks_go_init}

        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}错误${plain}] ${software[2]} 安装失败"
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev(){
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_file}.tar.gz
    cd ${shadowsocks_libev_file}
    ./configure --disable-documentation && make && make install
    if [ $? -eq 0 ]; then
        chmod +x ${shadowsocks_libev_init}
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}错误${plain}] ${software[3]} 安装失败"
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev_obfs(){
    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cd ${cur_dir}
        git clone https://github.com/shadowsocks/simple-obfs.git
        [ -d simple-obfs ] && cd simple-obfs || echo -e "[${red}Error:${plain}] Failed to git clone simple-obfs."
        git submodule update --init --recursive
        if centosversion 6; then
            if [ ! "$(command -v autoconf268)" ]; then
                echo -e "[${green}Info${plain}] 开始安装 autoconf268..."
                yum install -y autoconf268 > /dev/null 2>&1 || echo -e "[${red}错误:${plain}]  autoconf268安装失败"
            fi
            # replace command autoreconf to autoreconf268
            sed -i 's/autoreconf/autoreconf268/' autogen.sh
            # replace #include <ev.h> to #include <libev/ev.h>
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/local.h
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/server.h
        fi
        ./autogen.sh
        ./configure --disable-documentation
        make
        make install
        if [ ! "$(command -v obfs-server)" ]; then
            echo -e "[${red}错误${plain}] simple-obfs  ${software[${selected}-1]} 安装失败"
            install_cleanup
            exit 1
        fi
        [ -f /usr/local/bin/obfs-server ] && ln -s /usr/local/bin/obfs-server /usr/bin
    fi
}

install_completed_python(){
    clear
    ${shadowsocks_python_init} start
    echo
    echo  -e "${green}恭喜, ${software[0]} 已安装完成，请按以下信息设置您的客户端!${plain}"
    echo  -e "${green}Your Server IP        : $(get_ip) "
    echo  -e "${green}Your Server Port      : ${shadowsocksport} "
    echo  -e "${green}Your Password         : ${shadowsockspwd} "
    echo  -e "${green}Your Encryption Method: ${shadowsockscipher}"
}

install_completed_r(){
    clear
    ${shadowsocks_r_init} start
    echo
    echo  -e "${green}恭喜, ${software[1]} 已安装完成，请按以下信息设置您的客户端!${plain}"
    echo  -e "${green}Your Server IP        :  $(get_ip) ${plain}"
    echo  -e "${green}Your Server Port      :  ${shadowsocksport} ${plain}"
    echo  -e "${green}Your Password         :  ${shadowsockspwd} ${plain}"
    echo  -e "${green}Your Protocol         :  ${shadowsockprotocol} ${plain}"
    echo  -e "${green}Your obfs             :  ${shadowsockobfs} "
    echo  -e "${green}Your Encryption Method:  ${shadowsockscipher} ${plain}"
}

install_completed_go(){
    clear
    ${shadowsocks_go_init} start
    echo
    echo  -e "${green}恭喜, ${software[2]}已安装完成，请按以下信息设置您的客户端!${plain}"
    echo  -e "${green}Your Server IP        :  $(get_ip) ${plain}"
    echo  -e "${green}Your Server Port      :  ${shadowsocksport} ${plain}"
    echo  -e "${green}Your Password         :  ${shadowsockspwd} ${plain}"
    echo  -e "${green}Your Encryption Method:  ${shadowsockscipher} ${plain}"
}

install_completed_libev(){
    clear
    ldconfig
    ${shadowsocks_libev_init} start
    echo
    echo  -e "${green}恭喜, ${software[3]} 已安装完成，请按以下信息设置您的客户端!${plain}"
    echo  -e "${green}Your Server IP        :  $(get_ip) ${plain}"
    echo  -e "${green}Your Server Port      :  ${shadowsocksport} ${plain}"
    echo  -e "${green}Your Password         :  ${shadowsockspwd} ${plain}"
    if [ "$(command -v obfs-server)" ]; then
    echo  -e " ${green}obfs                 :  ${shadowsocklibev_obfs} ${plain}"
    fi
    echo  -e "${green}您的加密方式           :  ${shadowsockscipher} ${plain}"
}


install_main(){
    install_libsodium
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
    fi
    ldconfig

    if   [ "${selected}" == "1" ]; then
        install_shadowsocks_python
        install_completed_python
    elif [ "${selected}" == "2" ]; then
        install_shadowsocks_r
        install_completed_r
    elif [ "${selected}" == "3" ]; then
        install_shadowsocks_go
        install_completed_go
    elif [ "${selected}" == "4" ]; then
        install_mbedtls
        install_shadowsocks_libev
        install_shadowsocks_libev_obfs
        install_completed_libev
    fi

    echo

}

install_cleanup(){
    cd ${cur_dir}
    rm -rf simple-obfs
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
    rm -rf ${shadowsocks_python_file} ${shadowsocks_python_file}.zip
    rm -rf ${shadowsocks_r_file} ${shadowsocks_r_file}.tar.gz
    rm -rf ${shadowsocks_go_file_64}.gz ${shadowsocks_go_file_32}.gz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
}

install_shadowsocks(){
    disable_selinux
    install_select
    install_prepare
    install_dependencies
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
        config_firewall
    fi
    install_main
    install_cleanup
}

uninstall_shadowsocks_python(){
    printf "是否确定要卸载 ${red}${software[0]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_python_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_python_init} stop
        fi
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi

        rm -fr $(dirname ${shadowsocks_python_config})
        rm -f ${shadowsocks_python_init}
        rm -f /var/log/shadowsocks.log
        if [ -f /usr/local/shadowsocks_python.log ]; then
            cat /usr/local/shadowsocks_python.log | xargs rm -rf
            rm -f /usr/local/shadowsocks_python.log
        fi
        echo -e "[${green}Info${plain}] ${software[0]} 卸载成功"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} 卸载已取消"
        echo
    fi
}

uninstall_shadowsocks_r(){
    printf "是否确定要卸载 ${red}${software[1]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_r_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_r_init} stop
        fi
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_r_config})
        rm -f ${shadowsocks_r_init}
        rm -f /var/log/shadowsocks.log
        rm -fr /usr/local/shadowsocks
        echo -e "[${green}Info${plain}] ${software[1]} 卸载成功"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[1]} 卸载已取消"
        echo
    fi
}

uninstall_shadowsocks_go(){
    printf "是否确定要卸载 ${red}${software[2]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_go_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_go_init} stop
        fi
        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_go_config})
        rm -f ${shadowsocks_go_init}
        rm -f /usr/bin/shadowsocks-server
        echo -e "[${green}Info${plain}] ${software[2]} 卸载成功"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[2]} 卸载已取消"
        echo
    fi
}

uninstall_shadowsocks_libev(){
    printf "是否确定要卸载 ${red}${software[3]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_libev_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_libev_init} stop
        fi
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_libev_config})
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/bin/obfs-local
        rm -f /usr/local/bin/obfs-server
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}Info${plain}] ${software[3]} 卸载成功"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[3]} 卸载已取消"
        echo
    fi
}

uninstall_shadowsocks(){
    while true
    do
    echo  "您要卸载哪个版本?"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "请输入一个数字 [1-4]:" un_select
    case "${un_select}" in
        1|2|3|4)
        echo
        echo "您的选择 = ${software[${un_select}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}错误${plain}] 仅能输入一个数字 [1-4]"
        ;;
    esac
    done

    if   [ "${un_select}" == "1" ]; then
        if [ -f ${shadowsocks_python_init} ]; then
            uninstall_shadowsocks_python
        else
            echo -e "[${red}错误${plain}] 您没有安装${software[${un_select}-1]} ，卸载毛线"
            echo
            exit 1
        fi
    elif [ "${un_select}" == "2" ]; then
        if [ -f ${shadowsocks_r_init} ]; then
            uninstall_shadowsocks_r
        else
            echo -e "[${red}错误${plain}] 您没有安装${software[${un_select}-1]} 卸载毛线"
            echo
            exit 1
        fi
    elif [ "${un_select}" == "3" ]; then
        if [ -f ${shadowsocks_go_init} ]; then
            uninstall_shadowsocks_go
        else
            echo -e "[${red}错误${plain}] 您没有安装${software[${un_select}-1]} 卸载毛线"
            echo
            exit 1
        fi
    elif [ "${un_select}" == "4" ]; then
        if [ -f ${shadowsocks_libev_init} ]; then
            uninstall_shadowsocks_libev
        else
            echo -e "[${red}错误${plain}] 您没有安装${software[${un_select}-1]} 卸载毛线"
            echo
            exit 1
        fi
    fi
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "${action}" in
    install|uninstall)
        ${action}_shadowsocks
        ;;
    *)
        echo "参数错误! [${action}]"
        echo "使用方法: $(basename $0) [install|uninstall]"
        ;;
esac
