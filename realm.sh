#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
clear

sh_ver="1.0.2"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Yellow_font_prefix="\033[0;33m"

Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"
realm_conf_path="/etc/realm/config.json"
raw_conf_path="/etc/realm/rawconf"
now_ver_file="/etc/realm/ver.txt"
check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}

#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
}

Installation_dependency(){
    echo -e "${Info} 开始安装依赖..."
	if [[ ${release} == "centos" ]]; then
		yum install epel-release -y && yum update
        yum install gzip wget curl unzip jq -y
	else
		apt-get update && apt-get install gzip wget curl unzip jq -y
	fi
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
    echo -e "${Info} 依赖安装完毕..."
}

#检查系统内核版本
sysArch() {
    uname=$(uname -m)
    if [[ "$uname" == "i686" ]] || [[ "$uname" == "i386" ]]; then
        arch="i686"
    elif [[ "$uname" == *"armv7"* ]] || [[ "$uname" == "armv6l" ]]; then
        arch="arm"
    elif [[ "$uname" == *"armv8"* ]] || [[ "$uname" == "aarch64" ]]; then
        arch="aarch64"
    else
        arch="x86_64"
    fi    
}
#检测是否已安装RealM
check_status(){
    if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
        echo "------------------------------"
        echo -e "--------${Green_font_prefix} RealM已安装~ ${Font_color_suffix}--------"
        echo "------------------------------"
    else
        echo "------------------------------"
        echo -e "--------${Red_font_prefix}RealM未安装！${Font_color_suffix}---------"
        echo "------------------------------"
    fi
}

#安装RealM
Install_RealM(){
  if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
  echo "≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡"
  echo -e "≡≡≡≡≡≡ ${Green_font_prefix}RealM已安装~ ${Font_color_suffix}≡≡≡≡≡≡"
  echo "≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡"
  sleep 2s
  start_menu
  fi
  Installation_dependency
  echo -e "${Info} 开始安装 RealM 主程序..."
  new_ver=$(wget -qO- https://api.github.com/repos/xOS/RealM/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
  mkdir /etc/realm
  wget -N --no-check-certificate "https://github.com/xOS/RealM/releases/download/${new_ver}/realm-${arch}-unknown-linux-gnu.tar.gz" && tar -xvf realm-${arch}-unknown-linux-gnu.tar.gz && chmod +x realm && mv realm /usr/local/bin/realm 
  echo "${new_ver}" > ${now_ver_file}

echo '
[Unit]
Description=realm
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
LimitNOFILE=32767 
Type=simple
User=root
Restart=on-failure
RestartSec=5s
# DynamicUser=true
ExecStart=/usr/local/bin/realm -c /etc/realm/config.json

[Install]
WantedBy=multi-user.target' > /etc/systemd/system/realm.service
systemctl enable --now realm
Set_dns
Write_config
    echo "------------------------------"
    if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
        echo -e "-------${Green_font_prefix} RealM 主程序安装成功! ${Font_color_suffix}-------"
        echo "------------------------------"
    else
        echo -e "-------${Red_font_prefix}RealM 安装失败，请检查你的网络环境！${Font_color_suffix}-------"
        echo "------------------------------"
        `rm -rf "$(pwd)"/realm`
        `rm -rf "$(pwd)"/realm.service`
        `rm -rf "$(pwd)"/config.json`
    fi
sleep 3s
start_menu
}
#获取 ReamlM 进程 ID
check_pid(){
	PID=$(ps -ef| grep "ream" | awk '{print $2}')
}
#更新 ReamlM
Update_RealM(){
    new_ver=$(wget -qO- https://api.github.com/repos/xOS/RealM/releases| grep "tag_name"| head -n 1| awk -F ":" '{print $2}'| sed 's/\"//g;s/,//g;s/ //g')
	now_ver=$(cat ${now_ver_file})
	if [[ "${now_ver}" != "${new_ver}" ]]; then
		echo -e "${Info} 发现 RealM 已有新版本 [ ${new_ver} ]，旧版本 [ ${now_ver} ]"
		read -e -p "是否更新 ? [Y/n] :" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ $yn == [Yy] ]]; then
			check_pid
			[[ ! -z $PID ]] && kill -9 ${PID}
			wget -N --no-check-certificate "https://github.com/xOS/RealM/releases/download/${new_ver}/realm-${arch}-unknown-linux-gnu.tar.gz" && tar -xvf realm-${arch}-unknown-linux-gnu.tar.gz && chmod +x realm && mv -f realm /usr/local/bin/realm && systemctl restart realm
            echo "${new_ver}" > ${now_ver_file}
            echo -e "-------${Green_font_prefix} RealM 更新成功! ${Font_color_suffix}-------"
            sleep 3s
            start_menu
		fi
        sleep 3s
        start_menu
	else
		echo -e "${Info} 当前 RealM 已是最新版本 [ ${new_ver} ]"
        sleep 3s
        start_menu
	fi
}

#卸载RealM
Uninstall_RealM(){
    if test -o /usr/local/bin/realm -o /etc/systemd/system/realm.service -o $realm_conf_path;then
    sleep 2s
    systemctl stop realm.service
    systemctl disable realm.service
    `rm -rf /usr/local/bin/realm`
    `rm -rf /etc/systemd/system/realm.service`
    `rm -rf /etc/realm`
    echo "------------------------------"
    echo -e "-------${Green_font_prefix} RealM 卸载成功! ${Font_color_suffix}-------"
    echo "------------------------------"
    sleep 3s
    start_menu
    else
    echo -e "-------${Red_font_prefix}RealM 没有安装,卸载个锤子！${Font_color_suffix}-------"
    sleep 3s
    start_menu
    fi
}
#启动RealM
Start_RealM(){
    if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
    `systemctl start realm`
    echo "------------------------------"
    echo -e "-------${Green_font_prefix} RealM启动成功! ${Font_color_suffix}-------"
    echo "------------------------------"
    sleep 3s
    start_menu
    else
    echo -e "-------${Red_font_prefix}RealM没有安装,启动个锤子！${Font_color_suffix}-------"    
    sleep 3s
    start_menu
    fi
}

#停止RealM
Stop_RealM(){
    if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
    `systemctl stop realm`
    echo "------------------------------"
    echo -e "-------${Green_font_prefix} RealM停止成功! ${Font_color_suffix}-------"
    echo "------------------------------"
    sleep 3s
    start_menu
    else
    echo -e "-------${Red_font_prefix}RealM 没有安装,停止个锤子！${Font_color_suffix}-------"    
    sleep 3s
    start_menu
    fi
}

#重启RealM
Restart_RealM(){
    if test -a /usr/local/bin/realm -a /etc/systemd/system/realm.service -a $realm_conf_path;then
    `systemctl restart realm`
    echo "------------------------------"
    echo -e "-------${Green_font_prefix} RealM 重启成功! ${Font_color_suffix}-------"
    echo "------------------------------"
    sleep 3s
    start_menu
    else
    echo -e "-------${Red_font_prefix}RealM 没有安装,重启个锤子！${Font_color_suffix}-------"    
    sleep 3s
    start_menu
    fi
}

Write_config(){
	cat > ${realm_conf_path}<<-EOF
{"dns_mode":"${dns}","endpoints":[]}
EOF
}

Set_dns(){
	echo -e "请选择 DNS 模式
==============================	
 ${Green_font_prefix} 1.${Font_color_suffix} 仅 IPv4 模式
 ${Green_font_prefix} 2.${Font_color_suffix} 仅 IPv6 模式
 ${Green_font_prefix} 3.${Font_color_suffix} IPv4 + IPv6 模式
 ${Green_font_prefix} 4.${Font_color_suffix} IPv4 优先 + IPv6 模式 ${Red_font_prefix}(默认)${Font_color_suffix}
 ${Green_font_prefix} 5.${Font_color_suffix} IPv6 优先 + IPv4 模式
==============================
 ${Tip} 如不知道如何选择直接回车即可 !" && echo
	read -e -p "(默认: 4. IPv4 优先 + IPv6 模式):" dns
	[[ -z "${dns}" ]] && dns="4"
	if [[ ${dns} == "1" ]]; then
		dns="ipv4_only"
	elif [[ ${dns} == "2" ]]; then
		dns="ipv6_only"
	elif [[ ${dns} == "3" ]]; then
		dns="ipv4_and_ipv6"
	elif [[ ${dns} == "4" ]]; then
		dns="ipv4_then_ipv6"
    elif [[ ${dns} == "5" ]]; then
		dns="ipv6_then_ipv4"
	else
		dns="ipv4_then_ipv6"
	fi
	echo && echo "=============================="
	echo -e "	DNS 模式 : ${Red_background_prefix} ${dns} ${Font_color_suffix}"
	echo "==============================" && echo
}

#设置本地监听端口
Set_listening_ports(){
read -e -p " 请输入本地端口[1-65535] (支持端口段如1-100,数量需同转发端口相同):" lport
[[ -z "${lport}" ]] && echo "取消..." && exit 1
}

#设置转发地址
Set_remote_addresses(){
read -e -p " 请输入需转发的地址/IP :" ip
[[ -z "${ip}" ]] && echo "取消..." && exit 1
}

#设置转发端口
Set_remote_ports(){
read -e -p " 请输入远程端口[1-65535] (支持端口段如1-100，数量需同监听端口相同):" port
[[ -z "${port}" ]] && echo "取消..." && exit 1
}

Set_udp(){
	echo -e "是否开启 UDP ？
==============================
${Green_font_prefix} 1.${Font_color_suffix} 开启  ${Green_font_prefix} 2.${Font_color_suffix} 关闭
=============================="
	read -e -p "(默认：1.开启)：" udp
	[[ -z "${udp}" ]] && udp="1"
	if [[ ${udp} == "1" ]]; then
		udp=true
	else
		udp=false
	fi
	echo && echo "=============================="
	echo -e "UDP 开启状态：${Red_background_prefix} ${udp} ${Font_color_suffix}"
	echo "==============================" && echo
}

#配置转发
start_conf(){
    JSON='{"local":"0.0.0.0:lport","remote":"ip:port","udp":udpm}'
	JSON=${JSON/lport/$lport};
	JSON=${JSON/ip/$ip};
	JSON=${JSON/port/$port};
	JSON=${JSON/udpm/$udp};
	temp=`jq --argjson data $JSON '.endpoints += [$data]' $realm_conf_path`
	echo $temp > $realm_conf_path
}

#写入查询配置
Write_rawconf(){
    echo $lport"/"$ip"#"$port\n>> $raw_conf_path
}

#赋值
eachconf_retrieve()
{
    a=${trans_conf}
    b=${a#*/}
    listening_ports=${trans_conf%/*}
    remote_addresses=${b%#*}
    remote_ports=${trans_conf#*#}
}

#添加设置
Set_Config(){
Set_listening_ports
Set_remote_addresses
Set_remote_ports
Set_udp
	echo && echo -e "==============================
	请检查 RealM 转发规则配置是否有误 !\n
	本地 端口: ${Green_font_prefix}${lport}${Font_color_suffix}
	远程 IP: ${Green_font_prefix}${ip}${Font_color_suffix}
	远程端 口: ${Green_font_prefix}${port}${Font_color_suffix}

==============================\n"
	read -e -p "请按任意键继续，如有配置错误请使用 Ctrl+C 退出。" 
start_conf
Write_rawconf
Restart_RealM
}

#添加RealM转发规则
Add_RealM(){
Set_Config
echo -e "--------${Green_font_prefix} 规则添加成功! ${Font_color_suffix}--------"
read -p "输入任意键按回车返回主菜单"
#start_menu
}

#查看规则
Check_RealM(){
    echo -e "=============================="
    echo -e "           RealM 配置             "
    echo -e "=============================="
    echo -e "序号|本地端口|远程地址:远程端口"
    echo -e "=============================="
    count_line=$(awk 'END{print NR}' $raw_conf_path)
    for((i=1;i<=$count_line;i++))
    do
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        echo -e " $i  |  $listening_ports  |$remote_addresses:$remote_ports"
        echo -e "------------------------------"
    done
read -p "输入任意键按回车返回主菜单"
start_menu
}

#删除RealM转发规则
Delete_RealM(){
    echo -e "          RealM 配置              "
    echo -e "=============================="
    echo -e "序号|本地端口|转发地址:转发端口"
    echo -e "=============================="

    count_line=$(awk 'END{print NR}' $raw_conf_path)
    for((i=1;i<=$count_line;i++))
    do
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        echo -e " $i  |  $listening_ports  |$remote_addresses:$remote_ports"
        echo -e "------------------------------"
    done
read -p "请输入你要删除的配置编号：" numdelete
sed -i "${numdelete}d" $raw_conf_path
nu=${numdelete}-1
temp=`jq 'del(.endpoints['$nu'])' $realm_conf_path`
echo $temp > $realm_conf_path
clear
`systemctl restart realm`
echo -e "${Red_font_prefix}相应配置已删除,服务已重启${Font_color_suffix}"
sleep 2s
clear
echo -e "${Green_font_prefix}当前配置如下${Font_color_suffix}"
echo -e "------------------------------"
Check_RealM
read -p "输入任意键按回车返回主菜单"
start_menu
}


#更新脚本
Update_Shell(){
	echo -e "当前版本为 [ ${sh_ver} ]，开始检测最新版本..."
	sh_new_ver=$(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/xOS/RealM/master/realm.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 检测最新版本失败 !" && start_menu
	if [[ ${sh_new_ver} != ${sh_ver} ]]; then
		echo -e "发现新版本[ ${sh_new_ver} ]，是否更新？[Y/n]"
		read -p "(默认: y):" yn
		[[ -z "${yn}" ]] && yn="y"
		if [[ ${yn} == [Yy] ]]; then
			wget -O realm.sh --no-check-certificate https://raw.githubusercontent.com/xOS/RealM/master/realm.sh && chmod +x realm.sh
			echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !"
            echo -e "3s后执行新脚本"
	    sleep 3s
            bash realm.sh
		else
			echo && echo "	已取消..." && echo
            sleep 3s
            bash realm.sh
		fi
	else
		echo -e "当前已是最新版本[ ${sh_new_ver} ] !"
		sleep 3s
        bash realm.sh
	fi
}

#备份配置
Backup(){
	if test -a $raw_conf_path;then
	cp $raw_conf_path /etc/realm/rawconf.back
	echo -e " ${Green_font_prefix}备份完成！${Font_color_suffix}"
	sleep 2s
	start_menu
	else
	echo -e " ${Red_font_prefix}未找到配置文件，备份失败${Font_color_suffix}"
	sleep 2s
	start_menu
	fi
}

#恢复配置
Recovey(){
	if test -a /etc/realm/rawconf.back;then
	rm -f $raw_conf_path
	cp /etc/realm/rawconf.back $raw_conf_path
	echo -e " ${Green_font_prefix}恢复完成！${Font_color_suffix}"
	sleep 2s
	start_menu
	else
	echo -e " ${Red_font_prefix}未找到备份文件，备份失败${Font_color_suffix}"
	sleep 2s
	start_menu
	fi
}

#备份/恢复配置
Backup_Recovey(){
clear
echo -e "
 ==============================
 ${Green_font_prefix}1.${Font_color_suffix} 备份配置
 ${Green_font_prefix}2.${Font_color_suffix} 恢复配置
 ${Green_font_prefix}3.${Font_color_suffix} 删除备份
 =============================="
echo
 read -p " 请输入数字后[1-2] 按回车键:" num2
 case "$num2" in
	1)
     Backup
	;;
	2)
     Recovey 
	;;
	3)
     if test -a /etc/realm/rawconf.back;then
     rm -f /etc/realm/rawconf.back
	echo -e " ${Green_font_prefix}删除成功！${Font_color_suffix}"
	sleep 2s
	start_menu
	else
	echo -e " ${Red_font_prefix}未找到备份文件，删除失败${Font_color_suffix}"	
	sleep 2s
	start_menu
	fi
	;;
	*)
	esac
	echo -e "${Error}:请输入正确数字 [1-2] 按回车键"
	sleep 2s
	Backup_Recovey
}

#查看RealM状态
Status_RealM(){
  systemctl status realm
  read -p "输入任意键按回车返回主菜单"
  start_menu
}

#定时重启任务
Time_Task(){
  clear
  echo "###############################"
  echo "#        RealM 一键脚本       #"
  echo "###############################" 
  echo -e "=============================="
  echo -e "${Green_font_prefix}1.配置RealM定时重启任务${Font_color_suffix}"
  echo -e "${Red_font_prefix}2.删除RealM定时重启任务${Font_color_suffix}"
  echo -e "=============================="
  read -p "请选择: " numtype
  if [ "$numtype" == "1" ]; then  
  echo -e "请选择定时重启任务类型:"
  echo -e "1.分钟 2.小时 3.天" 
  read -p "请输入类型:
  " type_num
  case "$type_num" in
	1)
  echo -e "请设置每多少分钟重启RealM任务"	
  read -p "请设置分钟数:
  " type_m
  echo "*/$type_m * * * *  /usr/bin/systemctl restart realm" >> /var/spool/cron/crontabs/root
  sync /var/spool/cron/crontabs/root
  systemctl restart cron 
	;;
	2)
  echo -e "请设置每多少小时重启RealM任务"	
  read -p "请设置小时数:
  " type_h
  echo "0 0 */$type_h * * ? * /usr/bin/systemctl restart realm" >> /var/spool/cron/crontabs/root
  sync /var/spool/cron/crontabs/root
  systemctl restart cron
	;;
	3)
  echo -e "请设置每多少天重启RealM任务"	
  read -p "请设置天数:
  " type_d
  echo "0 0 /$type_d * * /usr/bin/systemctl restart realm" >> /var/spool/cron/crontabs/root
  sync /var/spool/cron/crontabs/root
  systemctl restart cron
	;;
	*)
	clear
	echo -e "${Error}:请输入正确数字 [1-3] 按回车键"
	sleep 2s
	Time_Task
	;;
  esac
  echo -e "${Green_font_prefix}设置成功!任务已重启完成~${Font_color_suffix}"	
  echo -e "${Red_font_prefix}注意：该重启任务测试环境为debian9,其他系统暂不清楚情况,请根据具体情况自行进行重启任务配置.不会请去百度~${Font_color_suffix}"	
  read -p "输入任意键按回车返回主菜单"
  start_menu   
  elif [ "$numtype" == "2" ]; then
  sed -i "/realm/d" /var/spool/cron/crontabs/root
  systemctl restart cron
  echo -e "${Green_font_prefix}定时重启任务删除完成！${Font_color_suffix}"
  read -p "输入任意键按回车返回主菜单"
  start_menu    
  else
  echo "输入错误，请重新输入！"
  sleep 2s
  Time_Task
  fi  
}

#主菜单
start_menu(){
check_root
check_sys
sysArch
clear
echo
echo "###############################"
echo "#        RealM 一键脚本       #"
echo "###############################"
echo -e "
 当前版本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
 ${Green_font_prefix}0.${Font_color_suffix} 更新脚本
 ${Green_font_prefix}1.${Font_color_suffix} 安装 RealM
 ${Green_font_prefix}2.${Font_color_suffix} 更新 RealM
 ${Green_font_prefix}3.${Font_color_suffix} 卸载 RealM
==============================
 ${Green_font_prefix}4.${Font_color_suffix} 启动 RealM
 ${Green_font_prefix}5.${Font_color_suffix} 停止 RealM
 ${Green_font_prefix}6.${Font_color_suffix} 重启 RealM
 ${Green_font_prefix}7.${Font_color_suffix} 查看 RealM 状态 
==============================
 ${Green_font_prefix}8.${Font_color_suffix} 添加 RealM 转发规则
 ${Green_font_prefix}9.${Font_color_suffix} 查看 RealM 转发规则
 ${Green_font_prefix}10.${Font_color_suffix} 删除 RealM 转发规则
 ${Green_font_prefix}11.${Font_color_suffix} 退出脚本
 ${Green_font_prefix}12.${Font_color_suffix} 备份/恢复配置
 ${Green_font_prefix}13.${Font_color_suffix} 添加定时重启任务"
 check_status

read -p " 请输入数字后[0-13] 按回车键:
" num
case "$num" in
	1)
	Install_RealM
	;;
    2)
    Update_RealM
    ;;
	3)
	Uninstall_RealM
	;;
	4)
	Start_RealM
	;;
	5)
	Stop_RealM
	;;	
	6)
	Restart_RealM
	;;
    7)
	Status_RealM
	;;		
	8)
	Add_RealM
	;;
	9)
	Check_RealM
	;;
	10)
	Delete_RealM
	;;
	11)
	exit 1
	;;
	0)
	Update_Shell
	;;
	12)
	Backup_Recovey
	;;
	13)
	Time_Task
	;;	
	*)	
	clear
	echo -e "${Error}:请输入正确数字 [0-12] 按回车键"
	sleep 2s
	start_menu
	;;
esac
}
start_menu