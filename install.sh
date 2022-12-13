#!/bin/bash
DOMAIN=$1
PROXIFIED=$2
TYPE=$3
IP=$(curl http://whatismyip.akamai.com/)

WRD=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr '[:upper:]' '[:lower:]' | head -1)
RWRD="${WRD}nim"

#curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
#apt install nodejs -y
##apt install git -y
#npm install -g npm
#npm install pm2 -g

#cd ~/
#mkdir sman
#cd sman
#git clone https://bitbucket.org/anonymith-backends/telemetry.git .
#sed -i -e 's/80/4444/1' ./service.js
#npm install
#pm2 start index.js --name sman
#pm2 save
#pm2 startup
#mkdir /var/log/openvpn
#touch /var/log/openvpn/status.log

#cd ~/v2ci

apt install -y expect

ARECORD=$(curl https://random-word-api.herokuapp.com/word)
ARECORD=`echo "$ARECORD" | cut -d'"' -f 2`

chmod +x cf-dns.sh
chmod +x telemetry.sh

./cf-dns.sh -d $DOMAIN -t A -n $ARECORD -c $IP -l 1 -x n

DOMAINNAME="${ARECORD}.${DOMAIN}"

wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/NimaEagle/lagent/master/install.sh" && chmod 700 /root/install.sh
expect script.exp $DOMAINNAME $RWRD

if [[ "$TYPE" == "vless_tcp_xtls_direct" ]]; then
CONFIGFILE="VLESSTCPXTLSDIRECT"
elif [[ "$TYPE" == "vless_tcp_xtls_splice" ]]; then
CONFIGFILE="VLESSTCPXTLSSPLICE"
elif [[ "$TYPE" == "trojan_tcp_xtls_direct" ]]; then
CONFIGFILE="TROJANTCPXTLSDIRECT"
elif [[ "$TYPE" == "trojan_tcp_xtls_splice" ]]; then
CONFIGFILE="TROJANTCPXTLSSPLICE"
elif [[ "$TYPE" == "vmess_ws" ]]; then
CONFIGFILE="VMESSWS"
elif [[ "$TYPE" == "vless_ws" ]]; then
CONFIGFILE="VLESSWS"
elif [[ "$TYPE" == "vless_grpc_tls" ]]; then
CONFIGFILE="VLESSGRPCTLS"
elif [[ "$TYPE" == "trojan" ]]; then
CONFIGFILE="TROJAN"
elif [[ "$TYPE" == "trojan_grpc" ]]; then
CONFIGFILE="TROJANGRPC"
fi

echo "${NAFAR}"

VLESSCONFIG=`cat ~/${CONFIGFILE}.txt`
touch ~/client.ovpn
echo -e "client\nproto v2r\nremote ${IP} 443\n${VLESSCONFIG}" > ~/clientt.ovpn

mkdir -p /home/nima/whats
touch /home/nima/whats/index.txt
echo -n "Error: 404" > /home/nima/whats/index.txt

# nginx
sed -i -e '0,/return 403;/s//root \/home\/nima;\n                                index index.txt;\n\n                                location \/ {\n                                        try_files $uri $uri\/ =404;\n                                }/' /etc/nginx/conf.d/alone.conf
systemctl restart nginx

{ echo "12"; echo "1"; } | vasma


# set proxified or not
if [ "$PROXIFIED" == "P" ]; then
    ./cf-dns.sh -d $DOMAIN -t A -n $ARECORD -c $IP -l 1 -x y
fi



# run rules
#iptables -N syn_flood
#iptables -A INPUT -p tcp --syn -j syn_flood
#iptables -A syn_flood -m limit --limit $LIMIT/s --limit-burst $BURST -j RETURN
#iptables -A syn_flood -j DROP
#iptables -A INPUT -p icmp -m limit --limit  $LIMIT/s --limit-burst $BURST -j ACCEPT
#iptables -A INPUT -p icmp -m limit --limit $LIMIT/s --limit-burst $BURST -j LOG --log-prefix PING-DROP:
#iptables -A INPUT -p icmp -j DROP
#iptables -A OUTPUT -p icmp -j ACCEPT

#sysctl -w net.ipv4.tcp_syncookies=1 #1
#sysctl -w net.ipv4.tcp_max_syn_backlog=3072 #128
#sysctl -w net.ipv4.tcp_synack_retries=5 #5
#sysctl -w net.ipv4.conf.all.send_redirects=1 #1
#sysctl -w net.ipv4.conf.all.accept_redirects=1 #1
#sysctl -w net.ipv4.conf.all.forwarding=0 #0
#sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 #1

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

iptables-save

#echo "kernel.printk=4 4 1 7 " >> /etc/sysctl.conf
#echo "kernel.panic=10" >> /etc/sysctl.conf
#echo "kernel.sysrq=0" >> /etc/sysctl.conf
#echo "kernel.shmmax=4294967296" >> /etc/sysctl.conf
#echo "kernel.shmall=4194304" >> /etc/sysctl.conf
#echo "kernel.core_uses_pid=1" >> /etc/sysctl.conf
#echo "kernel.msgmnb=65536" >> /etc/sysctl.conf
#echo "kernel.msgmax=65536" >> /etc/sysctl.conf
#echo "vm.swappiness=20" >> /etc/sysctl.conf
#echo "vm.dirty_ratio=80" >> /etc/sysctl.conf
#echo "vm.dirty_background_ratio=5" >> /etc/sysctl.conf
#echo "fs.file-max=2097152" >> /etc/sysctl.conf
#echo "net.core.netdev_max_backlog=262144" >> /etc/sysctl.conf
#echo "net.core.rmem_default=31457280" >> /etc/sysctl.conf
#echo "net.core.rmem_max=67108864" >> /etc/sysctl.conf
#echo "net.core.wmem_default=31457280" >> /etc/sysctl.conf
#echo "net.core.wmem_max=67108864" >> /etc/sysctl.conf
#echo "net.core.somaxconn=65535" >> /etc/sysctl.conf
#echo "net.core.optmem_max=25165824" >> /etc/sysctl.conf
#echo "net.ipv4.neigh.default.gc_thresh1=4096" >> /etc/sysctl.conf
#echo "net.ipv4.neigh.default.gc_thresh2=8192" >> /etc/sysctl.conf
#echo "net.ipv4.neigh.default.gc_thresh3=16384" >> /etc/sysctl.conf
#echo "net.ipv4.neigh.default.gc_interval=5" >> /etc/sysctl.conf
#echo "net.ipv4.neigh.default.gc_stale_time=120" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_max=10000000" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_loose=0" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_established=1800" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_close=10" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_close_wait=10" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_fin_wait=20" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_last_ack=20" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_syn_recv=20" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_syn_sent=20" >> /etc/sysctl.conf
#echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait=10" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_slow_start_after_idle=0" >> /etc/sysctl.conf
#echo "net.ipv4.ip_local_port_range=1024 65000" >> /etc/sysctl.conf
#echo "net.ipv4.ip_no_pmtu_disc=1" >> /etc/sysctl.conf
#echo "net.ipv4.route.flush=1" >> /etc/sysctl.conf
#echo "net.ipv4.route.max_size=8048576" >> /etc/sysctl.conf
#echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
#echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_congestion_control=htcp" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_mem=65536 131072 262144" >> /etc/sysctl.conf
#echo "net.ipv4.udp_mem=65536 131072 262144" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_rmem=4096 87380 33554432" >> /etc/sysctl.conf
#echo "net.ipv4.udp_rmem_min=16384" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_wmem=4096 87380 33554432" >> /etc/sysctl.conf
#echo "net.ipv4.udp_wmem_min=16384" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_max_tw_buckets=1440000" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_tw_recycle=0" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_tw_reuse=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_max_orphans=400000" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_window_scaling=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_synack_retries=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_syn_retries=2" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_max_syn_backlog=16384" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_timestamps=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_sack=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_fack=1" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_ecn=2" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_fin_timeout=10" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_keepalive_time=600" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_keepalive_intvl=60" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_keepalive_probes=10" >> /etc/sysctl.conf
#echo "net.ipv4.tcp_no_metrics_save=1" >> /etc/sysctl.conf
#echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
#echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
#echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
#echo "net.ipv4.conf.all.accept_source_route=0 " >> /etc/sysctl.conf
#echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf

echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog=2048 " >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries=3" >> /etc/sysctl.conf


sysctl -p

# install telemetry script and change it
./telemetry.sh
