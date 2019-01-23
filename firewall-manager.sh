#!/bin/bash

IPT=/sbin/iptables
IP6T=/sbin/ip6tables

# Static IPs
LAN_IP=$(ifconfig | grep -A 1 'eth0' | grep -o '192.[^ ]*' | head -1)

# WAN DNS

# CJDNS DNS

# LAN-reachable servers
LAN_SERVERS=(192.168.0.1)

# WAN-reachable servers
VPN_GUARDS=(179.43.176.98 46.165.251.67)
VPN_SERVERS=(
          swiss.privateinternetaccess.com   
	     nl.privateinternetaccess.com
	     mx.privateinternetaccess.com
	     de.privateinternetaccess.com
            )

# Filtered ports (VPN TUNnel)
TUN_TCP_FILTER=(80 443)
TUN_UDP_FILTER=(53 6667 6669 9150)


#  -----------------------------------------------------------------------------

#flush
$IPT -F;              $IP6T -F
$IPT -X;              $IP6T -X
$IPT -t nat -F;       $IP6T -t nat -F
$IPT -t nat -X;       $IP6T -t nat -X
$IPT -t mangle -F;    $IP6T -t mangle -F
$IPT -t mangle -X;    $IP6T -t mangle -X

#set policies
$IPT -P INPUT   DROP; $IP6T -P INPUT   DROP
$IPT -P OUTPUT  DROP; $IP6T -P OUTPUT  DROP
$IPT -P FORWARD DROP; $IP6T -P FORWARD DROP

#clients

#log attacks
$IPT -A INPUT -f -j LOG
$IPT -A INPUT -p icmp --icmp-type echo-request -j LOG

#drop invalid incoming packets
$IPT -A INPUT -f -j DROP
$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A INPUT -p tcp   --tcp-flags ALL         ALL             -j DROP
$IPT -A INPUT -p tcp   --tcp-flags ALL         NONE            -j DROP
$IPT -A INPUT -p tcp   --tcp-flags ALL         ACK,RST,SYN,FIN -j DROP
$IPT -A INPUT -p tcp   --tcp-flags SYN,RST SYN,RST             -j DROP
$IPT -A INPUT -p tcp   --tcp-flags SYN,FIN SYN,FIN             -j DROP

#allow loopback traffic
$IPT  -A INPUT  -i lo -j ACCEPT
$IPT  -A OUTPUT -o lo -j ACCEPT

#LAN services
for server in "${LAN_HTTP_SERVERS[@]}"; do
    allow_remote_server(eth0, $LAN_IP, $server)
done
    
#WAN services
for server in "${VPN_GUARDS[@]}"; do
    allow_remote_server(eth0, any, $server)
done
for server in "${VPN_SERVERS[@]}"; do
    allow_remote_server(eth0, any, $server)
done

#filter VPN
allow_ping_out(tun0, any)
for port in "${VPN_PORTS[@]}"; do
    allow_port_out(tun0, any, any, port)
done

#guards
$IPT -A INPUT  -j LOG;  $IP6T -A INPUT  -j LOG
$IPT -A OUTPUT -j LOG;  $IP6T -A OUTPUT -j LOG
$IPT -A INPUT  -j DROP; $IP6T -A INPUT  -j DROP
$IPT -A OUTPUT -j DROP; $IP6T -A OUTPUT -j DROP

#  -----------------------------------------------------------------------------

INBOUND_FILTER=  $IPT -A INPUT  -m state --state     ESTABLISHED -j ACCEPT
INBOUND_ALLOW=   $IPT -A INPUT  -m state --state NEW,ESTABLISHED -j ACCEPT
OUTBOUND_FILTER= $IPT -A OUTPUT -m state --state     ESTABLISHED -j ACCEPT
OUTBOUND_ALLOW=  $IPT -A OUTPUT -m state --state NEW,ESTABLISHED -j ACCEPT

function allow_ping_in(iface, client) {
    cip= $(getCIP client)
    sip= $(getSIP client)
    $INBOUND_ALLOW   -i $iface -d $cip -s $sip -p icmp --icmp-type echo-request
    $OUTBOUND_FILTER -o $iface -s $cip -d $sip -p icmp --icmp-type echo-reply
}

function allow_port_in(iface, clientspace, server, port) {
    pn=$(echo $port | grep -o '^[^:]*')
    prtcl=$(echo $port | grep -o ':[^ ]*')
    $INBOUND_ALLOW   -i $iface -d $clientspace -s $server --sport $pn -p $prtcl
    $OUTBOUND_FILTER -o $iface -s $clientspace -d $server --dport $pn -p $prtcl
 }

function allow_remote_client(iface, client) {
    for port in $(getTCP $client); do
	allow_port_in($iface, $(getCIP client), $(getSIP client), $port + :TCP)
    done
    for port in $(getUDP $client); do
	allow_port_in($iface, $(getCIP client), $(getSIP client), $port + :UDP)
    done
}

function allow_ping_out(iface, destination) {
    $INBOUND_FILTER -i $iface -d $destination -p icmp --icmp-type echo-reply
    $OUTBOUND_ALLOW -o $iface -d $destination -p icmp --icmp-type echo-request
}

function allow_port_out(iface, client, serverspace, port) {
    pn=$(echo $port | grep -o '^[^:]*')
    prtcl=$(echo $port | grep -o ':[^ ]*')
    $INBOUND_FILTER -i $iface -d $client -s $serverspace --sport $pn -p $prtcl
    $OUTBOUND_ALLOW -o $iface -s $client -d $serverspace --dport $pn -p $prtcl
}

function allow_remote_server(iface, clientspace, server) {
    for ip in $(getIPs $server); do
	for port in $(getTCP $server); do
	    allow_port_out($iface, $clientspace, $ip, $port + :TCP)
	done
	for port in $(getUDP $server); do
	    allow_port_out($iface, $clientspace, $ip, $port + :UDP)
	done
    done
}
