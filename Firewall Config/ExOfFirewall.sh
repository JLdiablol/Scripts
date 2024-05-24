#!/bin/bash

# An example of a firewall configuration script for a Linux server.
# Order of rules is important.
# Flush existing rules
iptables -F
iptables -X
iptables -Z

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Ingress and egress filtering 
iptables -A INPUT -j LOG --log-prefix "Ingress: "
iptables -A OUTPUT -j LOG --log-prefix "Egress: "

# Block bad servers inbound mail
# Listed bad servers (example IPs: 192.0.2.1, 203.0.113.5)
bad_servers=("192.0.2.1" "203.0.113.5")
for server in "${bad_servers[@]}"; do
  iptables -A INPUT -s "$server" -p tcp --dport 25 -j DROP
done

# Allow localhost traffic
iptables -A INPUT -i lo -j ACCEPT

# Allow established and related incoming connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow incoming POP3, IMAP and SMTP
iptables -A INPUT -p tcp --dport 110 -j ACCEPT  
iptables -A INPUT -p tcp --dport 995 -j ACCEPT  
iptables -A INPUT -p tcp --dport 143 -j ACCEPT  
iptables -A INPUT -p tcp --dport 993 -j ACCEPT 
# SMTP mail out from us, responses to us
iptables -A OUTPUT -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 25 -m state --state NEW -j DROP
iptables -A INPUT -p tcp --dport 587 -j ACCEPT 
iptables -A INPUT -p tcp --dport 465 -j ACCEPT  

# Allow incoming SSH (secure shell) connections
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow incoming HTTP and HTTPS 
iptables -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Allow DNS queries from us And DNS responses to us
iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --sport 53 -m state --state NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 53 -m state --state NEW -j ACCEPT


# Allow incoming ping (ICMP echo request)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT  # Allow pings to us
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT   # Allow our ping responses
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT # Allow our pings out
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT    # Allow responses

# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Save the rules
iptables-save > /etc/iptables/rules.v4

echo "Firewall rules configured successfully."
