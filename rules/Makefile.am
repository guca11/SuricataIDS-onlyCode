ruledir = $(datadir)/suricata/rules

dist_rule_DATA = \
app-layer-events.rules \
decoder-events.rules \
files.rules \
ipsec-events.rules \
stream-events.rules

if ENABLE_MQTT
dist_rule_DATA += mqtt-events.rules
endif	

if ENABLE_NTP
dist_rule_DATA += ntp-events.rules 
endif	

if ENABLE_SMTP
dist_rule_DATA += smtp-events.rules
endif

if ENABLE_KRB5
dist_rule_DATA += kerberos-events.rules
endif

if ENABLE_SMB
dist_rule_DATA += smb-events.rules
endif

if ENABLE_FTP
dist_rule_DATA += ftp-events.rules
endif

if ENABLE_SSH
dist_rule_DATA += ssh-events.rules 
endif

if ENABLE_WEBSOCKET
dist_rule_DATA += websocket-events.rules
endif

if ENABLE_PPPOE
dist_rule_DATA += decoder-events-pppoe.rules 
endif 

if ENABLE_DHCP
dist_rule_DATA += dhcp-events.rules
endif

if ENABLE_DNS
dist_rule_DATA += dns-events.rules
endif

if ENABLE_TLS
dist_rule_DATA += tls-events.rules
endif

if ENABLE_HTTP
dist_rule_DATA += http-events.rules 
dist_rule_DATA += http2-events.rules
endif 

if ENABLE_RAW
dist_rule_DATA += decoder-events-raw.rules 
endif

if ENABLE_IPV6
dist_rule_DATA += decoder-events-ipv6.rules 
endif

if ENABLE_UDP
dist_rule_DATA += decoder-events-udp.rules 
endif

if ENABLE_TCP
dist_rule_DATA += decoder-events-tcp.rules 
endif

# REMOVED PROTOCOLS RULES

# DNP3
# dnp3-events.rules

# ENIP
# enip-events.rules

# MODBUS
# modbus-events.rules

# NFS
# nfs-events.rules 

# QUIC
# quic-events.rules 

# RFB
# rfb-events.rules 
