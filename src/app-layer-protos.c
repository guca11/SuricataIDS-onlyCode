/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "app-layer-protos.h"

typedef struct AppProtoStringTuple {
    AppProto alproto;
    const char *str;
} AppProtoStringTuple;

const AppProtoStringTuple AppProtoStrings[ALPROTO_MAX] = {
    { ALPROTO_UNKNOWN, "unknown" },
#if ENABLE_HTTP
    { ALPROTO_HTTP, "http" },
    { ALPROTO_HTTP1, "http1" },
    { ALPROTO_HTTP2, "http2" },    
#endif
#if ENABLE_FTP    
    { ALPROTO_FTP, "ftp" },
    { ALPROTO_FTPDATA, "ftp-data" },
#endif
#if ENABLE_SMTP
    { ALPROTO_SMTP, "smtp" },
#endif
#if ENABLE_TLS
    { ALPROTO_TLS, "tls" },
#endif
#if ENABLE_SSH    
    { ALPROTO_SSH, "ssh" },
#endif
#if ENABLE_IMAP
    { ALPROTO_IMAP, "imap" },
#endif
    { ALPROTO_JABBER, "jabber" },
#if ENABLE_SMB    
    { ALPROTO_SMB, "smb" },
#endif
//    { ALPROTO_DCERPC, "dcerpc" },
    { ALPROTO_IRC, "irc" },
#if ENABLE_DNS    
    { ALPROTO_DNS, "dns" },
#endif
//    { ALPROTO_MODBUS, "modbus" },
//    { ALPROTO_ENIP, "enip" },
//    { ALPROTO_DNP3, "dnp3" },
//    { ALPROTO_NFS, "nfs" },
#if ENABLE_NTP
    { ALPROTO_NTP, "ntp" },
#endif
//    { ALPROTO_TFTP, "tftp" },
//    { ALPROTO_IKE, "ike" },
#if ENABLE_KRB5
    { ALPROTO_KRB5, "krb5" },
#endif
//    { ALPROTO_QUIC, "quic" },
#if ENABLE_DHCP
    { ALPROTO_DHCP, "dhcp" },
#endif
#if ENABLE_SNMP    
    { ALPROTO_SNMP, "snmp" },
#endif
//    { ALPROTO_SIP, "sip" },
//    { ALPROTO_RFB, "rfb" },
#if ENABLE_MQTT
    { ALPROTO_MQTT, "mqtt" },
#endif
//    { ALPROTO_PGSQL, "pgsql" },
#if ENABLE_TELNET
    { ALPROTO_TELNET, "telnet" },
#endif
#if ENABLE_WEBSOCKET
    { ALPROTO_WEBSOCKET, "websocket" },
#endif
#if ENABLE_LDAP    
    { ALPROTO_LDAP, "ldap" },
#endif
#if ENABLE_DNS && ENABLE_HTTP
    { ALPROTO_DOH2, "doh2" },
#endif
    { ALPROTO_TEMPLATE, "template" },
#if ENABLE_RDP
    { ALPROTO_RDP, "rdp" },
#endif
#if ENABLE_BITTORRENT    
    { ALPROTO_BITTORRENT_DHT, "bittorrent-dht" },
#endif
#if ENABLE_POP3
    { ALPROTO_POP3, "pop3" },
#endif
    { ALPROTO_FAILED, "failed" },
#ifdef UNITTESTS
    { ALPROTO_TEST, "test" },
#endif
};

const char *AppProtoToString(AppProto alproto)
{
    const char *proto_name = NULL;
    #if ENABLE_HTTP
    switch (alproto) {
        // special cases
        case ALPROTO_HTTP1:
            proto_name = "http";
            break;
        case ALPROTO_HTTP:
            proto_name = "http_any";
            break;
        default:
            if (alproto < ARRAY_SIZE(AppProtoStrings)) {
                BUG_ON(AppProtoStrings[alproto].alproto != alproto);
                proto_name = AppProtoStrings[alproto].str;
            }
    }
    #else
    if (alproto < ARRAY_SIZE(AppProtoStrings)) {
    	BUG_ON(AppProtoStrings[alproto].alproto != alproto);
        proto_name = AppProtoStrings[alproto].str;
    }
    #endif
    return proto_name;
}

AppProto StringToAppProto(const char *proto_name)
{
    if (proto_name == NULL)
        return ALPROTO_UNKNOWN;

    // We could use a Multi Pattern Matcher
    for (size_t i = 0; i < ARRAY_SIZE(AppProtoStrings); i++) {
        if (strcmp(proto_name, AppProtoStrings[i].str) == 0)
            return AppProtoStrings[i].alproto;
    }

    return ALPROTO_UNKNOWN;
}
