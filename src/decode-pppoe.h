/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author James Riden <jamesr@europe.com>
 */

#ifndef SURICATA_DECODE_PPPOE_H
#define SURICATA_DECODE_PPPOE_H

// Session header length minus the protocol field
#define PPPOE_SESSION_HEADER_MIN_LEN     7
#define PPPOE_DISCOVERY_HEADER_MIN_LEN 6
#define PPPOE_SESSION_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_SESSION_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)
#define PPPOE_DISCOVERY_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_DISCOVERY_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)

typedef struct PPPOESessionHdr_
{
    uint8_t pppoe_version_type;
    uint8_t pppoe_code;
    uint16_t session_id;
    uint16_t pppoe_length;
    uint16_t protocol;
} PPPOESessionHdr;

typedef struct PPPOEDiscoveryTag_
{
    uint16_t pppoe_tag_type;
    uint16_t pppoe_tag_length;
} __attribute__((__packed__)) PPPOEDiscoveryTag;

typedef struct PPPOEDiscoveryHdr_
{
    uint8_t pppoe_version_type;
    uint8_t pppoe_code;
    uint16_t discovery_id;
    uint16_t pppoe_length;
} __attribute__((__packed__)) PPPOEDiscoveryHdr;

/* see RFC 2516 - discovery codes */
#define PPPOE_CODE_PADI 0x09
#define PPPOE_CODE_PADO 0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7

/* see RFC 2516 Appendix A */
#define PPPOE_TAG_END_OF_LIST         0x0000 /* End-Of-List */
#define PPPOE_TAG_SERVICE_NAME        0x0101 /* Service-Name */
#define PPPOE_TAG_AC_NAME             0x0102 /* AC-Name */
#define PPPOE_TAG_HOST_UNIQ           0x0103 /* Host-Uniq */
#define PPPOE_TAG_AC_COOKIE           0x0104 /* AC-Cookie */
#define PPPOE_TAG_VENDOR_SPECIFIC     0x0105 /* Vendor-Specific */
#define PPPOE_TAG_RELAY_SESSION_ID    0x0110 /* Relay-Session-Id */
#define PPPOE_TAG_SERVICE_NAME_ERROR  0x0201 /* Service-Name-Error */
#define PPPOE_TAG_AC_SYS_ERROR        0x0202 /* AC-System Error */
#define PPPOE_TAG_GEN_ERROR           0x0203 /* Generic-Error */

void DecodePPPOERegisterTests(void);

#endif /* SURICATA_DECODE_PPPOE_H */

#define PPP_IP         0x0021       /* Internet Protocol */
#define PPP_IPV6       0x0057       /* Internet Protocol version 6 */
#define PPP_VJ_UCOMP   0x002f       /* VJ uncompressed TCP/IP */
#define PPP_IPX        0x002b       /* Novell IPX Protocol */
#define PPP_VJ_COMP    0x002d       /* VJ compressed TCP/IP */
#define PPP_OSI        0x0023       /* OSI Network Layer */
#define PPP_NS         0x0025       /* Xerox NS IDP */
#define PPP_DECNET     0x0027       /* DECnet Phase IV */
#define PPP_APPLE      0x0029       /* Appletalk */
#define PPP_BRPDU      0x0031       /* Bridging PDU */
#define PPP_STII       0x0033       /* Stream Protocol (ST-II) */
#define PPP_VINES      0x0035       /* Banyan Vines */
#define PPP_HELLO      0x0201       /* 802.1d Hello Packets */
#define PPP_LUXCOM     0x0231       /* Luxcom */
#define PPP_SNS        0x0233       /* Sigma Network Systems */
#define PPP_MPLS_UCAST 0x0281       /* rfc 3032 */
#define PPP_MPLS_MCAST 0x0283       /* rfc 3022 */
#define PPP_IPCP       0x8021       /* IP Control Protocol */
#define PPP_OSICP      0x8023       /* OSI Network Layer Control Protocol */
#define PPP_NSCP       0x8025       /* Xerox NS IDP Control Protocol */
#define PPP_DECNETCP   0x8027       /* DECnet Control Protocol */
#define PPP_APPLECP    0x8029       /* Appletalk Control Protocol */
#define PPP_IPXCP      0x802b       /* Novell IPX Control Protocol */
#define PPP_STIICP     0x8033       /* Stream Protocol Control Protocol */
#define PPP_VINESCP    0x8035       /* Banyan Vines Control Protocol */
#define PPP_IPV6CP     0x8057       /* IPv6 Control Protocol */
#define PPP_MPLSCP     0x8281       /* rfc 3022 */
#define PPP_LCP        0xc021       /* Link Control Protocol */
#define PPP_PAP        0xc023       /* Password Authentication Protocol */
#define PPP_LQM        0xc025       /* Link Quality Monitoring */
#define PPP_CHAP       0xc223       /* Challenge Handshake Authentication Protocol */

