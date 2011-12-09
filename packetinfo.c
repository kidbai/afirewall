/*
 * packetinfo.c
 *
 *  Created on: 06.12.2011
 *      Author: jan
 */
#define DEBUG

#ifdef DEBUG
#include <stdio.h>
#endif

#include <string.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include "packetinfo.h"

#define IP_PROTOCOL_UDP (0x11)
#define IP_PROTOCOL_TCP (0x06)

const char *pi_transport_hdr_type2string(enum transport_header_types t) {
	const char *text;

	switch(t) {
		case TCP: text = "TCP"; break;
		case UDP: text = "UDP"; break;
		case UNKNOWN_TRANSPORT_TYPE:
		default:
			text = "(unknown)";
	}
	return text;
}

const char *pi_network_hdr_type2string(enum network_header_types t) {
	const char *text;

	switch(t) {
		case IP: text = "IP"; break;
		case IP6: text = "IP6"; break;
		case UNKNOWN_NET_TYPE:
		default:
			text = "(unknown)";
	}
	return text;
}

static void set_outdev(struct packet_info *pinfo, struct nlif_handle *nlif, struct nfq_data *tb) {
	uint32_t ret;

	ret = nfq_get_outdev(tb);
	if(ret) {
		nfq_get_outdev_name(nlif, tb, pinfo->interface);
	} else {
		strncpy(pinfo->interface, "(unknown)", PACKETINFO_DEVLEN);
		pinfo->interface[PACKETINFO_DEVLEN-1] = '\0';
	}
}

static void decode_tcp(char *payload, struct packet_info *pinfo) {
	uint16_t sport;
	uint16_t dport;

	sport = ntohs(*(unsigned short*) &payload[0]);
	dport = ntohs(*(unsigned short*) &payload[2]);

	pinfo->remote_port = dport;
	pinfo->local_port = sport;

#ifdef DEBUG
	printf("DEBUG %s:%d> transport: TCP; sport: %u, dport: %u\n",
			__FILE__, __LINE__, sport, dport);
#endif
}

static void decode_udp(char *payload, struct packet_info *pinfo) {
	uint16_t sport;
	uint16_t dport;


	sport = ntohs(*(unsigned short*) &payload[0]);
	dport = ntohs(*(unsigned short*) &payload[2]);

	pinfo->remote_port = dport;
	pinfo->local_port = sport;

#ifdef DEBUG
	printf("DEBUG %s:%d> transport: UDP; sport: %u, dport: %u\n",
			__FILE__, __LINE__, sport, dport);
#endif

}

static void decode_ip(char *payload, struct packet_info *pinfo) {
	uint16_t start_of_ip_payload = 0;
	uint8_t next_proto;

	// header length is at payload[2], length 16 bits
	start_of_ip_payload = htons(*(unsigned short*)&payload[2]);

	// length is in 32bit words. Translate to bytes
	start_of_ip_payload >>= 4;

	// TODO: add local and remote addresses
#ifdef DEBUG
	printf("DEBUG %s:%d> network: IP\n",
			__FILE__, __LINE__);
#endif

	next_proto = payload[9];
	switch(next_proto) {
	case IP_PROTOCOL_UDP:	decode_udp(payload, pinfo); break;
	case IP_PROTOCOL_TCP:	decode_tcp(payload, pinfo); break;
	default:
		pinfo->transport_header_type = UNKNOWN_TRANSPORT_TYPE;
	}
}

static void decode_ip6(char *payload, struct packet_info *pinfo) {
	// TODO: handle extension headers
	uint16_t start_of_ip_payload = 40;	// IP6 has a fixed header length of 40 bytes
	uint8_t next_proto;

#ifdef DEBUG
	printf("DEBUG %s:%d> network: IP6\n",
			__FILE__, __LINE__);
#endif


	// TODO: add local and remote addresses
	next_proto = payload[6];
	switch(next_proto) {
	case IP_PROTOCOL_UDP:	decode_udp(&payload[start_of_ip_payload], pinfo); break;
	case IP_PROTOCOL_TCP:	decode_tcp(&payload[start_of_ip_payload], pinfo); break;
	default:
		pinfo->transport_header_type = UNKNOWN_TRANSPORT_TYPE;
	}
}

static void decode_packet(char *payload, struct packet_info *pinfo) {

	uint8_t ip_version = (payload[0] >> 4) & 0x07;	// select upper 4 bits

	switch(ip_version) {
	case 4:
		pinfo->transport_header_type = IP;
		decode_ip(payload, pinfo);
		break;
	case 6:
		pinfo->transport_header_type = IP6;
		decode_ip6(payload, pinfo);
		break;
	default:
		pinfo->network_header_type = UNKNOWN_NET_TYPE;
		pinfo->transport_header_type = UNKNOWN_TRANSPORT_TYPE;
	}
}

void pi_get(struct packet_info *pinfo, struct nlif_handle *nlif, struct nfq_data *tb) {
	char *payload;

	// set output interface
	set_outdev(pinfo, nlif, tb);

	nfq_get_payload(tb, &payload);
	decode_packet(payload, pinfo);
}

void pi_print(struct packet_info *pinfo) {
	const char *trans, *net;

	trans = pi_transport_hdr_type2string(pinfo->transport_header_type);
	net = pi_network_hdr_type2string(pinfo->network_header_type);

	printf("packet: interface: %s transport: %s network: %s source port: %u dest port: %u\n",
			pinfo->interface, trans, net, pinfo->local_port, pinfo->remote_port);

}
