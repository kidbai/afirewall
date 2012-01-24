/*
 * packetinfo.c
 *
 *  Created on: 06.12.2011
 *      Author: jan
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include "packetinfo.h"
#include "procutils.h"

/* IANA IP protocol numbers, see RFC 5137 -> http://www.iana.org/go/rfc5237 */
#define IP_PROTOCOL_UDP (0x11)
#define IP_PROTOCOL_TCP (0x06)

/**
 * Helper function to convert transport header type enum constants to strings.
 */
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

/**
 * Helper function to convert network header type enum constants to strings.
 */
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

/**
 * Retrieves the name of the network interface the packet is leaving on and
 * writes it in the packet info structure.
 */
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

/**
 * Retrieves the local and remote port numbers from the TCP header.
 * The parameter payload must point to the first byte of the TCP header.
 */
static void decode_tcp(char *payload, struct packet_info *pinfo) {
	/* Remote and local port numbers are unsigned 16 bit values, residing
	 * on bytes 0-1 (local) and bytes 2-3 (remote) in network byte order.
	 */
	pinfo->local_port = ntohs(*(unsigned short*) &payload[0]);
	pinfo->remote_port = ntohs(*(unsigned short*) &payload[2]);


}

/**
 * Retrieves the local and remote port numbers from the UDP header.
 * The parameter payload must point to the first byte of the UDP header.
 */
static void decode_udp(char *payload, struct packet_info *pinfo) {
	/* Remote and local port numbers are unsigned 16 bit values, residing
	 * on bytes 0-1 (local) and bytes 2-3 (remote) in network byte order.
	 */
	pinfo->local_port = ntohs(*(unsigned short*) &payload[0]);
	pinfo->remote_port = ntohs(*(unsigned short*) &payload[2]);

}

/**
 * Converts an IP address in binary representation to a human-readable string
 * representation.
 */
static void format_ip_address(char *dest, unsigned int dest_len,
		char *src, enum network_header_types type) {

	if(dest_len < PACKETINFO_ADDRLEN) {
		fprintf(stderr, "ip destination buffer not large enough\n");
		exit(1);
	}

	switch(type) {
	case IP:
		sprintf(dest, "%u.%u.%u.%u", src[0]&0xff,src[1]&0xff,src[2]&0xff,src[3]&0xff);
		break;
	case IP6:
		/* each 16-bit value is stored in network byte order -> need to swap it */
		sprintf(dest, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
				ntohs(*(uint16_t*) &dest[0]), ntohs(*(uint16_t*) &dest[2]),
				ntohs(*(uint16_t*) &dest[4]), ntohs(*(uint16_t*) &dest[6]),
				ntohs(*(uint16_t*) &dest[8]), ntohs(*(uint16_t*) &dest[10]),
				ntohs(*(uint16_t*) &dest[12]), ntohs(*(uint16_t*) &dest[14]));
	default:
		sprintf(dest, "(unknown)");
	}

	/* just in case... */
	dest[PACKETINFO_ADDRLEN-1] = '\0';
}

/**
 * Extracts local and remote IP addresses from an IPv4 header the
 * payload parameter points to. If the IP payload contains a known header format
 * like TCP or UDP, relevant information is extracted, too.
 */
static void decode_ip(char *payload, struct packet_info *pinfo) {
	uint16_t start_of_ip_payload = 0;
	uint8_t next_proto;

	/* header length is lower 4 bits, encoding the number of 32bit words */
	start_of_ip_payload = (payload[0]&0x0F) << 2;

	/* make addresses human-readable.
	 * Addresses reside on bytes 12-15 (local) and 16-19 (remote), each 32 bit,
	 * segment-wise.
	 */
	format_ip_address(pinfo->local_addr, PACKETINFO_ADDRLEN, &payload[12], IP);
	format_ip_address(pinfo->remote_addr, PACKETINFO_ADDRLEN, &payload[16], IP);
	memcpy(pinfo->_raw.local_addr, &payload[12], 4);
	memcpy(pinfo->_raw.remote_addr, &payload[16], 4);

	/* get information on next header type, 8bit on offset 9, and continue
	 * with extracting information from transport layer protocols. These
	 * protocol decoders need the IP header stripped off. */
	next_proto = payload[9];
	switch(next_proto) {
	case IP_PROTOCOL_UDP:
		pinfo->transport_header_type = UDP;
		decode_udp(&payload[start_of_ip_payload], pinfo);
		break;
	case IP_PROTOCOL_TCP:
		pinfo->transport_header_type = TCP;
		decode_tcp(&payload[start_of_ip_payload], pinfo);
		break;
	default:
		pinfo->transport_header_type = UNKNOWN_TRANSPORT_TYPE;
	}
}

static void decode_ip6(char *payload, struct packet_info *pinfo) {
	// TODO: eventually handle extension headers
	const uint16_t start_of_ip_payload = 40;	// IP6 has a fixed header length of 40 bytes
	uint8_t next_proto;

	/* make addresses human-readable.
	 * Addresses reside on bytes 8-23 (local) and 24-39 (remote), each 128 bit,
	 * stored 16-bit wise in network byte order.
	 */
	format_ip_address(pinfo->local_addr, PACKETINFO_ADDRLEN, &payload[8], IP6);
	format_ip_address(pinfo->remote_addr, PACKETINFO_ADDRLEN, &payload[24], IP6);
	memcpy(pinfo->_raw.local_addr, &payload[8], 16);
	memcpy(pinfo->_raw.remote_addr, &payload[24], 16);

	/* get information on next header type, 8bit on offset 6, and continue
	 * with extracting information from transport layer protocols. These
	 * protocol decoders need the IP header stripped off. */
	next_proto = payload[6];
	switch(next_proto) {
	case IP_PROTOCOL_UDP:
		pinfo->transport_header_type = UDP;
		decode_udp(&payload[start_of_ip_payload], pinfo);
		break;
	case IP_PROTOCOL_TCP:
		pinfo->transport_header_type = TCP;
		decode_tcp(&payload[start_of_ip_payload], pinfo);
		break;
	default:
		pinfo->transport_header_type = UNKNOWN_TRANSPORT_TYPE;
	}
}

/**
 * Decodes the payload and tries to find network-level and transport-level
 * headers to gather information from.
 */
static void decode_packet(char *payload, struct packet_info *pinfo) {

	/* IP version is encoded in the upper 4 bits in the first byte */
	uint8_t ip_version = (payload[0] >> 4) & 0x0F;

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

/**
 * Extracts packet information from a given packet handle
 */
void pi_get(struct packet_info *pinfo, struct nlif_handle *nlif, struct nfq_data *tb) {
	char *payload;

	// set output interface
	set_outdev(pinfo, nlif, tb);

	nfq_get_payload(tb, &payload);
	decode_packet(payload, pinfo);
}

/**
 * Prints packet information to stdout
 */
void pi_print(struct packet_info *pinfo) {
	const char *trans, *net;

	/* make human-readable forms of header types */
	trans = pi_transport_hdr_type2string(pinfo->transport_header_type);
	net = pi_network_hdr_type2string(pinfo->network_header_type);

	/* IPv4 and IPv6 have different address formats, so act according
	 * to IP version.
	 */
	switch(pinfo->network_header_type) {
	case IP:
		printf("outgoing packet: interface: %s network: IP transport: %s source: %s:%u destination: %s:%u\n",
				pinfo->interface, trans,
				pinfo->local_addr, pinfo->local_port, pinfo->remote_addr, pinfo->remote_port);
		int inode = address2sockfd(pinfo);
		printf("inode: %d\n", inode);
		break;
	case IP6:
		printf("outgoing packet: interface: %s network: IP6 transport: %s source: [%s]:%u destination: [%s]:%u\n",
				pinfo->interface, trans,
				pinfo->local_addr, pinfo->local_port, pinfo->remote_addr, pinfo->remote_port);
		break;
	default:
		printf("outgoing packet: interface: %s network: %s transport: %s\n",
				pinfo->interface, net, trans);
	}

}
