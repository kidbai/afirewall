/*
 * packetinfo.h
 *
 *  Created on: 06.12.2011
 *      Author: jan
 */

#ifndef PACKETINFO_H_
#define PACKETINFO_H_

#include <libnetfilter_queue/libnetfilter_queue.h>	/* nlif_* and nfq_* structs */

#define PACKETINFO_CMDLEN 256
#define PACKETINFO_ADDRLEN 64
#define PACKETINFO_DEVLEN IFNAMSIZ
#define PACKETINFO_PAYLOAD 0xFFFFU

#define PACKETINFO_RAW_ADDRLEN	16

#if PACKETINFO_ADDRLEN < 40
#warning address length must be at least 40 to capture IPv6 addresses
#endif

/* Transport-layer protocols we can decode */
enum transport_header_types {
	TCP,
	UDP,
	UNKNOWN_TRANSPORT_TYPE
};

/* Network-layer protocols we can decode */
enum network_header_types {
	IP,
	IP6,
	ICMP,	/* to be done */
	ICMP6,	/* to be done */
	UNKNOWN_NET_TYPE
};

typedef struct raw_data_t {
	char	local_addr[PACKETINFO_RAW_ADDRLEN];
	char	remote_addr[PACKETINFO_RAW_ADDRLEN];
} raw_data_t;

struct packet_info {
	/* ID and command-line of the process owning the socket */
	char  	process_cmd[PACKETINFO_CMDLEN];
	int		process_id;

	/* addresses and ports; only set when the underlying protocols support them */
	char	local_addr[PACKETINFO_ADDRLEN];
	int		local_port;
	char  	remote_addr[PACKETINFO_ADDRLEN];	/* enough to hold an ipv6 address */
	int 	remote_port;

	/* name of the interface the packet is going through */
	char	interface[PACKETINFO_DEVLEN];

	/* transport-layer protocol type */
	enum transport_header_types transport_header_type;

	/* network-layer protocol type */
	enum network_header_types network_header_type;

	raw_data_t	_raw;
};

/* fetch information on a packet */
void pi_get(struct packet_info *pinfo, struct nlif_handle *nlif, struct nfq_data *tb);

/* print packet information to stdout */
void pi_print(struct packet_info *pinfo);

#endif /* PACKETINFO_H_ */
