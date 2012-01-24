/**
 * Needs libnetfilter-queue-dev on Debian.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "packetinfo.h"

/* will be called when a packet enters the netfilter queue */
static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data) {
	static struct nlif_handle *nlif;
	static struct packet_info pinfo;
	static struct nfqnl_msg_packet_hdr *ph;

	u_int32_t id = 0;

	/* query network interface information */
	if(!nlif) {
		nlif = nlif_open();
		if(!nlif) {
			perror("nlif_open");
			exit(EXIT_FAILURE);
		}
		nlif_query(nlif);
	}

	/* retrieve packet id for verdict */
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	/* get packet information and print it */
	pi_get(&pinfo, nlif, nfa);
	pi_print(&pinfo);

	/* accept... */
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
	struct nfq_handle *h;		/* NFQ handle */
	struct nfq_q_handle *qh;	/* queue handle */
	int fd;						/* file handle for talking with NFQ API */
	int rv;						/* return value buffer for recv() call */

	/* packet buffer.
	 * Needs special alignedness for kernel<->userspace interaction (?) */
	char buf[4096] __attribute__ ((aligned));

	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	qh = nfq_create_queue(h, 0, &packet_callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	/* need to copy whole packet to buffer because we need to look into the
	 * protocol headers.
	 */
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, PACKETINFO_PAYLOAD) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	/* talk to the NFQ API via fd */
	fd = nfq_fd(h);

	/* main loop for packet handling. Calls callback for every packet */
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	/* clean up. BTW, we'll probably never reach this */
	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}
