/*
 * procutils.h
 *
 *  Created on: 24.01.2012
 *      Author: jan
 */

#ifndef PROCUTILS_H_
#define PROCUTILS_H_

int sockfd2process(struct packet_info *pinfo, int sockfd);
int address2sockfd(struct packet_info *pinfo);

#endif /* PROCUTILS_H_ */