/*
 *  Copyright (c) 2014-2021, Peter Haag
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be
 *	 used to endorse or promote products derived from this software without
 *	 specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_FEATURES_H
#include <features.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "util.h"
#include "nfdump.h"
#include "nffile.h"
#include "bookkeeper.h"
#include "collector.h"
#include "flowtree.h"
#include "ipfrag.h"
#include "pcaproc.h"
#include "netflow_pcap.h"

struct pcap_timeval {
	int32_t tv_sec;   /* seconds */
	int32_t tv_usec;  /* microseconds */
};

struct pcap_sf_pkthdr {
	struct pcap_timeval ts; /* time stamp */
	uint32_t	caplen;	    /* length of portion present */
	uint32_t	len;        /* length this packet (off wire) */
};

typedef struct vlan_hdr_s {
  uint16_t vlan_id;
  uint16_t type;
} vlan_hdr_t;

typedef struct gre_hdr_s {
  uint16_t flags;
  uint16_t type;
} gre_hdr_t;

static inline void ProcessTCPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessUDPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessICMPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessOtherFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

pcapfile_t *OpenNewPcapFile(pcap_t *p, char *filename, pcapfile_t *pcapfile) {

	if ( !pcapfile ) {
		// Create struct
		pcapfile = calloc(1, sizeof(pcapfile_t));
		if ( !pcapfile ) {
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pthread_mutex_init(&pcapfile->m_pbuff, NULL);
		pthread_cond_init(&pcapfile->c_pbuff, NULL);

		pcapfile->data_buffer = malloc(BUFFSIZE);
		if ( !pcapfile->data_buffer ) {
			free(pcapfile);
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pcapfile->alternate_buffer = malloc(BUFFSIZE);
		if ( !pcapfile->data_buffer ) {
			free(pcapfile->data_buffer);
			free(pcapfile);
			LogError("malloc() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pcapfile->data_ptr		 = pcapfile->data_buffer;
		pcapfile->data_size 	 = 0;
		pcapfile->alternate_size = 0;
		pcapfile->p 			 = p;
	}

	if ( filename ) {
		FILE* pFile = fopen(filename, "wb"); 
		if ( !pFile ) {
			LogError("fopen() error in %s line %d: %s", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pcapfile->pd = pcap_dump_fopen(p, pFile);
		if ( !pcapfile->pd ) {
			LogError("Fatal: pcap_dump_open() failed for file '%s': %s", filename, pcap_geterr(p));
			return NULL;
		} else {
			fflush(pFile);
			pcapfile->pfd = fileno((FILE *)pFile);
			return pcapfile;
		}
	} else
		return pcapfile;

} // End of OpenNewPcapFile

int ClosePcapFile(pcapfile_t *pcapfile) {
int err = 0;

	pcap_dump_close(pcapfile->pd);
	pcapfile->pfd = -1;

	return err;

} // End of ClosePcapFile

void RotateFile(pcapfile_t *pcapfile, time_t t_CloseRename, int live) {
struct pcap_stat p_stat;
void *_b;

	dbg_printf("RotateFile() time: %s\n", UNIX2ISO(t_CloseRename));
	// make sure, alternate buffer is already flushed
   	pthread_mutex_lock(&pcapfile->m_pbuff);
   	while ( pcapfile->alternate_size ) {
	   	pthread_cond_wait(&pcapfile->c_pbuff, &pcapfile->m_pbuff);
   	}

	// swap buffers
	_b = pcapfile->data_buffer;
	pcapfile->data_buffer 	   = pcapfile->alternate_buffer;
	pcapfile->data_ptr		   = pcapfile->data_buffer;
	pcapfile->alternate_buffer = _b;
	pcapfile->alternate_size   = pcapfile->data_size;
	pcapfile->t_CloseRename	= t_CloseRename;

	// release mutex and signal thread
 	pthread_mutex_unlock(&pcapfile->m_pbuff);
	pthread_cond_signal(&pcapfile->c_pbuff);

	pcapfile->data_size		 = 0;

	if ( live ) {
		// not a capture file
		if( pcap_stats(pcapfile->p, &p_stat) < 0) {
			LogError("pcap_stats() failed: %s", pcap_geterr(pcapfile->p));
		} else {
			LogInfo("Packets received: %u, dropped: %u, dropped by interface: %u ",
				p_stat.ps_recv, p_stat.ps_drop, p_stat.ps_ifdrop );
		}
	}

} // End of RotateFile

void PcapDump(pcapfile_t *pcapfile,  struct pcap_pkthdr *h, const u_char *sp) {
struct pcap_sf_pkthdr sf_hdr;
size_t	size = sizeof(struct pcap_sf_pkthdr) + h->caplen;

	if ( (pcapfile->data_size + size ) > BUFFSIZE ) {
		void *_b;
		// no space left in buffer - rotate buffers
		dbg_printf("PcapDump() cycle buffers: size: %u\n", pcapfile->data_size);
		// make sure, alternate buffer is flushed
		pthread_mutex_lock(&pcapfile->m_pbuff);
		while ( pcapfile->alternate_size ) {
			pthread_cond_wait(&pcapfile->c_pbuff, &pcapfile->m_pbuff);
		}

		// swap buffers
		_b = pcapfile->data_buffer;
		pcapfile->data_buffer 	   = pcapfile->alternate_buffer;
		pcapfile->data_ptr		   = pcapfile->data_buffer;
		pcapfile->alternate_buffer = _b;
		pcapfile->alternate_size   = pcapfile->data_size;
		pcapfile->t_CloseRename	= 0;

		// release mutex and signal thread
 		pthread_mutex_unlock(&pcapfile->m_pbuff);
		pthread_cond_signal(&pcapfile->c_pbuff);

		pcapfile->data_size		 = 0;
	}

	sf_hdr.ts.tv_sec  = h->ts.tv_sec;
	sf_hdr.ts.tv_usec = h->ts.tv_usec;
	sf_hdr.caplen	 = h->caplen;
	sf_hdr.len		= h->len;

	memcpy(pcapfile->data_ptr, (void *)&sf_hdr, sizeof(sf_hdr));
	pcapfile->data_ptr += sizeof(struct pcap_sf_pkthdr);
	memcpy(pcapfile->data_ptr, (void *)sp, h->caplen);
	pcapfile->data_ptr += h->caplen;
	pcapfile->data_size	 += (sizeof(struct pcap_sf_pkthdr) + h->caplen);

} // End of PcapDump

static inline void ProcessTCPFlow(FlowSource_t *fs, struct FlowNode *NewNode ) {
struct FlowNode *Node;

	assert(NewNode->memflag == NODE_IN_USE);
	Node = Insert_Node(NewNode);
	// Return existing Node if flow exists already, otherwise insert es new
	if ( Node == NULL ) {
		// Insert as new
		dbg_printf("New TCP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);

		// in case it's a FIN/RST only packet - immediately flush it
		if ( NewNode->fin == FIN_NODE  ) {
			// flush node
			if ( StorePcapFlow(fs, NewNode) ) {
				Remove_Node(NewNode);
			}
		}

		if ( Link_RevNode(NewNode)) {
			// if we could link this new node, it is the server answer
			// -> calculate server latency
			SetServer_latency(NewNode);
		}
		return;
	}

	assert(Node->memflag == NODE_IN_USE);

	// check for first client ACK for client latency
	if ( Node->latency.flag == 1 ) {
		SetClient_latency(Node, &(NewNode->t_first));
	} else if ( Node->latency.flag == 2 ) {
		SetApplication_latency(Node, &(NewNode->t_first));
	}
	// update existing flow
	Node->flags |= NewNode->flags;
	Node->packets++;
	Node->bytes += NewNode->bytes;
	Node->t_last = NewNode->t_last;
	dbg_printf("Existing TCP flow: Packets: %u, Bytes: %u\n", Node->packets, Node->bytes);

	if ( NewNode->fin == FIN_NODE) {
		// flush node
		Node->fin = FIN_NODE;
		if ( StorePcapFlow(fs, Node) ) {
			Remove_Node(Node);
		}
	} else {
		Free_Node(NewNode);
	}


} // End of ProcessTCPFlow

static inline void ProcessUDPFlow(FlowSource_t	*fs, struct FlowNode *NewNode ) {
struct FlowNode *Node;

	assert(NewNode->memflag == NODE_IN_USE);
	// Flush DNS queries directly
	if ( NewNode->src_port == 53 || NewNode->dst_port == 53 ) {
		StorePcapFlow(fs, NewNode);
		Free_Node(NewNode);
		return;
	}

	// insert other UDP traffic
	Node = Insert_Node(NewNode);
	// if insert fails, the existing node is returned -> flow exists already
	if ( Node == NULL ) {
		dbg_printf("New UDP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);
		return;
	}
	assert(Node->memflag == NODE_IN_USE);

	// update existing flow
	Node->packets++;
	Node->bytes += NewNode->bytes;
	Node->t_last = NewNode->t_last;
	dbg_printf("Existing UDP flow: Packets: %u, Bytes: %u\n", Node->packets, Node->bytes);

	Free_Node(NewNode);

} // End of ProcessUDPFlow

static inline void ProcessICMPFlow(FlowSource_t	*fs, struct FlowNode *NewNode ) {

	// Flush ICMP directly
	StorePcapFlow(fs, NewNode);
	dbg_printf("Flush ICMP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);

	Free_Node(NewNode);

} // End of ProcessICMPFlow

static inline void ProcessOtherFlow(FlowSource_t *fs, struct FlowNode *NewNode ) {
struct FlowNode *Node;

	assert(NewNode->memflag == NODE_IN_USE);

	// insert ESP/AH traffic
	Node = Insert_Node(NewNode);
	// if insert fails, the existing node is returned -> flow exists already
	if ( Node == NULL ) {
		dbg_printf("New flow IP proto: %u. Packets: %u, Bytes: %u\n",
			NewNode->proto, NewNode->packets, NewNode->bytes);
		return;
	}
	assert(Node->memflag == NODE_IN_USE);

	// update existing flow
	Node->packets++;
	Node->bytes += NewNode->bytes;
	Node->t_last = NewNode->t_last;
	dbg_printf("Existing flow IP proto: %u Packets: %u, Bytes: %u\n",
		NewNode->proto, Node->packets, Node->bytes);

	Free_Node(NewNode);

} // End of ProcessOtherFlow


void ProcessFlowNode(FlowSource_t *fs, struct FlowNode *node) {

	switch (node->proto) {
		case IPPROTO_TCP:
			ProcessTCPFlow(fs, node);
			break;
		case IPPROTO_UDP:
			ProcessUDPFlow(fs, node);
			break;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
			ProcessICMPFlow(fs, node);
			break;
		default:
			ProcessOtherFlow(fs, node);
	}

} // End of ProcessFlowNode

void ProcessPacket(NodeList_t *NodeList, pcap_dev_t *pcap_dev, const struct pcap_pkthdr *hdr, const u_char *data) {
struct FlowNode	*Node;
struct ip 	  *ip;
void		  *payload, *defragmented;
uint32_t	  size_ip, offset, data_len, payload_len, bytes;
uint16_t	  version, IPproto;
char		  s1[64];
char		  s2[64];
static unsigned pkg_cnt = 0;

	pkg_cnt++;
	dbg_printf("\nNext Packet: %u\n", pkg_cnt);

	pcap_dev->proc_stat.packets++;
	offset = pcap_dev->linkoffset;
	defragmented = NULL;
	Node = NULL;

	uint16_t protocol = 0;
	switch (pcap_dev->linktype) {
		case DLT_EN10MB:
			protocol = data[12] << 0x08 | data[13];
			int	IEEE802 = protocol <= 1500;
			if ( IEEE802 ) {
				pcap_dev->proc_stat.skipped++;
				return;
			}
			break;
		case DLT_RAW:
			protocol = 0x800;
			break;
		case DLT_PPP: 
			protocol = 0x800;
			break;
		case DLT_PPP_SERIAL:
			protocol = 0x800;
			break;
		case DLT_LOOP: 
		case DLT_NULL: {
			uint32_t header;
			if ( pcap_dev->linktype == DLT_LOOP ) 
				header = ntohl(*((uint32_t *)data));
			else
				header = *((uint32_t *)data);
			switch (header) {
				case 2:
					protocol = 0x800;
					break;
				case 24:
				case 28:
				case 30:
					protocol = 0x86DD;
					break;
				default:
					LogInfo("Unsupported DLT_NULL protocol: 0x%x, packet: %u", header, pkg_cnt);
				return;
			}
			} break;
		case DLT_LINUX_SLL: 
			protocol = data[14] << 8 | data[15];
			break;
		case DLT_IEEE802_11: 
			protocol = 0x800;
			break;
		default:
			LogInfo("Unsupported link type: 0x%x, packet: %u", pcap_dev->linktype, pkg_cnt);
			return;
	}

	REDO_LINK:
		switch (protocol) {
			case 0x800:	 // IPv4
			case 0x86DD: // IPv6
				break;
			case 0x8100: {	// VLAN
				do {
					vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)(data + offset);  // offset points to end of link layer
					dbg_printf("VLAN ID: %u, type: 0x%x\n",
						ntohs(vlan_hdr->vlan_id), ntohs(vlan_hdr->type) );
					protocol = ntohs(vlan_hdr->type);
					offset += 4;
				} while ( protocol == 0x8100 );
		
				// redo protocol evaluation
				goto REDO_LINK;
				} break;
			case 0x8847: { // MPLS
				// unwind MPLS label stack
				uint32_t *mpls = (uint32_t *)(data + offset);
				offset += 4;
				dbg_printf("MPLS label: %x\n", ntohl(*mpls) >> 8);
				while ((offset < hdr->caplen) && ((ntohl(*mpls) & 0x100) == 0)) { // check for Bottom of stack
					offset += 4;
					mpls++;
					dbg_printf("MPLS label: %x\n", ntohl(*mpls) >> 8);
				}
				uint8_t *hdr = (uint8_t *)data + offset;
				if((*hdr >> 4) == 4)
					protocol = 0x0800;	// IPv4
				else if((*hdr >> 4) == 6)
					protocol = 0x86DD;	// IPv6
				else {
					LogInfo("Unsupported protocol: 0x%x", *hdr >> 4);
					goto END_FUNC;
				}

				// redo protocol evaluation
				goto REDO_LINK;
				} break;
			case 0x26:	 // ?? multicast router termination ??
			case 0x32:	
			case 0x806:	 // skip ARP
			case 0x4305: // B.A.T.M.A.N. BATADV
			case 0x886f: // MS NLB heartbeat
			case 0x88a2: // ATA over ethernet
			case 0x88cc: // CISCO LLDP
			case 0x9000: // Loop
			case 0x9003: 
			case 0x8808: // Ethernet flow control
			case 0x880b: // PPP - rfc 7042
			case 0x6558: // Ethernet Bridge
				pcap_dev->proc_stat.skipped++;
				goto END_FUNC;
				break;
			default:
				pcap_dev->proc_stat.unknown++;
				LogInfo("Unsupported ether type: 0x%x, packet: %u", protocol, pkg_cnt);
				goto END_FUNC;
		}

	if (hdr->caplen < offset) {
		pcap_dev->proc_stat.short_snap++;
		LogInfo("Short packet: %u/%u", hdr->caplen, offset);
		goto END_FUNC;
	}

	data	 = data + offset;
	data_len = hdr->caplen - offset;
	offset	 = 0;

	// IP decoding
	REDO_IPPROTO:
	// IP decoding
	if ( defragmented ) {
		// data is sitting on a defragmented IPv4 packet memory region
		// REDO loop could result in a memory leak, if again IP is fragmented
		// XXX memory leak to be fixed
		LogError("Fragmentation memory leak triggered!");
		goto END_FUNC;
	}

	ip  	= (struct ip *)(data + offset); // offset points to end of link layer
	version = ip->ip_v;	 // ip version

	if ( version == 6 ) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *) (data + offset);
		size_ip = sizeof(struct ip6_hdr);
		offset = size_ip;	// offset point to end of IP header

		if ( data_len < size_ip ) {
			LogInfo("Packet: %u Length error: data_len: %u < size IPV6: %u, captured: %u, hdr len: %u",
				pkg_cnt, data_len, size_ip, hdr->caplen, hdr->len);	
			pcap_dev->proc_stat.short_snap++;
			goto END_FUNC;
		}

		// XXX Extension headers not processed
		IPproto		= ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		payload_len = bytes = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);

		if (data_len < (payload_len + size_ip) ) {
			// capture len was limited - so adapt payload_len
			payload_len = data_len - size_ip;
		}

		dbg_printf("Packet IPv6, SRC %s, DST %s, ",
			inet_ntop(AF_INET6, &ip6->ip6_src, s1, sizeof(s1)),
			inet_ntop(AF_INET6, &ip6->ip6_dst, s2, sizeof(s2)));

		payload = (void *)ip + size_ip;

		Node = New_Node();
		if ( !Node ) {
			pcap_dev->proc_stat.skipped++;
			LogError("Node allocation error - skip packet");
			return;
		}
		Node->t_first.tv_sec = hdr->ts.tv_sec;
		Node->t_first.tv_usec = hdr->ts.tv_usec;
		Node->t_last.tv_sec  = hdr->ts.tv_sec;
		Node->t_last.tv_usec  = hdr->ts.tv_usec;

		// keep compiler happy - get's optimized out anyway
		void *p = (void *)&ip6->ip6_src;
		uint64_t *addr = (uint64_t *)p;
		Node->src_addr.v6[0] = ntohll(addr[0]);
		Node->src_addr.v6[1] = ntohll(addr[1]);

		p = (void *)&ip6->ip6_dst;
		addr = (uint64_t *)p;
		Node->dst_addr.v6[0] = ntohll(addr[0]);
		Node->dst_addr.v6[1] = ntohll(addr[1]);
		Node->version = AF_INET6;

	} else if ( version == 4 ) {
		uint16_t ip_off = ntohs(ip->ip_off);
		uint32_t frag_offset = (ip_off & IP_OFFMASK) << 3;
		size_ip = (ip->ip_hl << 2);
		offset = size_ip;	// offset point to end of IP header

		if ( data_len < size_ip ) {
			dbg_printf("Packet: %u Length error: data_len: %u < size IPV4: %u, captured: %u, hdr len: %u\n",
				pkg_cnt, data_len, size_ip, hdr->caplen, hdr->len);	
			pcap_dev->proc_stat.short_snap++;
			goto END_FUNC;
		}

		payload_len = ntohs(ip->ip_len);
		dbg_printf("size IP hader: %u, len: %u\n", size_ip, payload_len);

		payload_len -= size_ip;	// ajust length compatibel IPv6
		payload = (void *)ip + size_ip;
		IPproto   = ip->ip_p;

		if (data_len < (payload_len + size_ip) ) {
			// capture len was limited - so adapt payload_len
			payload_len = data_len - size_ip;
			pcap_dev->proc_stat.short_snap++;
		}

		dbg_printf("Packet IPv4 SRC %s, DST %s, ",
			inet_ntop(AF_INET, &ip->ip_src, s1, sizeof(s1)),
			inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)));

		// IPv4 defragmentation
		if ( (ip_off & IP_MF) || frag_offset ) {
			uint16_t ip_id = ntohs(ip->ip_id);
#ifdef DEVEL
			if ( frag_offset == 0 )
				printf("Fragmented packet: first segement: ip_off: %u, frag_offset: %u\n",
					ip_off, frag_offset);
			if (( ip_off & IP_MF ) && frag_offset )
				printf("Fragmented packet: middle segement: ip_off: %u, frag_offset: %u\n",
					ip_off, frag_offset);
			if (( ip_off & IP_MF ) == 0  )
				printf("Fragmented packet: last segement: ip_off: %u, frag_offset: %u\n",
					ip_off, frag_offset);
#endif
			// fragmented packet
			defragmented = IPFrag_tree_Update(hdr->ts.tv_sec, ip->ip_src.s_addr, ip->ip_dst.s_addr,
				ip_id, &payload_len, ip_off, payload);
			if ( defragmented == NULL ) {
				// not yet complete
				dbg_printf("Fragmentation not yet completed. Size %u bytes\n", payload_len);
				goto END_FUNC;
			}
			dbg_printf("Fragmentation complete\n");
			// packet defragmented - set payload to defragmented data
			payload = defragmented;
		}
		bytes 		= payload_len;

		Node = New_Node();
		if ( !Node ) {
			pcap_dev->proc_stat.skipped++;
			LogError("Node allocation error - skip packet");
			return;
		}
		Node->t_first.tv_sec = hdr->ts.tv_sec;
		Node->t_first.tv_usec = hdr->ts.tv_usec;
		Node->t_last.tv_sec  = hdr->ts.tv_sec;
		Node->t_last.tv_usec  = hdr->ts.tv_usec;

		Node->src_addr.v6[0] = 0;
		Node->src_addr.v6[1] = 0;
		Node->src_addr.v4 = ntohl(ip->ip_src.s_addr);

		Node->dst_addr.v6[0] = 0;
		Node->dst_addr.v6[1] = 0;
		Node->dst_addr.v4 = ntohl(ip->ip_dst.s_addr);
		Node->version = AF_INET;
	} else {
		LogInfo("ProcessPacket() Unsupported protocol version: %i", version);
		pcap_dev->proc_stat.unknown++;
		goto END_FUNC;
	}

	Node->packets = 1;
	Node->bytes   = bytes;
	Node->proto   = IPproto;
	dbg_printf("Payload: %u bytes, Full packet: %u bytes\n", payload_len, bytes);

	// TCP/UDP decoding
	switch (IPproto) {
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr *)payload;
			uint16_t UDPlen = ntohs(udp->uh_ulen);
			if ( UDPlen < 8 ) {
				LogInfo("UDP payload length error: %u bytes < 8, SRC %s, DST %s",
					UDPlen, inet_ntop(AF_INET, &ip->ip_src, s1, sizeof(s1)),
					inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)));

				Free_Node(Node);
				break;
			}

			payload = payload + sizeof(struct udphdr);
			payload_len -= sizeof(struct udphdr);
			dbg_printf("UDP: size: %u, SRC: %i, DST: %i\n",
				payload_len, ntohs(udp->uh_sport), ntohs(udp->uh_dport));

			Node->bytes = payload_len;
			Node->flags = 0;
			Node->src_port = ntohs(udp->uh_sport);
			Node->dst_port = ntohs(udp->uh_dport);

			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr *)payload;
			uint32_t size_tcp;
			size_tcp = tcp->th_off << 2;

			if ( payload_len < size_tcp ) {
				pcap_dev->proc_stat.short_snap++;
				Free_Node(Node);
				break;
			}

			payload = payload + size_tcp;
			payload_len -= size_tcp;
			dbg_printf("Size TCP header: %u, size TCP payload: %u ", size_tcp, payload_len);
			dbg_printf("src %i, DST %i, flags %i : ",
				ntohs(tcp->th_sport), ntohs(tcp->th_dport), tcp->th_flags);

#ifdef DEVEL
			if ( tcp->th_flags & TH_SYN )  printf("SYN ");
			if ( tcp->th_flags & TH_ACK )  printf("ACK ");
			if ( tcp->th_flags & TH_URG )  printf("URG ");
			if ( tcp->th_flags & TH_PUSH ) printf("PUSH ");
			if ( tcp->th_flags & TH_FIN )  printf("FIN ");
			if ( tcp->th_flags & TH_RST )  printf("RST ");
			printf("\n");
#endif

			Node->flags = tcp->th_flags;
			Node->src_port = ntohs(tcp->th_sport);
			Node->dst_port = ntohs(tcp->th_dport);
			Push_Node(NodeList, Node);

			} break;
		case IPPROTO_ICMP: {
			struct icmp *icmp = (struct icmp *)payload;

			Node->dst_port = (icmp->icmp_type << 8 ) + icmp->icmp_code;
			dbg_printf("IPv%d ICMP proto: %u, type: %u, code: %u\n",
				version, ip->ip_p, icmp->icmp_type, icmp->icmp_code);
			Node->bytes -= sizeof(struct udphdr);
			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_ICMPV6: {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)payload;

			Node->dst_port = (icmp6->icmp6_type << 8 ) + icmp6->icmp6_code;
			dbg_printf("IPv%d ICMP proto: %u, type: %u, code: %u\n",
				version, ip->ip_p, icmp6->icmp6_type, icmp6->icmp6_code);
			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_IPV6: {
			uint32_t size_inner_ip = sizeof(struct ip6_hdr);

			if ( payload_len < size_inner_ip ) {
				pcap_dev->proc_stat.short_snap++;
				Free_Node(Node);
				goto END_FUNC;
			}
			offset   = 0;
			data 	 = payload;
			data_len = payload_len;

//			// move IP to tun IP
			Node->tun_src_addr = Node->src_addr;
			Node->tun_dst_addr = Node->dst_addr;
			Node->tun_proto	= IPPROTO_IPIP;

			dbg_printf("IPIPv6 tunnel - inner IPv6:\n");

			// redo proto evaluation
			goto REDO_IPPROTO;
			} break;
		case IPPROTO_IPIP: {
			struct ip *inner_ip	= (struct ip *)payload;
			uint32_t size_inner_ip = (inner_ip->ip_hl << 2);

			if ( payload_len < size_inner_ip ) {
				pcap_dev->proc_stat.short_snap++;
				Free_Node(Node);
				break;
			}
			offset   = 0;
			data 	 = payload;
			data_len = payload_len;

			// move IP to tun IP
			Node->tun_src_addr = Node->src_addr;
			Node->tun_dst_addr = Node->dst_addr;
			Node->tun_proto	= IPPROTO_IPIP;

			dbg_printf("IPIP tunnel - inner IP:\n");

			// redo proto evaluation
			goto REDO_IPPROTO;

			} break;
		case IPPROTO_GRE: {
			gre_hdr_t *gre_hdr = (gre_hdr_t *)payload;
			uint32_t gre_hdr_size = sizeof(gre_hdr_t); // offset points to end of inner IP

			if ( payload_len < gre_hdr_size ) {
				pcap_dev->proc_stat.short_snap++;
				Free_Node(Node);
				break;
			}

			dbg_printf("GRE proto encapsulation: type: 0x%x\n", protocol);
			protocol = ntohs(gre_hdr->type);
			offset   = gre_hdr_size;
			data 	 = payload;
			data_len = payload_len;

			// move IP to tun IP
			Node->tun_src_addr = Node->src_addr;
			Node->tun_dst_addr = Node->dst_addr;
			Node->tun_proto	= IPPROTO_GRE;

			// redo IP proto evaluation
			goto REDO_LINK;

			} break;
		default:
			// other IP protocols are treated as stream such as ESP etc.
			Push_Node(NodeList, Node);
			break;
	}

	END_FUNC:
	if ( defragmented ) {
		free(defragmented);
		defragmented = NULL;
		dbg_printf("Defragmented buffer freed for proto %u", IPproto);	
	}


} // End of ProcessPacket
