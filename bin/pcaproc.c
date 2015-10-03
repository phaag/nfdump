/*
 *  Copyright (c) 2014, Peter Haag
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
 *  $Author$
 *
 *  $Id$
 *
 *  $LastChangedRevision$
 *  
 */

#include "config.h"

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
#include "nffile.h"
#include "bookkeeper.h"
#include "nfxstat.h"
#include "collector.h"
#include "flowtree.h"
#include "ipfrag.h"
#include "pcaproc.h"
#include "content_dns.h"
#include "netflow_pcap.h"

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

static inline void ProcessTCPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessUDPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessICMPFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

static inline void ProcessOtherFlow(FlowSource_t	*fs, struct FlowNode *NewNode );

struct pcap_timeval {
	int32_t tv_sec;	   /* seconds */
	int32_t tv_usec;	  /* microseconds */
};

struct pcap_sf_pkthdr {
	struct pcap_timeval ts; /* time stamp */
	uint32_t	caplen;	 /* length of portion present */
	uint32_t	len;		/* length this packet (off wire) */
};

typedef struct vlan_hdr_s {
  uint16_t vlan_id;
  uint16_t type;
} vlan_hdr_t;

typedef struct gre_hdr_s {
  uint16_t flags;
  uint16_t type;
} gre_hdr_t;

int lock_sync = 0;

pcapfile_t *OpenNewPcapFile(pcap_t *p, char *filename, pcapfile_t *pcapfile) {

	if ( !pcapfile ) {
		// Create struct
		pcapfile = calloc(1, sizeof(pcapfile_t));
		if ( !pcapfile ) {
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pthread_mutex_init(&pcapfile->m_pbuff, NULL);
		pthread_cond_init(&pcapfile->c_pbuff, NULL);

		pcapfile->data_buffer = malloc(BUFFSIZE);
		if ( !pcapfile->data_buffer ) {
			free(pcapfile);
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pcapfile->alternate_buffer = malloc(BUFFSIZE);
		if ( !pcapfile->data_buffer ) {
			free(pcapfile->data_buffer);
			free(pcapfile);
			LogError("malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
			return NULL;
		}
		pcapfile->data_ptr		 = pcapfile->data_buffer;
		pcapfile->data_size 	 = 0;
		pcapfile->alternate_size = 0;
		pcapfile->p 			 = p;
	}

	if ( filename ) {
		pcapfile->pd = pcap_dump_open(p, filename);
		if ( !pcapfile->pd ) {
			LogError("Fatal: pcap_dump_open() failed for file '%s': %s", filename, pcap_geterr(p));
			return NULL;
		} else {
			fflush((FILE *)pcapfile->pd);
			pcapfile->pfd = fileno((FILE *)pcapfile->pd);
			return pcapfile;
		}
	} else 
		return pcapfile;

} // End of OpenNewPcapFile

int ClosePcapFile(pcapfile_t *pcapfile) {
int err = 0;

	if ( fclose((FILE *)pcapfile->pd) < 0 ) {
		LogError("close() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		err = errno;
	}
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

/*
	if ( pcapfile->pd)
		pcap_dump((u_char *)pcapfile->pd, h, sp);
	else
		printf("NULL handle\n");
	return;
*/
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

static inline void ProcessTCPFlow(FlowSource_t	*fs, struct FlowNode *NewNode ) {
struct FlowNode *Node;

	assert(NewNode->memflag == NODE_IN_USE);
	Node = Insert_Node(NewNode);
	// if insert fails, the existing node is returned -> flow exists already
	if ( Node == NULL ) {
		dbg_printf("New TCP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);

		// in case it's a FIN/RST only packet - immediately flush it
		if ( NewNode->fin == FIN_NODE  ) {
			// flush node
			if ( StorePcapFlow(fs, NewNode) ) {
				Remove_Node(NewNode);
			} 
		}

		if ( !CacheCheck() ) {
			uint32_t NumFlows;
			LogError("Node cache exhausted! - Immediate flush - increase flow cache!!");	
			NumFlows  = Flush_FlowTree(fs);
			LogError("Flushed flows: %u", NumFlows);	
		}
		return;
	}

	assert(Node->memflag == NODE_IN_USE);

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
		AppendUDPNode(NewNode);
		dbg_printf("New UDP flow: Packets: %u, Bytes: %u\n", NewNode->packets, NewNode->bytes);
		return;
	} 
	assert(Node->memflag == NODE_IN_USE);

	// update existing flow
	Node->packets++;
	Node->bytes += NewNode->bytes; 
	Node->t_last = NewNode->t_last; 
	TouchUDPNode(Node);

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

	// Flush Other packets directly
	StorePcapFlow(fs, NewNode);
	dbg_printf("Flush Other flow: Proto: %u, Packets: %u, Bytes: %u\n", NewNode->proto, NewNode->packets, NewNode->bytes);

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
uint32_t	  size_ip, offset, data_len, payload_len;
uint16_t	  version, ethertype, proto;
#ifdef DEVEL
char		  s1[64];
char		  s2[64];
#endif
static unsigned pkg_cnt = 0;

	pkg_cnt++;
	dbg_printf("\nNext Packet: %u\n", pkg_cnt);

	pcap_dev->proc_stat.packets++;
	offset = pcap_dev->linkoffset;

	Node = New_Node();
	if ( !Node ) {
		pcap_dev->proc_stat.skipped++;
		LogError("Node allocation error - skip packet");
		return;
	}

	if ( pcap_dev->linktype == DLT_EN10MB ) {
		ethertype = data[12] << 0x08 | data[13];
		int	IEEE802 = ethertype <= 1500;
		if ( IEEE802 ) {
			pcap_dev->proc_stat.skipped++;
			Free_Node(Node);
			return;
		}
		REDO_LINK:
			switch (ethertype) {
				case 0x800:	 // IPv4
				case 0x86DD: // IPv6
					break;
				case 0x8100: {	// VLAN 
					do {
						vlan_hdr_t *vlan_hdr = (vlan_hdr_t *)(data + offset);  // offset points to end of link layer
						dbg_printf("VLAN ID: %u, type: 0x%x\n", ntohs(vlan_hdr->vlan_id), ntohs(vlan_hdr->type) );
						ethertype = ntohs(vlan_hdr->type);
/*
pkt->vlans[pkt->vlan_count].pcp = (p[0] >> 5) & 7;
	  pkt->vlans[pkt->vlan_count].cfi = (p[0] >> 4) & 1;
	  pkt->vlans[pkt->vlan_count].vid = uint_16_be(p) & 0xfff;
*/
						offset += 4;
					} while ( ethertype == 0x8100 );
			
					// redo ethertype evaluation
					goto REDO_LINK;
					} break;
				case 0x806:	 // skip ARP
					// silently skip ARP
					pcap_dev->proc_stat.skipped++;
					return;
					break;
				case 0x26:	 // ?? multicast router termination ??
				case 0x4305: // B.A.T.M.A.N. BATADV
				case 0x886f: // MS NLB heartbeat
				case 0x88a2: // ATA over ethernet
				case 0x88cc: // CISCO LLDP
				case 0x9000: // Loop
				case 0x880b: // PPP - rfc 7042
					pcap_dev->proc_stat.skipped++;
					if ( Node->proto ) {
						// if it's an encap which we do not understand yet - push tunnel
						Push_Node(NodeList, Node);
					} else {
						pcap_dev->proc_stat.skipped++;
						dbg_printf("Skip Ethertype 0x%x", ethertype);
						Free_Node(Node);
					}
					return;
					break;
				default:
					pcap_dev->proc_stat.unknown++;
					LogError("Unsupported link type: 0x%x, packet: %u", ethertype, pkg_cnt);
					Free_Node(Node);
					return;
			}
	}

	if (hdr->caplen < offset) {
		pcap_dev->proc_stat.short_snap++;
		LogError("Short packet: %u/%u", hdr->caplen, offset);
		Free_Node(Node);
		return;
	}

	Node->t_first.tv_sec = hdr->ts.tv_sec;
	Node->t_first.tv_usec = hdr->ts.tv_usec;
	Node->t_last.tv_sec  = hdr->ts.tv_sec;
	Node->t_last.tv_usec  = hdr->ts.tv_usec;

	data	 = data + offset;
	data_len = hdr->caplen - offset;
	offset	 = 0;
	defragmented = NULL;

	// IP decoding
	REDO_IPPROTO:
	// IP decoding
	if ( defragmented ) {
		// data is sitting on a defragmented IPv4 packet memory region
		// REDO loop could result in a memory leak, if again IP is fragmented
		// XXX memory leak to be fixed
	}

	ip  	= (struct ip *)(data + offset); // offset points to end of link layer
	version = ip->ip_v;	 // ip version

	if ( version == 6 ) {
		uint64_t *addr;
		struct ip6_hdr *ip6 = (struct ip6_hdr *) (data + offset);
		size_ip = sizeof(struct ip6_hdr);
		offset = size_ip;	// offset point to end of IP header

		if ( data_len < size_ip ) {
			LogError("Packet: %u Length error: data_len: %u < size IPV6: %u, captured: %u, hdr len: %u", 
				pkg_cnt, data_len, size_ip, hdr->caplen, hdr->len);	
			pcap_dev->proc_stat.short_snap++;
			Free_Node(Node);
			return;
		}

		// XXX Extension headers not processed
		proto		= ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		payload_len = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);

		if (data_len < (payload_len + size_ip) ) {
			LogError("Packet: %u Length error: data_len: %u < payload_len %u + size IPv6", 
				pkg_cnt, data_len, payload_len);
			pcap_dev->proc_stat.short_snap++;
			Free_Node(Node);
			return;
		}

		dbg_printf("Packet IPv6, SRC %s, DST %s, ",
			inet_ntop(AF_INET6, &ip6->ip6_src, s1, sizeof(s1)),
			inet_ntop(AF_INET6, &ip6->ip6_dst, s2, sizeof(s2)));

		payload = (void *)ip + size_ip;

		addr = (uint64_t *)&ip6->ip6_src;
		Node->src_addr.v6[0] = ntohll(addr[0]);
		Node->src_addr.v6[1] = ntohll(addr[1]);

		addr = (uint64_t *)&ip6->ip6_dst;
		Node->dst_addr.v6[0] = ntohll(addr[0]);
		Node->dst_addr.v6[1] = ntohll(addr[1]);
		Node->version = AF_INET6;

	} else if ( version == 4 ) {
		uint16_t ip_off = ntohs(ip->ip_off);
		uint32_t frag_offset = (ip_off & IP_OFFMASK) << 3;
		size_ip = (ip->ip_hl << 2);
		offset = size_ip;	// offset point to end of IP header

		if ( data_len < size_ip ) {
			LogError("Packet: %u Length error: data_len: %u < size IPV4: %u, captured: %u, hdr len: %u", 
				pkg_cnt, data_len, size_ip, hdr->caplen, hdr->len);	
			pcap_dev->proc_stat.short_snap++;
			Free_Node(Node);
			return;
		}

		payload_len = ntohs(ip->ip_len);
		dbg_printf("size IP hader: %u, len: %u, %u\n", size_ip, ip->ip_len, payload_len);

		payload_len -= size_ip;	// ajust length compatibel IPv6
		payload = (void *)ip + size_ip;
		proto   = ip->ip_p;


		if (data_len < (payload_len + size_ip) ) {
			LogError("Packet: %u Length error: data_len: %u < payload_len %u + size IPv4, captured: %u, hdr len: %u", 
				pkg_cnt, data_len, payload_len, hdr->caplen, hdr->len);
			pcap_dev->proc_stat.short_snap++;
		}

		dbg_printf("Packet IPv4 SRC %s, DST %s, ",
			inet_ntop(AF_INET, &ip->ip_src, s1, sizeof(s1)),
			inet_ntop(AF_INET, &ip->ip_dst, s2, sizeof(s2)));

		// IPv4 defragmentation
		if ( (ip_off & IP_MF) || frag_offset ) { 
			uint16_t ip_id = ntohs(ip->ip_id);
			// fragmented packet
			defragmented = IPFrag_tree_Update(ip->ip_src.s_addr, ip->ip_dst.s_addr, ip_id, &payload_len, ip_off, payload);
			if ( defragmented == NULL ) 
				// not yet complete
				return;
			// packet defragmented - set payload to defragmented data
			payload = defragmented;
		} 

		Node->src_addr.v6[0] = 0;
		Node->src_addr.v6[1] = 0;
		Node->src_addr.v4 = ntohl(ip->ip_src.s_addr);

		Node->dst_addr.v6[0] = 0;
		Node->dst_addr.v6[1] = 0;
		Node->dst_addr.v4 = ntohl(ip->ip_dst.s_addr);
		Node->version = AF_INET;
	} else {
		LogError("ProcessPacket() Unsupprted protocol version: %i", version);
		pcap_dev->proc_stat.unknown++;
		Free_Node(Node);
		return;
	}

	Node->packets = 1;
	Node->bytes   = payload_len;
	Node->proto   = proto;
	dbg_printf("Size: %u\n", payload_len);

	// TCP/UDP decoding
	switch (proto) {
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr *)payload;
			uint16_t UDPlen = ntohs(udp->uh_ulen);
			if ( UDPlen < 8 ) {
				LogError("UDP payload legth error: %u bytes < 8\n",
					UDPlen);
				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
			}
			uint32_t size_udp_payload = ntohs(udp->uh_ulen) - 8;

			if ( (payload_len - sizeof(struct udphdr)) != size_udp_payload ) {
				LogError("UDP payload legth error: Expected %u, have %u bytes\n",
					size_udp_payload, (payload_len - (unsigned)sizeof(struct udphdr)));

				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
			}
			payload = payload + sizeof(struct udphdr);
			payload_len -= sizeof(struct udphdr);
			dbg_printf("UDP: size: %u, SRC: %i, DST: %i\n", 
				size_udp_payload, ntohs(udp->uh_sport), ntohs(udp->uh_dport));

			Node->flags = 0;
			Node->src_port = ntohs(udp->uh_sport);
			Node->dst_port = ntohs(udp->uh_dport);

			if ( hdr->caplen == hdr->len ) {
				// process payload of full packets
				if ( Node->src_port == 53 || Node->dst_port == 53 ) 
 					content_decode_dns(Node, payload, payload_len);
			}

			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr *)payload;
			uint32_t size_tcp;
			size_tcp = tcp->th_off << 2;

			if ( payload_len < size_tcp ) {
				LogError("TCP header length error: len: %u < size TCP header: %u", payload_len, size_tcp);	
				pcap_dev->proc_stat.short_snap++;
				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
			}

			payload = payload + size_tcp;
			payload_len -= size_tcp;
			dbg_printf("Size TCP header: %u, size TCP payload: %u ", size_tcp, payload_len);
			// XXX Debug stuff - remove when released ...
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
			dbg_printf("IPv%d ICMP proto: %u, type: %u, code: %u\n", version, ip->ip_p, icmp->icmp_type, icmp->icmp_code);
			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_ICMPV6: {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)payload;

			Node->dst_port = (icmp6->icmp6_type << 8 ) + icmp6->icmp6_code;
			dbg_printf("IPv%d ICMP proto: %u, type: %u, code: %u\n", version, ip->ip_p, icmp6->icmp6_type, icmp6->icmp6_code);
			Push_Node(NodeList, Node);
			} break;
		case IPPROTO_IPV6: {
			uint32_t size_inner_ip = sizeof(struct ip6_hdr);

			if ( payload_len < size_inner_ip ) {
				LogError("IPIPv6 tunnel header length error: len: %u < size inner IP: %u", payload_len, size_inner_ip);	
				pcap_dev->proc_stat.short_snap++;
				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
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
				LogError("IPIP tunnel header length error: len: %u < size inner IP: %u", payload_len, size_inner_ip);	
				pcap_dev->proc_stat.short_snap++;
				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
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
				LogError("GRE tunnel header length error: len: %u < size GRE hdr: %u", payload_len, gre_hdr_size);	
				pcap_dev->proc_stat.short_snap++;
				if ( defragmented ) {
					free(defragmented);
					defragmented = NULL;
				}
				Free_Node(Node);
				return;
			}

			dbg_printf("GRE proto encapsulation: type: 0x%x\n", ethertype);
			ethertype = ntohs(gre_hdr->type);
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
			// not handled protocol - simply save node
			Push_Node(NodeList, Node);
			pcap_dev->proc_stat.unknown++;
			break;
	}


} // End of ProcessPacket



