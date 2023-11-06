#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "display.c"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ipv4 *ipv4; /* The IPv4 header */
const struct sniff_ipv4 *ipv6; /* The IPv6 header */
const struct sniff_tcp *tcp; /* The TCP header */
const struct sniff_udp *udp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

/* IPv4 header */
struct sniff_ipv4 {
	u_char ip_vhl;		        /* version << 4 | header length >> 2 */
	u_char ip_tos;		        /* type of service */
	u_short ip_len;		        /* total length */
	u_short ip_id;		        /* identification */
	u_short ip_off;		        /* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* don't fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		        /* time to live */
	u_char ip_p;		        /* protocol */
	u_short ip_sum;		        /* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* IPv6 header */
struct sniff_ipv6 {
    u_int8_t  ip_version_traffic_class_flow_label[4];  /* Version, Traffic Class, and Flow Label */
    u_int16_t ip_payload_length;                       /* Payload Length */
    u_int8_t  ip_next_header;                           /* Next Header (Equivalent to Protocol in IPv4) */
    u_int8_t  ip_hop_limit;                             /* Hop Limit (TTL in IPv4) */
    struct in6_addr ip_src;                             /* Source IPv6 Address */
    struct in6_addr ip_dst;                             /* Destination IPv6 Address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


/* UDP header */
struct sniff_udp {
    uint16_t uh_sport;   /* Source port */
    uint16_t uh_dport;   /* Destination port */
    uint16_t uh_len;     /* Length of the UDP header and data */
    uint16_t uh_sum;     /* Checksum */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void process_ipv6 (const struct sniff_ipv6 *ipv6);

void process_ipv4 (const struct sniff_ipv4 *ipv4);

void process_tcp (const struct sniff_tcp *tcp, int size_ip, int ip_len);

void process_udp (const struct sniff_udp *udp);

/* callback function */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ipv4 *ipv4;              /* The IP header */
	const struct sniff_ipv6 *ipv6; 
    
	const char *payload;                    /* Packet payload */

	int size_ip;
	

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
    u_short ether_type = ntohs(ethernet->ether_type);
    switch (ether_type) {
        case 0x0800:
            printf("IPv4 packet\n");
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHERNET);
            process_ipv4(ipv4);
            break;
        case 0x86DD:
            printf("IPv6 packet\n");
            ipv6 = (struct sniff_ipv6*)(packet + SIZE_ETHERNET);
            process_ipv6(ipv6);
            break;
        case 0x0806:
            printf("ARP packet\n");
            break;
        case 0x86C6:
            printf("IPv6 Routing Header\n");
            break;
        default:
            printf("Unknown or unsupported EtherType: 0x%04X\n", ether_type);
    }

	/* define/compute tcp header offset */
	// tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	// size_tcp = TH_OFF(tcp)*4;
	// if (size_tcp < 20) {
	// 	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
	// 	return;
	// }

	// printf("   Src port: %d\n", ntohs(tcp->th_sport));
	// printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	// /* define/compute tcp payload (segment) offset */
	// payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	// /* compute tcp payload (segment) size */
	// size_payload = ntohs(ipv4->ip_len) - (size_ip + size_tcp);

	// /*
	//  * Print payload data; it might be binary, so don't just
	//  * treat it as a string.
	//  */
	// if (size_payload > 0) {
	// 	printf("   Payload (%d bytes):\n", size_payload);
	// 	//print_payload(payload, size_payload);
	// }

    return;
}


void process_ipv6 (const struct sniff_ipv6 *ipv6) {

    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;            /* The UDP header */
    int size_ip;
	size_ip = 40;

    // Extract the source and destination IP addresses
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6->ip_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6->ip_dst), dst_ip, INET6_ADDRSTRLEN);

    printf("       From: %s\n", src_ip);
    printf("         To: %s\n", dst_ip);

    // Determine the protocol
    switch (ipv6->ip_next_header) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            tcp = (struct sniff_tcp*)(ipv6 + size_ip);
            process_tcp(tcp, size_ip, ipv6->ip_payload_length);
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            udp = (struct sniff_udp*)(ipv6 + size_ip);
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
        default:
            printf("   Protocol: unknown\n");
    }
}

void process_ipv4 (const struct sniff_ipv4 *ipv4) {

    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;            /* The UDP header */
    int size_ip;
	size_ip = IP_HL(ipv4)*4;
    
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		exit(0);
        return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ipv4->ip_src));
	printf("         To: %s\n", inet_ntoa(ipv4->ip_dst));

	/* determine protocol */
	switch(ipv4->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
            tcp = (const struct sniff_tcp*)((u_char *)ipv4 + size_ip);
            process_tcp(tcp, size_ip, ipv4->ip_len);
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
            udp = (const struct sniff_udp*)((u_char *)ipv4 + size_ip);
            process_udp(udp);
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

}

void process_tcp (const struct sniff_tcp *tcp, int size_ip, int ip_len) {
    int size_tcp;
	int size_payload;
    const u_char *payload;

    size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = ((const u_char *)tcp + size_tcp);

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip_len) - (size_ip + size_tcp);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		//print_payload(payload, size_payload);
	}
}

void process_udp (const struct sniff_udp *udp) {
    printf("\nudp wip\n");
}


int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE]; //error string
    pcap_if_t *all_devs; //list of all devices
    pcap_t *handle; //session handle
    struct bpf_program fp; //compiled filter expression
    char filter_exp[] = " "; //filter expresssion
    bpf_u_int32 mask; //netmask of dev
    bpf_u_int32 net; //ip of dev
    struct pcap_pkthdr header; //pcap header
    const u_char *packet; //captured packet
    int num_packets = 100;

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find all capture devices if not specified on command-line */
        if (pcap_findalldevs(&all_devs, errbuf)==-1) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        //select the first device
	    dev = all_devs->name;
	}

    /* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

    print_app_banner();


	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

    
    //create a sniffing session
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

     /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }


    //filter expression is translated into bpf format 
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	return(2);
    }

    //apply filter
    if (pcap_setfilter(handle, &fp) == -1) {
    	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    	return(2);
    }

    //packet = pcap_next(handle, &header);
    //printf ("captured: %d\n", header.len);

    pcap_loop(handle, num_packets, got_packet, NULL);
    
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");


	return(0);
}

//sudo tcpdump -A -s 1492 dst port 80