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
#include <getopt.h>

#include "display.c"


#define SNAP_LEN 50

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
const struct sniff_udp *udp; /* The UDP header */
const char *payload; /* Packet payload */

u_int size_ip;
int snap_len = SNAP_LEN;

/* ARP header */
struct sniff_arp {
    u_short ar_hrd;        /* format of hardware address (e.g., Ethernet) */
    u_short ar_pro;        /* format of protocol address (e.g., IPv4) */
    u_char ar_hln;         /* length of hardware address (Ethernet = 6) */
    u_char ar_pln;         /* length of protocol address (IPv4 = 4) */
    u_short ar_op;         /* ARP operation (e.g., request or reply) */
    u_char ar_sha[6];      /* sender hardware address (MAC address) */
    u_char ar_sip[4];      /* sender protocol address (IPv4 address) */
    u_char ar_tha[6];      /* target hardware address (MAC address) */
    u_char ar_tip[4];      /* target protocol address (IPv4 address) */
    #define ARP_REQUEST 1
    #define ARP_REPLY 2

};

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
void process_udp (const struct sniff_udp *udp, int ip_len);
void process_arp(const struct sniff_arp *arp) ;

/* callback function */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ipv4 *ipv4;              /* The IP header */
	const struct sniff_ipv6 *ipv6;
    const struct sniff_arp *arp;  


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
            arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
            process_arp(arp);
            break;
        case 0x86C6:
            printf("IPv6 Routing Header\n");
            break;
        default:
            printf("Unknown or unsupported EtherType: 0x%04X\n", ether_type);
    }

    return;
}

void process_ipv6 (const struct sniff_ipv6 *ipv6) {

    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;            /* The UDP header */
    int size_ip;
	size_ip = 40;

    int offset = 40;

    // Extract the source and destination IP addresses
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6->ip_src), src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6->ip_dst), dst_ip, INET6_ADDRSTRLEN);

    printf("       From: %s\n", src_ip);
    printf("         To: %s\n", dst_ip);

     int next_header = ipv6->ip_next_header;
    while (next_header == IPPROTO_IPV6 ||
           next_header == IPPROTO_HOPOPTS) {
        // Skip over IPv6 extension headers, as they have variable lengths
        const uint8_t *extension_header = ((const uint8_t *)ipv6) + offset;
        int header_length = (extension_header[1] + 1) * 8;  // Length is in 8-byte units
        offset += header_length;
        next_header = extension_header[0];
    }

    switch (next_header) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            tcp = (const struct sniff_tcp *)(((const char *)ipv6) + offset);
            process_tcp(tcp, size_ip, ntohs(ipv6->ip_payload_length));
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            udp = (const struct sniff_udp *)(((const char *)ipv6) + offset);
            process_udp(udp, ntohs(ipv6->ip_payload_length));
            break;
        case IPPROTO_ICMPV6:
            printf("   Protocol: ICMP\n");
            break;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown: %d\n", next_header);
			return;
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
            process_udp(udp, ipv4->ip_len);
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

void process_arp(const struct sniff_arp *arp) {
    printf("   ARP Request/Reply\n");
    
    if (ntohs(arp->ar_op) == ARP_REQUEST) {
        printf("   Operation: Request\n");
    } else if (ntohs(arp->ar_op) == ARP_REPLY) {
        printf("   Operation: Reply\n");
    } else {
        printf("   Operation: Unknown\n");
    }

    printf("   Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->ar_sha[0], arp->ar_sha[1], arp->ar_sha[2], arp->ar_sha[3], arp->ar_sha[4], arp->ar_sha[5]);
    printf("   Sender IP Address: %d.%d.%d.%d\n", arp->ar_sip[0], arp->ar_sip[1], arp->ar_sip[2], arp->ar_sip[3]);
    printf("   Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n", arp->ar_tha[0], arp->ar_tha[1], arp->ar_tha[2], arp->ar_tha[3], arp->ar_tha[4], arp->ar_tha[5]);
    printf("   Target IP Address: %d.%d.%d.%d\n", arp->ar_tip[0], arp->ar_tip[1], arp->ar_tip[2], arp->ar_tip[3]);
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

	/* print payload data */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload, snap_len);

    if (size_payload > 0 && strstr((const char *)payload, "HTTP") != NULL) {
        // Check the HTTP method
        if (strstr((const char *)payload, "GET") != NULL) {
            printf("   HTTP Request Type: GET\n");
        } else if (strstr((const char *)payload, "POST") != NULL) {
            printf("   HTTP Request Type: POST\n");
        } else if (strstr((const char *)payload, "PUT") != NULL) {
            printf("   HTTP Request Type: PUT\n");
        } else if (strstr((const char *)payload, "DELETE") != NULL) {
            printf("   HTTP Request Type: DELETE\n");
        } else {
            printf("   Unknown HTTP Request Type\n");
        }
    }        
	}
}

void process_udp(const struct sniff_udp *udp, int ip_len) {
    int size_udp;
    int size_payload;
    const u_char *payload;

    size_udp = ntohs(udp->uh_len);

    printf("   Src Port: %u\n", ntohs(udp->uh_sport));
    printf("   Dst Port: %u\n", ntohs(udp->uh_dport));

    /* define/compute tcp payload (segment) offset */
	payload = ((const u_char *)udp + 8);

    /* compute udp payload (segment) size */
    size_payload = ntohs(ip_len) - size_ip - 8;

    /* checksum information */
    printf("   Checksum: 0x%04X\n", ntohs(udp->uh_sum));


    // Check if the payload size is greater than zero and looks like a DNS query
    if (size_payload >= 12) { // A DNS query typically has a minimum size of 12 bytes

        // Check the DNS query flag (third and fourth bytes)
        if (payload[2] == 0x01 && payload[3] == 0x00) {
            printf("   DNS query (UDP)\n");

            // Extract and print more DNS query information
            uint16_t query_id = (payload[0] << 8) | payload[1];
            uint16_t question_count = (payload[4] << 8) | payload[5];

            printf("   DNS Query ID: %u\n", query_id);
            printf("   Question Count: %u\n", question_count);
            char dn[256] = ""; 
            int first_label = 1;
            // Extract and print the domain name being queried
            int offset = 12; // Start of the DNS query section
            while (offset < size_payload) {
                int label_length = payload[offset];
                if (label_length == 0) {
                    break; // End of domain name
                }

                // Append the label to the fully-qualified domain name (FQDN)

                if (!first_label) {
                    strncat(dn, ".", sizeof(dn) - strlen(dn) - 1);
                }
                strncat(dn, (char *)(payload + offset + 1), label_length);
                offset += (label_length + 1);
                first_label = 0;
            }

            // Print the fully-qualified domain name (FQDN)
            printf("   Domain Name: %s\n", dn);

        }
    }

 	/* print payload data */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload, snap_len);
	}

}

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE]; //error string
    pcap_if_t *all_devs; //list of all devices
    pcap_t *handle; //session handle
    struct bpf_program fp; //compiled filter expression
    char filter_exp[256] = "port 53"; //filter expresssion
    bpf_u_int32 mask; //netmask of dev
    bpf_u_int32 net; //ip of dev
    struct pcap_pkthdr header; //pcap header
    const u_char *packet; //captured packet
    int num_packets = 100;

    dev = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "s:i:n:f:")) != -1) {
        switch (opt) {
            case 's':
                snap_len = atoi(optarg);
                if (snap_len <= 0) {
                    fprintf(stderr, "Invalid snap length: %s\n", optarg);
                    exit(2);
                }
                break;
            case 'i':
                dev = optarg;
                break;
            case 'n':
                num_packets = atoi(optarg);
                if (num_packets <= 0) {
                    fprintf(stderr, "Invalid number of packets: %s\n", optarg);
                    exit(2);
                }
                break;
            case 'f':
                if (strlen(optarg) >= sizeof(filter_exp)) {
                    fprintf(stderr, "Filter expression is too long\n");
                    exit(2);
                }
                strcpy(filter_exp, optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s [-s snap_length] [-i interface_name] [-n number_of_packets] [-f filter_expression]\n", argv[0]);
                exit(2);
        }
    }


	if (dev == NULL) {
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

