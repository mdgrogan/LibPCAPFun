#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

/* When using threaded server, first few bytes are getting cut.
 * also, port #s are showing up as zero. seems to work when outward facing though
 * so... just go through and check
 * */


pcap_t *pd = NULL;

/************************************************
 * List devices available for sniffing.
 * return could probably be void...
 ***********************************************/
int listDevs() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devList, *tmp;

    if (pcap_findalldevs(&devList, errbuf)) {
	fprintf(stderr, "findalldevs() failed: %s\n", errbuf);
	return 1;
    }

    if (devList) {
	for (tmp = devList; tmp; tmp = tmp->next) {
	    printf("device: %s\n", tmp->name);
	}
    } else {
	printf("no devices found\n");
    }

    return 0;
}

/************************************************
 * Set device for sniffing and compile filter, if 
 * provided. 
 * return pointer to the pcap descriptor.
 ***********************************************/
pcap_t *initPcap(char *dev, const char *bpfstr, int *linktype) {
    pcap_t *pcapDescr;
    uint32_t maskp, netp;
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* if dev not user set, get default */
    if (!*dev && !(dev = pcap_lookupdev(errbuf))) {
	fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
	return NULL;
    }

    /* get IP and netmask - demos all req maskp but don't use -- what gives? */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* open device for live capture */
    if (!(pcapDescr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf))) {
	fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
	return NULL;
    }

    /* compile and set packet filter */
    if (pcap_compile(pcapDescr, &bpf, bpfstr, 0, maskp)) {
	fprintf(stderr, "pcap_compile() failed: **%s**\n", pcap_geterr(pcapDescr));
	return NULL;
    }
    if (pcap_setfilter(pcapDescr, &bpf) < 0) {
	fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(pcapDescr));
	pcap_freecode(&bpf);
	return NULL;
    }
    pcap_freecode(&bpf);

    /* determine datalink layer type and set header length accordingly */
    if ((*linktype = pcap_datalink(pcapDescr)) < 0) {
	fprintf(stderr, "pcap_datalink() failed: %s\n", pcap_geterr(pcapDescr));
	return NULL;
    }

    return pcapDescr;
}

/************************************************
 * handle ethernet packets
 ***********************************************/
u_int16_t handleEther(const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    u_int caplen = packethdr->caplen;
    u_int length = packethdr->len;
    struct ether_header *etherptr;
    u_short ether_type;
    
    if (caplen < ETHER_HDR_LEN) {
	printf("Malformed ethernet header\n");
	return -1; /* unsigned??? */
    }

    etherptr = (struct ether_header *)packetptr;
    ether_type = ntohs(etherptr->ether_type);
    if (ether_type == ETHERTYPE_IP)
	printf("%-10s", "ETH(IP)");
    if (ether_type == ETHERTYPE_ARP)
	printf("%-10s", "ETH(ARP)");
    printf("SRC: %-24s DST: %-24s LEN: %d\n", 
	    ether_ntoa((struct ether_addr *)etherptr->ether_shost),
	    ether_ntoa((struct ether_addr *)etherptr->ether_dhost),
	    length);
    return ether_type;
}

/************************************************
 * print data in rows of 16 bytes: offset hex ascii
 * shamelessly ripped from sniffex.c
 ***********************************************/
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    int i, gap;
    const u_char *ch;

    printf("%05d   ", offset);
    ch = payload;
    for (i = 0; i < len; i++) {
	printf("%02x ", *ch);
	ch++;
	if (i == 7)
	    printf(" ");
    }
    if (len < 8)
	printf(" ");
    if (len < 16) {
	gap = 16 - len;
	for (i=0; i < gap; i++)
	    printf(" ");
    }
    printf(" ");

    ch = payload;
    for (i = 0; i < len; i++) {
	if (isprint(*ch))
	    printf("%c", *ch);
	else
	    printf(".");
	ch++;
    }
    printf("\n");
    return;
}


/************************************************
 * print tcp payload
 * shamelessly ripped from sniffex.c
 ***********************************************/
void print_payload(const u_char *payload, int len) {
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;

    if (len <= 0)
	return;

    if (len <= line_width) {
	print_hex_ascii_line(ch, len, offset);
	return;
    }

    for (;;) {
	line_len = line_width % len_rem;
	print_hex_ascii_line(ch, line_len, offset);
	len_rem = len_rem - line_len;
	ch = ch + line_len;
	offset = offset + line_width;
	if (len_rem <= line_width) {
	    print_hex_ascii_line(ch, len_rem, offset);
	    break;
	}
    }
    return;
}

/************************************************
 * handle IP packets
 ***********************************************/
u_int16_t handleIP(const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip *iphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    const char *payload;
    int payload_size;
    int iphdr_size;
    int tcphdr_size;;

    /* set header fields. this needs to be generalized if this function
    * is otherwise compatible with wlan/ppp/otherstuff  */
    iphdr = (struct ip *)(packetptr + sizeof(struct ether_header)); 
    iphdr_size = 4*iphdr->ip_hl;
    if (iphdr_size < 20) {
	printf(" invalid IP header length: %u bytes\n", iphdr_size);
	return 1;
    }

    switch (iphdr->ip_p) {
	case IPPROTO_TCP:
	    tcphdr = (struct tcphdr *)(iphdr + iphdr_size);
	    tcphdr_size = 4*tcphdr->th_off; /* might not be bad idea to check this <20 */
	    printf("%-14s %-15s:%-13d %-15s:%-8d ID:%d TOS:0x%x, TTL:%d\n", "Protocol: TCP", 
		    inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport),
		    inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport),
		    ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl);
	    printf("%c%c%c%c%c%c Seq:0x%x Ack:0x%x Win:0x%x\n", 
		    (tcphdr->urg ? 'U':'*'), (tcphdr->ack ? 'A':'*'),
		    (tcphdr->psh ? 'P':'*'), (tcphdr->rst ? 'R':'*'),
		    (tcphdr->syn ? 'S':'*'), (tcphdr->fin ? 'F':'*'),
		    ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
		    ntohs(tcphdr->window));
	    payload = (u_char *)(packetptr + sizeof(struct ether_header) +iphdr_size + tcphdr_size);
	    payload_size = ntohs(iphdr->ip_len) - (iphdr_size + tcphdr_size);
	    if (payload_size > 0) {
		printf("Payload (%d bytes):\n", payload_size);
		print_payload(payload, payload_size);
	    }
	    break;
	case IPPROTO_UDP:
	    udphdr = (struct udphdr *)(iphdr + 4*iphdr->ip_hl);
	    printf("%-14s %-15s:%-13d %-15s:%-8d\n\n", "Protocol: UDP", 
		    inet_ntoa(iphdr->ip_src), ntohs(udphdr->uh_sport),
		    inet_ntoa(iphdr->ip_dst), ntohs(udphdr->uh_dport));
	    break;
	case IPPROTO_ICMP:
	    printf("Protocol: ICMP\n");
	default:
	    printf("Protocol: unknown\n");
    }
    return 0;
}

/************************************************
 * loop handler: deal with packet parsing. A
 * substantial amount of this overhead is assuming
 * that there's some difference in the handling
 * of different data link types (ether vs wlan). 
 * Not sure if that is the case yet... 
 ***********************************************/
void loopHandler(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr) {
    static int i = 1;
    u_int16_t type = 0;
    int linktype = (int)*user;
    
    printf("Packet #%d:\n", i);
    i++;

    /* every might be translated to eth... dunno */
    switch (linktype) {
	case DLT_NULL:
	    printf("DLT_NULL\n");
	    break;
	case DLT_EN10MB:
	    type = handleEther(packethdr, packetptr);
	    break;
	case DLT_PPP:
	    printf("DLT_PPP\n");
	    break;
	case DLT_RAW:
	    printf("DLT_RAW\n");
	    break;
	case DLT_IEEE802_11:
	    printf("DLT_IEEE802_11\n");
	    break;
	default:
	    printf("DLT unknown - check tcpdump.org/linktypes: %d\n", linktype);
    }
    switch (type) {
	case ETHERTYPE_IP:
	    handleIP(packethdr, packetptr);
	    break;
	case ETHERTYPE_ARP:
	    printf("ARP related stuff should go here\n");
	    break;
	default:
	    printf("unknown type...\n");
    }
}

/************************************************
 * Set quit flag. Let loop handler deal with cleanup.
 * sigaction is resulting in segfault...
 ***********************************************/
/*void userBail(int signo) {
    pcap_breakloop(pd);
    pcap_close(pd);
}*/

int main (int argc, char **argv)
{
    pcap_t *pd = NULL;
    char dev[256] = "";
    char bpfstr[256] = "";
    int linktype = 0;
    int packets = 0;
    int c, i;
    /*struct sigaction sigact;

    memset(&sigact, 0, sizeof(sigact));
    sigact.sa_handler = userBail;
    if (sigaction(SIGINT, &sigact, NULL) == -1)
	fprintf(stderr, "cannot handle SIGINT\n");
    if (sigaction(SIGTERM, &sigact, NULL) == -1)
	fprintf(stderr, "cannot handle SIGINT\n");
    if (sigaction(SIGQUIT, &sigact, NULL) == -1)
	fprintf(stderr, "cannot handle SIGINT\n");
    */
    if (argc < 2) {
	printf("Usage: ./main "
	    "-l (list available interfaces) "
	    "-i [interface] [filter args] "
	    "-n [# of packets to capture, "
	    "default unlimited]\n");
	    return 1;
    }
    while ((c = getopt(argc, argv, "li:f:n:")) != -1) {
	switch (c) {
	    case 'l':
		/* too lazy to deal with return */
		listDevs();
		return 0;
	    case 'i':
		strcpy(dev, optarg);
		break;
	    case 'n':
		packets = atoi(optarg);
		break;
	    default:
	    printf("Usage: ./main "
		"-l (list available interfaces) "
		"-i [interface] [filter args]"
		"-n [# of packets to capture, "
		"default unlimited]\n");
	}
    }
    /* frighteningly unsafe */
    for (i = optind; i<argc; i++) {
	strcat(bpfstr, argv[i]);
	if (i != argc-1) 
	    strcat(bpfstr, " ");
	else
	    strcat(bpfstr, "\0");
    }
    if ((pd = initPcap(dev, bpfstr, &linktype))) {
	if (pcap_loop(pd, packets, loopHandler, (u_char *)&linktype) < 0) {
		fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(pd));
	}

    }

    return 0;
}
