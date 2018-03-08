/*
 * Standard C includes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Standard UNIX includes
 */
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * Other includes
 */
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>

/*
 * Includes for BPF
 */
#include <sys/time.h>
#include <sys/ioctl.h>

/*
 * Local include files
 */
#include "webspy.h"
#include "httpfilter.h"

/*
 * The descriptor of the output file.
 */
FILE * outfile;

/*
 * Function Prototypes
 */
void process_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                       char *host, socklen_t hostlen,
                       char *serv, socklen_t servlen, int flags);

char* getHostName(const unsigned char **packet);
char* getPrefix(const unsigned char **packet);
void printURL(const unsigned char **packet);
void incrementETHER(const unsigned char **packet);


/*
 * Function: init_pcap ()
 *
 * Purpose:
 *	This function initializes the packet capture library for reading
 *	packets from a packet capturing program.
 */
pcap_t *
init_pcap (FILE * thefile, char * filename)
{
	char		error[PCAP_ERRBUF_SIZE];	/* Error buffer */
	pcap_t *	pcapd;				/* Pcap descriptor */

	/*
	 * Setup the global file pointer.
	 */
	outfile = thefile;

	/*
	 * Open the dump file and get a pcap descriptor.
	 */
	if ((pcapd=pcap_open_offline (filename, error)) == NULL)
	{
		fprintf (stderr, "Error is %s\n", error);
		return NULL;
	}

	return pcapd;
}

/*
 * Function: print_ether
 *
 * Description:
 *   Print the Ethernet header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the Ethernet
 *             header.
 */
void
print_ether (FILE * outfile, const unsigned char ** packet)
{
	struct ether_header header;
	int index;

	struct sockaddr_in sa;

	/*
	 * Align the data by copying it into a Ethernet header structure.
	 */
	bcopy (*packet, &header, sizeof (struct ether_header));

	/*
	 * Print out the Ethernet information.
	 */
	//fprintf (outfile, "================= ETHERNET HEADER ==============\n");
	//fprintf (outfile, "Source Address:\t\t");
	for (index=0; index < ETHER_ADDR_LEN; index++)
	{
		//fprintf (outfile, "%x", header.ether_shost[index]);
	}
	//fprintf (outfile, "\n");

	//fprintf (outfile, "Destination Address:\t");
	for (index=0; index < ETHER_ADDR_LEN; index++)
	{
	
		//fprintf (outfile, "%x", header.ether_dhost[index]);
	}
	//fprintf (outfile, "\n");

	//fprintf (outfile, "Protocol Type:\t\t");
	switch (ntohs(header.ether_type))
	{
		case ETHERTYPE_PUP:
			//fprintf (outfile, "PUP Protocol\n");
			break;

		case ETHERTYPE_IP:
			//fprintf (outfile, "IP Protocol\n");
			break;

		case ETHERTYPE_ARP:
			//fprintf (outfile, "ARP Protocol\n");
			break;

		case ETHERTYPE_REVARP:
			//fprintf (outfile, "RARP Protocol\n");
			break;

		default:
			//fprintf (outfile, "Unknown Protocol: %x\n", header.ether_type);
			break;
	}

	/*
	 * Adjust the pointer to point after the Ethernet header.
	 */
	*packet += sizeof (struct ether_header);

	/*
	 * Return indicating no errors.
	 */
	return;
}

/* Move this stuff elsewhere or rename func
 * Function: print_ip
 *
 * Description:
 *   Print the IPv4 header.
 *
 * Inputs:
 *   outfile - The file to which to print the Ethernet header information
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   packet  - The pointer is advanced to the first byte past the IPv4
 *             header.
 */
void
print_ip (FILE * outfile, const unsigned char ** packet)
{
	struct ip ip_header;
    
	/*
	 * After reading comments in tcpdump source code, I discovered that
	 * the dump file does not guarantee that the IP header is aligned
	 * on a word boundary.
	 *
	 * This is apparently what's causing me problems, so I will word align
	 * it just like tcpdump does.
	 */

	bcopy (*packet, &ip_header, sizeof (struct ip));

	/*
	 * TODO: Print ip header
	 */

	return;
}		




/* 
 * Function: printURL
 *
 * Description:
 *   Prints URL obtained from packet.
 *
 * Inputs:
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   None.
 */



void 
printURL(const unsigned char **packet) 
{

	incrementETHER(packet);
	char host[10000];
	strcpy(host,getHostName(packet));
	char *prefix = getPrefix(packet);
	char request_type[10];

	strncpy(request_type, packet[0], 4);
	request_type[4] = '\0';

	/* 
	 * resource pointer starts at the first instance
	 * of the backlash in the data, aka start of the resource 
	 */

	char *resource = strchr(packet[0], '/');

	/* Check if it is a request */
	if (strcmp(request_type, "GET ") == 0 ) {               
	    if (resource != NULL) {
	    	strtok(resource, " ");
	    	printf("%s%s%s%s\n", request_type, prefix, host, resource);
	    }
	    // else if there is data, but we can't tell it's a request, we assume it is encryted. 
	} else if (strlen(packet[0]) > 0) {		
		printf("%s%s/OMITTED\n", prefix, host);
	}

}

/* 
 * Function: incrementEther
 *
 * Description:
 *   increments our packet past the ethernet header.
 *
 * Inputs:
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   None.
 */

void 
incrementETHER(const unsigned char **packet) 
{
	struct ether_header header;
	/*
	 * Align the data by copying it into a Ethernet header structure.
	 */

	bcopy (*packet, &header, sizeof (struct ether_header));

	*packet += sizeof(struct ether_header);

	return;

}

/* 
 * Function: getHTTPtype
 *
 * Description:
 *   Get's http prefix from the tcp header and moves packet pointer so we can access data. 
 *
 * Inputs:
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   prefix - char * that contains the prefix http or https
 */


char *
getPrefix(const unsigned char **packet)
{

	struct tcphdr tcp_header;
	
	bcopy (*packet, &tcp_header, sizeof (struct tcphdr));

	char *prefix;
    
	if (tcp_header.dest == 443) {
        prefix = "https://";
	} else {
		prefix = "http://";
	}

    *packet += tcp_header.th_off * 4;
    
    return prefix;

}

/* 
 * Function: getHostname
 *
 * Description:
 *   Get's ip address from ip header and uses that to obtain a hostname/domain name
 *
 * Inputs:
 *   packet  - A pointer to the pointer to the packet information.
 *
 * Outputs:
 *   host - char * containing the domain name associated with the packet
 */


char *
getHostName(const unsigned char **packet) 
{
	struct ip ip_header;
    struct in_addr addr;

	/*
	 * After reading comments in tcpdump source code, I discovered that
	 * the dump file does not guarantee that the IP header is aligned
	 * on a word boundary.
	 *
	 * This is apparently what's causing me problems, so I will word align
	 * it just like tcpdump does.
	 */

	bcopy (*packet, &ip_header, sizeof (struct ip));
	
	struct sockaddr_in sa;
	sa.sin_family = AF_INET;
    addr.s_addr = htole32(ip_header.ip_dst.s_addr); 
	sa.sin_addr = addr;
	static char host[10000];
    
	if( getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) != 0 ){
		strcpy(host, "OMITTED");
	}

	*packet += sizeof (struct ip);

	return host;

}


/*
 * Function: process_packet ()
 *
 * Purpose:
 *	This function is called each time a packet is captured.  It will
 *	determine if the packet is one that is desired, and then it will
 *	print the packet's information into the output file.
 *
 * Inputs:
 *	thing         - I have no idea what this is.
 *	packet_header - The header that libpcap precedes a packet with.  It
 *	                indicates how much of the packet was captured.
 *	packet        - A pointer to the captured packet.
 *
 * Outputs:
 *	None.
 *
 * Return value:
 *	None.
 */
void
process_packet (u_char * thing,
                const struct pcap_pkthdr * packet_header,
                const u_char * packet)
{
	/* Determine where the IP Header is */
	const unsigned char *pointer;

	/* Length of the data */
	long packet_length;

	/*
	 * Filter the packet using our BPF filter.
	 */
	if ((pcap_offline_filter (&HTTPFilter, packet_header, packet) == 0))
	{
		return;
	}

	/*
	 * Print the URL
	 */
	pointer = packet;
	
	printURL(&pointer);

	return;
}
