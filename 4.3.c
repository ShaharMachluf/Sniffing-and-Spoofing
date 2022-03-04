#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};


unsigned short calculate_checksum(unsigned short * paddress, int len);

void got_packet(u_char *packet)
{
  char data[IP_MAXPACKET] = "This is the ping.\n";
  int datalen = strlen(data) + 1;
//   struct in_addr src, dest;
  int ip_header_len;
  struct ethheader *eth = (struct ethheader *)packet;//point to the beggining of the ethernet header

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ip * ipheader = (struct ip *)
                           (packet + sizeof(struct ethheader));  //point to the beggining of the ip header

    /* determine protocol */
    if(ipheader->ip_p == IPPROTO_ICMP) {                                
      ip_header_len = ipheader->ip_hl * 4;
      struct icmp * icmpheader = (struct icmp*)(packet + sizeof(struct ethheader) + ip_header_len);//point to the beggining of the ICMP header
      if(icmpheader->icmp_type == 8){
        struct ip iphdr;//new ipheader
        struct icmp icmphdr;//new icmp header
        iphdr.ip_src = ipheader->ip_dst;
        iphdr.ip_dst = ipheader->ip_src;
        //==================
        // IP header
        //==================

        // IP protocol version (4 bits)
        iphdr.ip_v = 4;

        // IP header length (4 bits): Number of 32-bit words in header = 5
        iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct

        // Type of service (8 bits) - not using, zero it.
        iphdr.ip_tos = 0;

        // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
        iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

        // ID sequence number (16 bits): not in use since we do not allow fragmentation
        iphdr.ip_id = 0;

        // Fragmentation bits - we are sending short packets below MTU-size and without 
        // fragmentation
        int ip_flags[4];

        // Reserved bit
        ip_flags[0] = 0;

        // "Do not fragment" bit
        ip_flags[1] = 0;

        // "More fragments" bit
        ip_flags[2] = 0;

        // Fragmentation offset (13 bits)
        ip_flags[3] = 0;

        iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14)
                        + (ip_flags[2] << 13) +  ip_flags[3]);

        // TTL (8 bits): 128 - you can play with it: set to some reasonable number
        iphdr.ip_ttl = 128;

        // Upper protocol (8 bits): ICMP is protocol number 1
        iphdr.ip_p = IPPROTO_ICMP;


        // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
        iphdr.ip_sum = 0;
        iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);


        //===================
        // ICMP header
        //===================

        // Message Type (8 bits): ICMP_ECHO_REQUEST
        icmphdr.icmp_type = 0;

        // Message Code (8 bits): echo request
        icmphdr.icmp_code = 0;

        // Identifier (16 bits): some number to trace the response.
        // It will be copied to the response packet and used to map response to the request sent earlier.
        // Thus, it serves as a Transaction-ID when we need to make "ping"
        icmphdr.icmp_id = 18; // hai

        // Sequence Number (16 bits): starts at 0
        icmphdr.icmp_seq = 0;

        // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
        icmphdr.icmp_cksum = 0;

        // Combine the packet 
        char packets[IP_MAXPACKET];

        // First, IP header.
        memcpy (packets, &iphdr, IP4_HDRLEN);

        // Next, ICMP header
        memcpy ((packets + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

        // After ICMP header, add the ICMP data.
        memcpy (packets + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

        // Calculate the ICMP header checksum
        icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packets + IP4_HDRLEN), ICMP_HDRLEN + datalen);
        memcpy ((packets + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

        struct sockaddr_in dest_in;
        memset (&dest_in, 0, sizeof (struct sockaddr_in));
        dest_in.sin_family = AF_INET;

        // The port is irrelant for Networking and therefore was zeroed.
        dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;
        int sock = -1;
        if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
        {
            fprintf (stderr, "socket() failed with error: %d", errno);
            fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
            return;
        }
        const int flagOne = 1;
        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL,&flagOne, // The above casting is important for Windows.
                    sizeof (flagOne)) == -1) 
        {
            fprintf (stderr, "setsockopt() failed with error: %d", errno);
            return;
        }

        // Send the packet using sendto() for sending datagrams.
        if (sendto (sock, packets, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
        {
            fprintf (stderr, "sendto() failed with error: %d", errno);
            return;
        }
      }
    }
  }
}


int main() {
    int PACKET_LEN = 512;
    char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // Create the raw socket
    int sock = socket(AF_PACKET, SOCK_RAW,  htons(ETH_P_ALL));  

    // Turn on the promiscuous mode. 
    mr.mr_type = PACKET_MR_PROMISC;                           
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr,  
                     sizeof(mr));

    // Getting captured packets
    while (1) {
        int data_size=recvfrom(sock, buffer, PACKET_LEN, 0,  
	                 &saddr, (socklen_t*)sizeof(saddr));
        if(data_size) {
          got_packet(buffer);
        }
    }

    close(sock);
    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}