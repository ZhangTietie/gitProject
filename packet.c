#include <stdio.h>
#include <sys/ioctl.h> 
#include <netinet/ip.h> 
#include <netinet/udp.h>  
#include <net/if.h> 
#include <net/ethernet.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <string.h>

#define BUFFER_LEN 1024
#define TYPE_INDEX 23
#define ID_INDEX 38
#define SEQ_INDEX 40
#define IP_INDEX 26

uint16_t in_cksum(uint16_t *addr, int len)  
{  
	int             nleft = len;  
	uint32_t        sum = 0;  
	uint16_t        *w = addr;  
	uint16_t        answer = 0;  

	while (nleft > 1)  {  
		sum += *w++;  
		nleft -= 2;  
	}  

	if (nleft == 1) {  
		*(unsigned char *)(&answer) = *(unsigned char *)w ;  
		sum += answer;  
	}  

	sum = (sum >> 16) + (sum & 0xffff);  
	sum += (sum >> 16);  
	answer = ~sum;  
	return(answer);  
}  

int create_sock(void) {
	int res_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (res_sock == -1) {
		perror("Create server sock error");
		exit(-1);
	}
	return res_sock;
}

bool read_data(char *buf, int sock) {
	// use udp
	int len = recvfrom(sock, buf, BUFFER_LEN-1, 0, NULL, NULL);
	if (len == -1) {
		perror("Recv data from socket error");
		return false;
	}
	return true;
}

bool is_icmp(char *main_data) {
	char protype = main_data[TYPE_INDEX];
	return protype == IPPROTO_ICMP;
}

void get_dest_ip(char *ip, const char *data){
	sprintf(ip, "%d.%d.%d.%d", data[IP_INDEX]&0xff, data[IP_INDEX+1]&0xff, data[IP_INDEX+2]&0xff, data[IP_INDEX+3]&0xff);
}

void get_src_ip(char *ip, const char *data) {
	sprintf(ip, "%d.%d.%d.%d", data[IP_INDEX+4]&0xff, data[IP_INDEX+5]&0xff, data[IP_INDEX+6]&0xff, data[IP_INDEX+7]&0xff);
}

short get_id(const char *buf) {
	short res = *(short *)(buf + ID_INDEX);
	return ntohs(res);
}

short get_sequence(const char *buf) {
	short res = *(short *)(buf + SEQ_INDEX);
	return ntohs(res);
}

void construct_response(char *packet, char *dest_ip, short id, short sequence) {
    struct iphdr *ip, *ip_reply;
    struct icmphdr* icmp;
    struct sockaddr_in connection;
    char *dst_addr= dest_ip;
    char *src_addr= "37.139.29.127";
    char *buffer;
    int sockfd, optval, addrlen;

    ip = (struct iphdr*) packet;
    icmp = (struct icmphdr*) (packet + sizeof(struct iphdr));

    ip->ihl         = 5;
    ip->version     = 4;
    ip->tot_len     = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip->protocol    = IPPROTO_ICMP;
    ip->saddr       = inet_addr(src_addr);
    ip->daddr       = inet_addr(dst_addr);
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr)); 

	bzero(icmp, sizeof(struct icmphdr));
    icmp->type      = ICMP_ECHOREPLY;
	icmp->code      = 0;
	icmp->un.echo.sequence = htons(sequence);
	icmp->un.echo.id = htons(id);
    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr));

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

	optval = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int));

    connection.sin_family       = AF_INET;
    connection.sin_addr.s_addr  = ip->daddr;
    sendto(sockfd, packet, ip->tot_len, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
	close(sockfd);
}


int main() {

	int	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sockfd == -1) {
		perror("Create sockfd error");
		exit(-1);
	}

	printf("Create sock ok\n");
	while (1) {
		char buffer[BUFFER_LEN] = "";

		if(!read_data(buffer, sockfd) || !is_icmp(buffer)) {
			continue;
		}

		printf("Get icmp packet\n");
		char packet[1024] = "";
		char srcip[32] = "";
		char destip[32] = "";
		get_src_ip(srcip, buffer);
		get_dest_ip(destip, buffer);
		printf("icmp %s=>%s\n", destip, srcip);
		construct_response(packet, destip, get_id(buffer), get_sequence(buffer));
	}
	return 0;
}
