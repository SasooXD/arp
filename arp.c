#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETH_P_ARP 0x0806
#define ETH_FRAME_LEN 42

void handle_error(const char *msg, int sock)
{
	perror(msg);
	if (sock >= 0)
		close(sock);
	exit(EXIT_FAILURE);
}

void get_mac_address(const char *iface, int sock, unsigned char *mac)
{
	struct ifreq if_mac;
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)
		handle_error("SIOCGIFHWADDR failed", sock);
	memcpy(mac, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
}

void get_ip_address(const char *iface, int sock, unsigned char *ip)
{
	struct ifreq if_ip;
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFADDR, &if_ip) < 0)
		handle_error("SIOCGIFADDR failed", sock);
	struct sockaddr_in *ip_addr = (struct sockaddr_in *)&if_ip.ifr_addr;
	memcpy(ip, &ip_addr->sin_addr, 4);
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: %s [interface] [target_ip]\n", argv[0]);
		return EXIT_FAILURE;
	}

	const char *iface = argv[1];
	const char *target_ip_str = argv[2];
	unsigned char target_ip[4];

	if (inet_pton(AF_INET, target_ip_str, target_ip) != 1)
	{
		fprintf(stderr, "Invalid IP address: %s\n", target_ip_str);
		return EXIT_FAILURE;
	}

	unsigned char buffer[ETH_FRAME_LEN];
	unsigned char src_mac[ETH_ALEN], src_ip[4];
	unsigned char broadcast_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0)
		handle_error("Socket creation failed", -1);

	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
		handle_error("SIOCGIFINDEX failed", sock);

	get_mac_address(iface, sock, src_mac);
	get_ip_address(iface, sock, src_ip);

	memset(buffer, 0, ETH_FRAME_LEN);

	struct ethhdr *eth = (struct ethhdr *)buffer;
	memcpy(eth->h_dest, broadcast_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_ARP);

	struct ether_arp
	{
		unsigned short ar_hrd;	 // Hardware type
		unsigned short ar_pro;	 // Protocol type
		unsigned char ar_hln;	 // Hardware size
		unsigned char ar_pln;	 // Protocol size
		unsigned short ar_op;	 // Opcode
		unsigned char ar_sha[6]; // Sender hardware address
		unsigned char ar_sip[4]; // Sender IP address
		unsigned char ar_tha[6]; // Target hardware address
		unsigned char ar_tip[4]; // Target IP address
	};

	struct ether_arp *arp = (struct ether_arp *)(buffer + sizeof(struct ethhdr));
	arp->ar_hrd = htons(ARPHRD_ETHER);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = ETH_ALEN;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARP_REQUEST);
	memcpy(arp->ar_sha, src_mac, ETH_ALEN);
	memcpy(arp->ar_sip, src_ip, 4);
	memset(arp->ar_tha, 0, ETH_ALEN);
	memcpy(arp->ar_tip, target_ip, 4);

	struct sockaddr_ll socket_address;
	memset(&socket_address, 0, sizeof(struct sockaddr_ll));
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;
	memcpy(socket_address.sll_addr, broadcast_mac, ETH_ALEN);

	if (sendto(sock, buffer, ETH_FRAME_LEN, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0)
		handle_error("sendto failed", sock);

	while (1)
	{
		unsigned char recv_buffer[ETH_FRAME_LEN];
		ssize_t recv_len = recv(sock, recv_buffer, ETH_FRAME_LEN, 0);
		if (recv_len < 0)
			handle_error("recv failed", sock);

		struct ethhdr *recv_eth = (struct ethhdr *)recv_buffer;
		if (ntohs(recv_eth->h_proto) == ETH_P_ARP)
		{
			struct ether_arp *recv_arp = (struct ether_arp *)(recv_buffer + sizeof(struct ethhdr));
			if (ntohs(recv_arp->ar_op) == ARP_REPLY && memcmp(recv_arp->ar_tip, src_ip, 4) == 0)
			{
				printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
					   recv_arp->ar_sha[0], recv_arp->ar_sha[1], recv_arp->ar_sha[2],
					   recv_arp->ar_sha[3], recv_arp->ar_sha[4], recv_arp->ar_sha[5]);
				break;
			}
		}
	}

	close(sock);
	return 0;
}
