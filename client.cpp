// client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include <IPHlpApi.h>
#include "pcap.h"
#include <bitset>
#include <vector>
#include <Windows.h>

#define MAX_THREADS 2
CRITICAL_SECTION HandleLock;

#pragma comment(lib, "ws2_32.lib") //WinSock lib
#pragma comment(lib, "IPHLPAPI.lib") //IP Helper lib

//contains the dns packet data
typedef struct dns_payload {
	u_char size;
	u_char junk;
	u_char junk2;
}dns_payload;

//dns header
typedef struct dns_header {
	u_short identifier;
	u_short flags_codes;
	u_short qcount;
	u_short acount;
	u_short nscount;
	u_short arcount;
}dns_header;

// UDP header used for dns packets
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/*
*This struct will be used to decode Ethernet headers
*/
typedef struct eth_header {
	u_char dest[6];
	u_char src[6];
	u_short type;
}eth_header;

//contains the values of mac address as integers
typedef struct mac_values {
	int value0;
	int value1;
	int value2;
	int value3;
	int value4;
	int value5;
}mac_values;

//contains the values of the ip address as ints
typedef struct ip_addr {
	int octet1;
	int octet2;
	int octet3;
	int octet4;
}ip_addr;

/*
*This struct will be used to decapsulate ipv4 headers
*/
typedef struct IPv4 {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_addr saddr;			// Source address
	ip_addr  daddr;			// Destination address
	u_int   op_pad;         // Option + Padding
}IPv4;

/*
*This function will find the size of lists created by functions in wpdpack libs
*list: should be the first point of a pcap interface list
*returns: the size of the list parameter
*/
int size_of_list(pcap_if_t*  list) {
	int size = 0;

	//loops until d is NULL and counts elements
	for (pcap_if_t* d = list; d != NULL; d = d->next) {
		//std::cout << "Printing device list" << std::endl << d->description << std::endl;
		size++;
	}

	return size;
}

/*
*This function returns the device to capture on
*returns: device if successful otherwise returns NULL
*/
pcap_t* get_handle(pcap_if_t** first_device) {
	pcap_if_t* all_devices;				//first point of interface list
	char error_msg[PCAP_ERRBUF_SIZE];	//error message buffer

	//returns on error
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devices, error_msg) == -1) {
		std::cout << "did not get device list" << std::endl;
		return NULL;
	}

	//returns if no interfaces
	if (size_of_list(all_devices) == 0) {
		return NULL;
	}

	//select interface
	//In this case inteface selected is the second interface
	pcap_if_t* device = all_devices;
	if (device != NULL) {
		char error_msg[PCAP_ERRBUF_SIZE];	//error message buffer
		pcap_t* adhandle;					//stores the handle created by pcap_open for pcap_next_ex to read packets
											
		if ((adhandle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, error_msg)) == NULL) {
			pcap_freealldevs(device);
			return NULL;
		}
		(*first_device) = all_devices;
		return adhandle;
	}

	return NULL;
}

/*
 *This function will get the mac address of the local machine
 *and enter it into a values struct
 *returns: the mac address of local machine in values struct
 */
void get_mac(mac_values** values) {
	IP_ADAPTER_INFO *info = NULL, *pos;
	DWORD size = 0;

	GetAdaptersInfo(info, &size);
	info = (IP_ADAPTER_INFO *)malloc(size);
	GetAdaptersInfo(info, &size);
	
	pos = info;
	if(pos != NULL) {
		/////////interate over adapters///////////////
		(*values)->value0 = pos->Address[0];
		for (u_int i = 1; i < pos->AddressLength; i++) {
			//printf("%2.2x", pos->Address[i]);
			switch (i) {
				case 1:
					(*values)->value1 = pos->Address[1];
					break;
				case 2:
					(*values)->value2 = pos->Address[2];
					break;
				case 3:
					(*values)->value3 = pos->Address[3];
					break;
				case 4:
					(*values)->value4 = pos->Address[4];
					break;
				case 5:
					(*values)->value5 = pos->Address[5];
					break;
				default:
					break;
			}
		}
	}
	free(info);
}

/*
*This function will split a string based on
*the character to passed to it and insert the
*parts into a vector
*/
void split(const std::string& s, char delim, std::vector<std::string>& v) {
	std::string::size_type i = 0;
	std::string::size_type j = s.find(delim);

	while (j != std::string::npos) {
		v.push_back(s.substr(i, j - i));
		i = ++j;
		j = s.find(delim, j);

		if (j == std::string::npos)
			v.push_back(s.substr(i, s.length()));
	}
}

/*
 *Finds lines that contain ipv4 addresses
 *returns: ipv4 addresses inside vector
 */
void ipv4_address(std::vector<std::string>& lines_vect, std::vector<std::string>& ip_addresses) {
	std::size_t found;
	
	for (int i = 0; i < lines_vect.size(); i++) {
		found = lines_vect[i].find("IPv4");
		if (found != std::string::npos) {
			std::vector<std::string> name_ip;
			std::vector<std::string> space_ip;
			split(lines_vect[i], ':', name_ip);
			split(name_ip[1], ' ', space_ip);
			ip_addresses.push_back(space_ip[1]);
		}
	}

}

/*
 *This function will get the ip address of the current machine
 *returns: ip_addr struct
 */
void get_ip(std::vector<std::string>& ip_addresses) {
	//take address from captured response
	const char* cmd = "ipconfig";
	char buffer[128];
	std::string result = "";
	std::vector<std::string> lines;
	FILE* _pipe = _popen(cmd, "r");

	//redirects stdout to pipe and adds elements of buffer to result string
	if (!_pipe) {
		std::cout << "ERROR" << std::endl;
	}

	while (!feof(_pipe)) {
		if (fgets(buffer, 128, _pipe) != NULL)
			result += buffer;
	}
	_pclose(_pipe);

	split(result, '\n', lines);
	ipv4_address(lines, ip_addresses);
}

/*
*This function will decapsulate packets
*and call functions if needed
*renturns nothing
*/
void decapsulate(const u_char *data, int size) {
	eth_header* eth_hdr;
	eth_hdr = (eth_header*)data;
	IPv4* ih;
	u_int head_len;
	//tcp_head* th;
	udp_header* uh;
	u_short sport;
	u_short dport;
	dns_header* dns_h;
	dns_payload* dns_pay;

	if (ntohs(eth_hdr->type) == 0x800) {
		// retireve the position of the ip header
		ih = (IPv4 *)(data + 14); //length of ethernet header

								  // print ip addresses
		printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
			ih->saddr.octet1,
			ih->saddr.octet2,
			ih->saddr.octet3,
			ih->saddr.octet4,
			ih->daddr.octet1,
			ih->daddr.octet2,
			ih->daddr.octet3,
			ih->daddr.octet4);

		//get tcp header
		/*ip_head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
		th = (tcp_head *)((u_char*)ih + ip_head_len);*/

		//get udp header = pointer + length of ipheader
		head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
		uh = (udp_header *)((u_char*)ih + head_len);

		//convert form network byte order to host byte order
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);

		std::cout << "source " << sport << "dest " << dport << "length " << head_len << std::endl;

		//dns header = point + udp header
		head_len = 8; //standard length of udp header is 8 bytes
		dns_h = (dns_header *)((u_char*)uh + head_len);

		//std::cout << "Identifier " << dns_h->identifier << std::endl;
		printf("Identifier %2.2x", dns_h->identifier);
		//determine if the packet is a response or request
		std::bitset<16> id(dns_h->flags_codes);
		std::cout << "QR: " << id[7] << std::endl;//bytes swap lsb
		if (id[7] == 1) {
			//dns payload= pointer + dns header size
			head_len = 12;
			dns_pay = (dns_payload *)((u_char*)dns_h + head_len);

			u_char* domain_char = (u_char*)dns_h + head_len;
			u_int index = 0;
			//loop to the end of question field
			while (*domain_char != 0) {
				domain_char = (u_char*)dns_h + head_len + index;
				std::cout << domain_char << std::endl;
				index++;
			}
			std::cout << index << std::endl;
			u_char* type = (u_char*)dns_pay + index + 1;//grab least sign bit
			int lsb = (int)*type;
			type = type - 1;//grab most sig bit
			int msb = (int)*type;
			msb = msb * 256;
			int type_val = msb + lsb;
			std::cout << "Type: " << type_val << std::endl;
			//Use value returned by type for messages
		}
	}
}

/*
 *Used to send ip packets
 *returns: success of packet being sent
 */
int send_packet(std::string address, std::string mac_addr) {
	mac_values* values = (mac_values*)malloc((sizeof(int) * 6));
	get_mac(&values);
	u_char packet[34];

	////////get gateway ip address///////////
	//arp -a > "C:\Path to file
	//destination mac address
	packet[0] = values->value0;
	packet[1] = values->value1;
	packet[2] = values->value2;
	packet[3] = values->value3;
	packet[4] = values->value4;
	packet[5] = values->value5;
	//source mac address
	packet[6] = values->value0;
	packet[7] = values->value1;
	packet[8] = values->value2;
	packet[9] = values->value3;
	packet[10] = values->value4;
	packet[11] = values->value5;
	free(values);
	
	//ethernet type IPv4
	packet[12] = 8;
	packet[13] = 0;
	//version field and IHL
	packet[14] = 69; //64 represents 4=>IPv4  5 represents minimum ipv4 length
	//differentiated services
	packet[15] = 0;
	//total length =1500
	packet[16] = 5;
	packet[17] = 220;
	//identification =19142
	packet[18] = 74;
	packet[19] = 198;
	//flags don't fragment =010
	packet[20] = 64;
	//fragment offset
	packet[21] = 0;
	//TTL
	packet[22] = 255;
	//layer 4 protocol
	packet[23] = 17;  //must be set to detect layer 4 protocols
	//header checksum
	packet[24] = 39;
	packet[25] = 50;

	//getting all ip addresses from ipconfig command
	std::vector<std::string> ip_addresses;
	get_ip(ip_addresses);
	ip_addr* ip_address = (ip_addr*)malloc((sizeof(int) * 4));
	/////////////not the way to do this//////////////////
	/*for (int i = 0; i < ip_addresses.size(); i++) {
		std::vector<std::string> octets;
		split(ip_addresses[i], '.', octets);
		ip_address->octet1 = atoi(octets[0].c_str());
		ip_address->octet2 = atoi(octets[1].c_str());
		ip_address->octet3 = atoi(octets[2].c_str());
		ip_address->octet4 = atoi(octets[3].c_str());
	}*/
	/////////////////////////////////////////////////////
	std::vector<std::string> octets;
	split(ip_addresses[0], '.', octets);
	ip_address->octet1 = atoi(octets[0].c_str());
	ip_address->octet2 = atoi(octets[1].c_str());
	ip_address->octet3 = atoi(octets[2].c_str());
	ip_address->octet4 = atoi(octets[3].c_str());

	//source ip address
	packet[26] = ip_address->octet1;
	packet[27] = ip_address->octet2;
	packet[28] = ip_address->octet3;
	packet[29] = ip_address->octet4;
	//destination ip address
	packet[30] = ip_address->octet1;
	packet[31] = ip_address->octet2;
	packet[32] = ip_address->octet3;
	packet[33] = ip_address->octet4;
	free(ip_address);
	
	/* Fill the rest of the packet 
	for (int i = 97;i<100;i++)
	{
		packet[i] = i % 256;
	}*/

	/* Send down the packet */
	EnterCriticalSection(&HandleLock);
	pcap_if_t* first_device;
	pcap_t* fp = get_handle(&first_device);
	if (fp == NULL) {
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	if (pcap_sendpacket(fp, packet, 34 /* size */) != 0)
	{
		std::cout << "\nError sending the packet: \n" << pcap_geterr(fp) << std::endl;
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	LeaveCriticalSection(&HandleLock);
	
	return 0;
}

/*
 *This is the server interface for send packets
 *returns: success of operation
 */
DWORD WINAPI command_console(PVOID pPARAM) {
	//Variables
	std::string option = "";
	std::string address = "";
	std::string mac_addr = "";

	//create interface
	printf("Bot Options:\n1:Get Data\n2:Enter Commands\n");
	std::cin >> option;
	printf("Enter IP Address or 1 to List Bots:\n");
	std::cin >> address;
	printf("Enter MAC Address or 1 to List Bots:\n");
	std::cin >> mac_addr;
	if (address == "1" || mac_addr == "1") {
		address = "";
		mac_addr = "";
		//////List address function//////
		printf("Enter IP Address:\n");
		std::cin >> address;
		printf("Enter MAC Address:\n");
		std::cin >> mac_addr;
		send_packet(address, mac_addr);
	}
	else 
		send_packet(address, mac_addr);

	return 0;
}

/*
 *function will take an object containing a interface handle
 *which will be used to open a capturing session on that int
 *returns: unsigned int to help show how the thread completed execution
 */
DWORD WINAPI capture(PVOID pPARAM) {
	//add any code that does not require critical sect

	/////////////beginning of critical section/////////////
	EnterCriticalSection(&HandleLock);
	//device is pointer to list of devices
	pcap_if_t* first_device;			//pointer to first device in the list
	pcap_t* adhandle = get_handle(&first_device);	//handle of interface
	if (adhandle == NULL) {
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	struct bpf_program opcode;			//this will contain useful shit
	u_int netmask;						//this will contain the netmask of the interface capturing
	netmask = ((struct sockaddr_in*) (first_device->addresses->netmask))->sin_addr.S_un.S_addr;
	if (pcap_compile(adhandle, &opcode, "ip proto \\udp and port 53", 1, netmask) < 0) {
		pcap_freealldevs(first_device);
		LeaveCriticalSection(&HandleLock);
		return -1;
	}

	//set filter
	if (pcap_setfilter(adhandle, &opcode) < 0) {
		pcap_freealldevs(first_device);
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	pcap_freealldevs(first_device);
	LeaveCriticalSection(&HandleLock);
	/////////////end of critical section//////////////////


	//capture packets on dev
	struct pcap_pkthdr *pktHeader;		//stores packet header information
	const u_char *pkt_data;				//stores packet data
	/////////infinite loop need to change///////////
	while (pcap_next_ex(adhandle, &pktHeader, &pkt_data) >-1) {

		//inspect packet
		if (pktHeader->len > 0) {
			decapsulate(pkt_data, pktHeader->caplen);
		}
	}
	///////////////////////////////////////////////

	return 0;   // thread completed successfully
}

int main()
{
	InitializeCriticalSection(&HandleLock);
	//captures packets using winpcap driver
	//capture ip traffic

	//send dns packets
	/*if (send_packet(adhandle) == -1) {
		return -1;
	}*/
	

	//trying the multithreaded prog
	DWORD id;
	//HANDLE hCapture = CreateThread(NULL, 0, capture, (PVOID)1, 0, &id);
	HANDLE hSender = CreateThread(NULL, 0, command_console, (PVOID)2, 0, &id);
	
	//Wait for objects
	WaitForSingleObject(hSender, INFINITE);

	int temp = 0;
	std::cin >> temp;
    return 0;
}

