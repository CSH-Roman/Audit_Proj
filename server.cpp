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
#include <fstream>

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

// TCP header used for hand shake
typedef struct tcp_head{
	u_short sport;			//source port
	u_short dport;			//destination port
	u_int seq_num;			//sequence number
	u_int ack_num;			//acknowledgement number
	u_char data_off;		//data offset
	u_char control_bits;	//control bits
	u_short window;			//window
	u_short chk;			//checksum
	u_short urg_pointer;	//urgent pointer
}tcp_head;

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

//contains the values of the ip address as ints
typedef struct ip_address {
	u_char octet1;
	u_char octet2;
	u_char octet3;
	u_char octet4;
}ip_address_strc;

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
	ip_address_strc saddr;			// Source address
	ip_address_strc daddr;			// Destination address
	u_int   op_pad;         // Option + Padding
}IPv4;

//function prototypes
int send_packet(std::string address, std::string mac_addr, std::string option, bool ack);
int decapsulate(const u_char *data, int size);
void get_ip(std::vector<std::string>& ip_addresses);
void ipv4_address(std::vector<std::string>& lines_vect, std::vector<std::string>& ip_addresses);
void split(const std::string& s, char delim, std::vector<std::string>& v);
void get_mac(mac_values** values);
pcap_t* get_handle(pcap_if_t** first_device);
int size_of_list(pcap_if_t*  list);
int mode_manager(std::string option, std::string address, std::string mac_addr);
int connected_mode_send(std::string address, std::string mac_addr, std::string option, std::string command);
DWORD WINAPI command_console(PVOID pPARAM);
DWORD WINAPI capture(PVOID pPARAM);

int main()
{
	//send_packet("127.0.0.1", "40:25:c2:c0:15:51", "1", false);
	
	InitializeCriticalSection(&HandleLock);

	//trying the multithreaded prog
	DWORD id;
	HANDLE hCapture = CreateThread(NULL, 0, capture, (PVOID)1, 0, &id);
	HANDLE hSender = CreateThread(NULL, 0, command_console, (PVOID)2, 0, &id);
	
	//Wait for objects
	WaitForSingleObject(hCapture, INFINITE);
	//WaitForSingleObject(hSender, INFINITE);
	//release resources of critical sections
	DeleteCriticalSection(&HandleLock);
	
	int temp = 0;
	std::cin >> temp;
    return 0;
}

/*
 *This function will handle what modes options are run in.
 *It will also handle user interaction with the interface.
 *Parameters: option (str), dst IP address (str), src IP address (str)
 *Return: 0 success, 1 Failure
 */
int mode_manager(std::string option, std::string address, std::string mac_addr) {
	//enter connected mode to send and receive packets
	if (option == "1") {
		std::string command = "";
		std::cout << "1)Enter command" << std::endl;
		std::cin >> command;
		//send packet
		send_packet(address, mac_addr, option, false);
		//check for response
		//enter command mode
		connected_mode_send(address, mac_addr, option, command);
	}
	//enter connection-less mode
	else if(option == "2"){
		//send packet with specific header length
	}
	else
		return 1; //error

	return 0; //success
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
		mode_manager(option, address, mac_addr);
	}
	else
		mode_manager(option, address, mac_addr);

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
	if (pcap_compile(adhandle, &opcode, "ip", 1, netmask) < 0) {
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

/*
*Used to send ip packets
*returns: success of packet being sent
*/
int connected_mode_send(std::string address, std::string mac_addr, std::string option, std::string command) {
	mac_values* values = (mac_values*)malloc((sizeof(int) * 6));
	mac_values* mac_address = (mac_values*)malloc((sizeof(int) * 6));
	get_mac(&values);
	u_char packet[162];
	
	std::vector<std::string> mac_val;
	split(mac_addr, ':', mac_val);
	mac_address->value0 = atoi(mac_val[0].c_str());
	mac_address->value1 = atoi(mac_val[1].c_str());
	mac_address->value2 = atoi(mac_val[2].c_str());
	mac_address->value3 = atoi(mac_val[3].c_str());
	mac_address->value4 = atoi(mac_val[4].c_str());
	mac_address->value5 = atoi(mac_val[5].c_str());

	//destination mac address
	packet[0] = mac_address->value0;
	packet[1] = mac_address->value1;
	packet[2] = mac_address->value2;
	packet[3] = mac_address->value3;
	packet[4] = mac_address->value4;
	packet[5] = mac_address->value5;
	free(mac_address);
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
	int size = 0;
	if (option == "1") {
		packet[14] = 69; //64 represents 4=>IPv4  5 represents minimum ipv4 length
		//get packet size
		int com_len = command.length();
		size = 60; //needs this for sending packet function
		
		std::cout << "I've sent the packet boss." << std::endl;
		//sending ack packet
		std::ifstream myfile("psh_ack_tcp_header.txt");
		if (myfile.is_open()) {
			std::string line;
			getline(myfile, line);
			std::vector<std::string> bytes;
			split(line, ' ', bytes);
			int index = 0;
			for (int i = 34; i < 54; i++) {
				packet[i] = atoi(bytes[index].c_str());
				index++;
			}
			myfile.close();
		}

		//set ssl header
		packet[55] = 23;  //packet type
		//version 1.1
		packet[56] = 1;   //major 1
		packet[57] = 2;   //minor 1
		//length
		packet[58] = 0;   //high
		packet[59] = 2;   //low
		//data
		int index = 60; //start index
		for (int x = 0; x < command.length(); x++) {
			packet[index] = command[x];
		}
		
	}
	else if (option == "2") {
		//this will represent something else
	}
	else
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
	packet[23] = 6;  //must be set to detect layer 4 protocols
					 //header checksum
	packet[24] = 39;
	packet[25] = 50;

	//getting all ip addresses from ipconfig command
	std::vector<std::string> ip_addresses;
	get_ip(ip_addresses);
	ip_addr* ip_address = (ip_addr*)malloc((sizeof(int) * 4));
	ip_addr* dest_addr = (ip_addr*)malloc((sizeof(int) * 4));
	//source address
	std::vector<std::string> octets;
	split(ip_addresses[0], '.', octets);
	ip_address->octet1 = atoi(octets[0].c_str());
	ip_address->octet2 = atoi(octets[1].c_str());
	ip_address->octet3 = atoi(octets[2].c_str());
	ip_address->octet4 = atoi(octets[3].c_str());

	//destination address
	std::vector<std::string> octs;
	split(address, '.', octs);
	dest_addr->octet1 = atoi(octs[0].c_str());
	dest_addr->octet2 = atoi(octs[1].c_str());
	dest_addr->octet3 = atoi(octs[2].c_str());
	dest_addr->octet4 = atoi(octs[3].c_str());

	//source ip address
	packet[26] = ip_address->octet1;
	packet[27] = ip_address->octet2;
	packet[28] = ip_address->octet3;
	packet[29] = ip_address->octet4;
	//destination ip address
	packet[30] = dest_addr->octet1;
	packet[31] = dest_addr->octet2;
	packet[32] = dest_addr->octet3;
	packet[33] = dest_addr->octet4;
	free(ip_address);

	std::cout << "made it here" << std::endl;
	/* Send the packet */
	EnterCriticalSection(&HandleLock);
	pcap_if_t* first_device;
	pcap_t* fp = get_handle(&first_device);
	if (fp == NULL) {
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	if (pcap_sendpacket(fp, packet, size /* size */) != 0)
	{
		std::cout << "\nError sending the packet: \n" << pcap_geterr(fp) << std::endl;
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	LeaveCriticalSection(&HandleLock);

	return 0;
}

/*
*Used to send ip packets
*returns: success of packet being sent
*/
int send_packet(std::string address, std::string mac_addr, std::string option, bool ack) {
	mac_values* values = (mac_values*)malloc((sizeof(int) * 6));
	mac_values* mac_address = (mac_values*)malloc((sizeof(int) * 6));
	get_mac(&values);
	u_char packet[62];

	std::vector<std::string> mac_val;
	split(mac_addr, ':', mac_val);
	mac_address->value0 = atoi(mac_val[0].c_str());
	mac_address->value1 = atoi(mac_val[1].c_str());
	mac_address->value2 = atoi(mac_val[2].c_str());
	mac_address->value3 = atoi(mac_val[3].c_str());
	mac_address->value4 = atoi(mac_val[4].c_str());
	mac_address->value5 = atoi(mac_val[5].c_str());

	//destination mac address
	packet[0] = mac_address->value0;
	packet[1] = mac_address->value1;
	packet[2] = mac_address->value2;
	packet[3] = mac_address->value3;
	packet[4] = mac_address->value4;
	packet[5] = mac_address->value5;
	free(mac_address);
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
	int size = 0;
	if (option == "1") {
		packet[14] = 70;
		size = 58;
		//need to set option length
		for (int i = 34; i < 38; i++) {
			packet[i] = i % 256;
		}

		if (ack == true) {
			std::cout << "I've sent the packet boss." << std::endl;
			//sending ack packet
			std::ifstream myfile("ack_tcp_header.txt");
			if (myfile.is_open()) {
				std::string line;
				getline(myfile, line);
				std::vector<std::string> bytes;
				split(line, ' ', bytes);
				int index = 0;
				for (int i = 38; i < 58; i++) {
					packet[i] = atoi(bytes[index].c_str());
					index++;
				}
				myfile.close();
			}
		}
		else {
			//sending syn packet
			std::ifstream myfile("syn_tcp_header.txt");
			if (myfile.is_open()) {
				std::string line;
				getline(myfile, line);
				std::vector<std::string> bytes;
				split(line, ' ', bytes);
				int index = 0;
				for (int i = 38; i < 58; i++) {
					packet[i] = atoi(bytes[index].c_str());
					index++;
				}
				myfile.close();
			}
		}
	}
	else if (option == "2") {
		packet[14] = 71;
		size = 62;
		//need to set option length
		for (int i = 34; i < 42; i++) {
			packet[i] = i % 256;
		}
		//sending syn packet
		std::ifstream myfile("syn_tcp_header.txt");
		if (myfile.is_open()) {
			std::string line;
			getline(myfile, line);
			std::vector<std::string> bytes;
			split(line, ' ', bytes);
			int index = 0;
			for (int i = 42; i < 62; i++) {
				packet[i] = atoi(bytes[index].c_str());
				index++;
			}
			myfile.close();
		}
	}
	else
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
	packet[23] = 6;  //must be set to detect layer 4 protocols
					 //header checksum
	packet[24] = 39;
	packet[25] = 50;

	//getting all ip addresses from ipconfig command
	std::vector<std::string> ip_addresses;
	get_ip(ip_addresses);
	ip_addr* ip_address = (ip_addr*)malloc((sizeof(int) * 4));
	ip_addr* dest_addr = (ip_addr*)malloc((sizeof(int) * 4));
	//source address
	std::vector<std::string> octets;
	split(ip_addresses[0], '.', octets);
	ip_address->octet1 = atoi(octets[0].c_str());
	ip_address->octet2 = atoi(octets[1].c_str());
	ip_address->octet3 = atoi(octets[2].c_str());
	ip_address->octet4 = atoi(octets[3].c_str());

	//destination address
	std::vector<std::string> octs;
	split(address, '.', octs);
	dest_addr->octet1 = atoi(octs[0].c_str());
	dest_addr->octet2 = atoi(octs[1].c_str());
	dest_addr->octet3 = atoi(octs[2].c_str());
	dest_addr->octet4 = atoi(octs[3].c_str());

	//source ip address
	packet[26] = ip_address->octet1;
	packet[27] = ip_address->octet2;
	packet[28] = ip_address->octet3;
	packet[29] = ip_address->octet4;
	//destination ip address
	packet[30] = dest_addr->octet1;
	packet[31] = dest_addr->octet2;
	packet[32] = dest_addr->octet3;
	packet[33] = dest_addr->octet4;
	free(ip_address);


	/* Send the packet */
	EnterCriticalSection(&HandleLock);
	pcap_if_t* first_device;
	pcap_t* fp = get_handle(&first_device);
	if (fp == NULL) {
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	if (pcap_sendpacket(fp, packet, size /* size */) != 0)
	{
		std::cout << "\nError sending the packet: \n" << pcap_geterr(fp) << std::endl;
		LeaveCriticalSection(&HandleLock);
		return -1;
	}
	LeaveCriticalSection(&HandleLock);

	return 0;
}

/*
*This function will decapsulate packets
*and call functions if needed
*renturns nothing
*/
int decapsulate(const u_char *data, int size) {
	eth_header* eth_hdr;
	eth_hdr = (eth_header*)data;
	IPv4* ih;
	u_int head_len;
	tcp_head* th;
	udp_header* uh;
	u_short sport;
	u_short dport;
	dns_header* dns_h;
	dns_payload* dns_pay;

	if (ntohs(eth_hdr->type) == 0x800) {
		// retireve the position of the ip header
		ih = (IPv4 *)(data + 14); //length of ethernet header

		int ip_head_len = (int)ih->ver_ihl - 64;

		//looks for packets that have options
		if (ip_head_len > 5) {
			//get ip address as string
			std::string address = "";
			char octet[4];
			_itoa_s((int)ih->saddr.octet1, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.octet2, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.octet3, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.octet4, octet, 10);
			address = address + octet;

			//get mac address as string
			std::string mac_address = "";
			char byte[4];
			_itoa_s((int)eth_hdr->src[0], byte, 10);
			mac_address = mac_address + byte + ':';
			_itoa_s((int)eth_hdr->src[1], byte, 10);
			mac_address = mac_address + byte + ':';
			_itoa_s((int)eth_hdr->src[2], byte, 10);
			mac_address = mac_address + byte + ':';
			_itoa_s((int)eth_hdr->src[3], byte, 10);
			mac_address = mac_address + byte + ':';
			_itoa_s((int)eth_hdr->src[4], byte, 10);
			mac_address = mac_address + byte + ':';
			_itoa_s((int)eth_hdr->src[5], byte, 10);
			mac_address = mac_address + byte;

			if ((int)ih->proto == 6) {
				std::cout << "Capturing TCP" << std::endl;
				//get tcp header
				head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
				th = (tcp_head *)((u_char*)ih + head_len);

				//check control bit number
				if ((int)th->control_bits == 18) {
					//send syn ack
					send_packet(address, mac_address, "1", true);
					return 1;
				}
			}

			if ((int)ih->proto == 17) {
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
					return 2;
				}
			}
		}

	}
	return 0;
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
	if (pos != NULL) {
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