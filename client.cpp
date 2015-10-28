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

#pragma comment(lib, "ws2_32.lib") //WinSock lib
#pragma comment(lib, "IPHLPAPI.lib") //IP Helper lib

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
*This function returns the device to capture on
*returns: device if successful otherwise returns NULL
*/
pcap_t* get_handle() {
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
 *Used to send packets to server using cc
 */
int send_packet(pcap_t* fp) {
	mac_values* values = (mac_values*)malloc((sizeof(int) * 6));
	get_mac(&values);
	u_char packet[102];


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

	//UDP Header
	//source port
	packet[34] = 0;
	packet[35] = 53;
	//destination port
	packet[36] = 0;
	packet[37] = 53;
	//length in bytes of udp header
	packet[38] = 0;
	packet[39] = 68;
	//checksum
	packet[40] = 70;
	packet[41] = 70;

	//DNS Header
	//id
	packet[42] = 54;
	packet[43] = 54;
	//flags and opcodes
	//128: response 0: standard query 0: not authority 0: truncate bit 0: recursion desired
	packet[44] = 128;
	//0: recusion available 0: z bit 0: authentication data 0: checking disabled 0: reply code
	packet[45] = 0;
	//total questions
	packet[46] = 0;
	packet[47] = 1;
	//total answers
	packet[48] = 0;
	packet[49] = 1;
	/////////////////ERROR WITH ORDER////////////////////
	//authority rr
	packet[50] = 0;
	packet[51] = 0;
	//additional rr
	packet[52] = 0;
	packet[53] = 0;
	
	//DNS Response Question and Answer
	//Query Name www.hello.com
	packet[54] = 3;
	packet[55] = 119;
	packet[56] = 119;
	packet[57] = 119;
	packet[58] = 5;
	packet[59] = 104;
	packet[60] = 101;
	packet[61] = 108;
	packet[62] = 108;
	packet[63] = 111;
	packet[64] = 3;
	packet[65] = 99;
	packet[66] = 111;
	packet[67] = 109;
	packet[68] = 0;
	//type
	packet[69] = 0;
	packet[70] = 60;
	//class
	packet[71] = 0; 
	packet[72] = 1; //internet
	//Answer
	//Name www.hello.com
	packet[73] = 3;
	packet[74] = 119;
	packet[75] = 119;
	packet[76] = 119;
	packet[77] = 5;
	packet[78] = 104;
	packet[79] = 101;
	packet[80] = 108;
	packet[81] = 108;
	packet[82] = 111;
	packet[83] = 3;
	packet[84] = 99;
	packet[85] = 111;
	packet[86] = 109;
	packet[87] = 0;
	//type
	packet[88] = 0;
	packet[89] = 60;
	//class
	packet[90] = 0;
	packet[91] = 1;//internet
	//time to live
	packet[92] = 0;
	packet[93] = 0;
	packet[94] = 0;
	packet[95] = 255;
	//rdata length
	packet[96] = 0;
	packet[97] = 4;
	//data ip address
	packet[98] = 192;
	packet[99] = 168;
	packet[100] = 1;
	packet[101] = 1;

	/* Fill the rest of the packet 
	for (int i = 97;i<100;i++)
	{
		packet[i] = i % 256;
	}*/

	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, 102 /* size */) != 0)
	{
		std::cout << "\nError sending the packet: \n" << pcap_geterr(fp) << std::endl;
		return -1;
	}
	/////////////////////////////////////////////////////////////
	return 0;
}

int main()
{
	//device is pointer to list of devices
	pcap_t* adhandle = get_handle();
	if (adhandle == NULL)
		return -1;

	//captures packets using winpcap driver
	//capture ip traffic

	//send dns packets
	if (send_packet(adhandle) == -1) {
		return -1;
	}
	
	int temp = 0;
	std::cin >> temp;
    return 0;
}

