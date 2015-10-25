// client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include <IPHlpApi.h>
#include "pcap.h"
#include <bitset>

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
		//printf("\n%s\n\t", pos->Description);
		//printf("%2.2x", pos->Address[0]);
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
 *Used to send packets to server using cc
 */
int send_packet(pcap_t* fp) {
	mac_values* values = (mac_values*)malloc((sizeof(int) * 6));
	get_mac(&values);
	u_char packet[100];


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
	///////////Doesn't work properly//////////
	std::bitset<8> vers(packet[14]);
	//set ipv4: 1000 ihl: 1000
	vers[6] = 1;
	//set ihl equal 4
	vers[2] = 1;
	//packet[14] = 68;
	//////////////////////////////////////////
	//differentiated services
	packet[15] = 0;
	//total length =1500
	packet[16] = 5;
	packet[17] = 220;
	//identification =19142
	packet[18] = 74;
	packet[19] = 198;
	//flags don't fragment =010
	packet[20] = 0;
	/////Doesn't Work Properly/////
	std::bitset<8> flags(packet[20]);
	flags[6] = 1;
	///////////////////////////////
	//fragment offset
	packet[21] = 0;
	//TTL
	packet[22] = 255;
	//layer 4 protocol
	packet[23] = 143;
	//header checksum
	packet[24] = 39;
	packet[25] = 50;
	//source ip address
	packet[26] = 127;
	packet[27] = 0;
	packet[28] = 0;
	packet[29] = 1;
	//destination ip address
	packet[30] = 127;
	packet[31] = 0;
	packet[32] = 0;
	packet[33] = 1;

	/* Fill the rest of the packet */
	for (int i = 34;i<100;i++)
	{
		packet[i] = i % 256;
	}

	/* Send down the packet */
	if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
	{
		std::cout << "\nError sending the packet: \n" << pcap_geterr(fp) << std::endl;
		return -1;
	}
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

