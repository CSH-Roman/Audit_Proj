// client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include <IPHlpApi.h>
#include "pcap.h"

#pragma comment(lib, "ws2_32.lib") //WinSock lib
#pragma comment(lib, "IPHLPAPI.lib") //IP Helper lib

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
 *returns: the mac address of local machine
 */
void get_mac(mac_values** values) {
	IP_ADAPTER_INFO *info = NULL, *pos;
	DWORD size = 0;

	GetAdaptersInfo(info, &size);

	info = (IP_ADAPTER_INFO *)malloc(size);
	
	GetAdaptersInfo(info, &size);

	pos = info;
	if(pos != NULL) {
		printf("\n%s\n\t", pos->Description);
		printf("%2.2x", pos->Address[0]);
		(*values)->value0 = (int)pos->Address[0];
		for (int i = 1; i < pos->AddressLength; i++) {
			printf(":%2.2x", pos->Address[i]);
			switch (i) {
				case 1:
					(*values)->value1 = (int)pos->Address[i];
					break;
				case 2:
					(*values)->value2 = (int)pos->Address[i];
					break;
				case 3:
					(*values)->value3 = (int)pos->Address[i];
					break;
				case 4:
					(*values)->value4 = (int)pos->Address[i];
					break;
				case 5:
					(*values)->value5 = (int)pos->Address[i];
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
	u_char packet[100];

	// set mac destination to 
	packet[0] = 1;
	packet[1] = 1;
	packet[2] = 1;
	packet[3] = 1;
	packet[4] = 1;
	packet[5] = 1;

	// set mac source to 
	packet[6] = 'E0';
	packet[7] = 25;
	packet[8] = 20;
	packet[9] = 90;
	packet[10] = 15;
	packet[11] = 50;

	/* Fill the rest of the packet */
	for (int i = 12;i<100;i++)
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
	mac_values* values= (mac_values*) malloc((sizeof(int) *6));
	get_mac(&values);
	u_char packet[100];

	// need hex converter function 
	packet[0] = values->value0;
	packet[1] = values->value1;
	packet[2] = values->value2;
	packet[3] = values->value3;
	packet[4] = values->value4;
	packet[5] = values->value5;
	free(values);

	for (int i = 0; i < 6; i++) {
		std::cout << packet[i] << std::endl;
	}

	//captures packets using winpcap driver
	/*pcap_t* adhandle = get_handle();//device is pointer to list of devices
	if (adhandle == NULL)
		return -1;

	//capture ip traffic
	//send dns packets
	if (send_packet(adhandle) == -1) {
		return -1;
	}*/
	int temp = 0;
	std::cin >> temp;
    return 0;
}

