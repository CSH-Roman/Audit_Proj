// client.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <iostream>
#include <string>
#include "pcap.h"

#pragma comment(lib, "ws2_32.lib") //WinSock lib

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
 *Used to send packets to server using cc
 */
int send_packet(pcap_t* fp) {
	u_char packet[100];

	//need to convert hexidecimal to decimal
	// set mac destination to 
	packet[0] = 1;
	packet[1] = 1;
	packet[2] = 1;
	packet[3] = 1;
	packet[4] = 1;
	packet[5] = 1;

	// set mac source to 
	packet[6] = 40;
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
	//captures packets using winpcap driver
	pcap_t* adhandle = get_handle();//device is pointer to list of devices
	if (adhandle == NULL)
		return -1;

	//capture ip traffic
	//send dns packets
	if (send_packet(adhandle) == -1) {
		return -1;
	}
	int temp = 0;
	std::cin >> temp;
    return 0;
}

