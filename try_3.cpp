// try_3.cpp : Defines the entry point for the console application.
// Purpose:  This is a functioning client

#include "stdafx.h"
#include <iostream>
#include <WS2tcpip.h>
#include <string>

//specify WinSock lib or else symbols will not match
#pragma comment(lib,"ws2_32.lib") //WinSock lib

int main()
{
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

