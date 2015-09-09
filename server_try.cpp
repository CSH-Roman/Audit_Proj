// server_try.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <WS2tcpip.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ws2_32.lib") //WinSock lib

int main(int argc, char** argv)
{
	//Initialize socket
	WSADATA wsa;
	WORD mkword = MAKEWORD(2, 2);
	int what = WSAStartup(mkword, &wsa);
	if (what != 0) {
		std::cout << "Failed to initialize socket...\n" << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "Good - Everything worked" << std::endl;
	}
	//////////////////////////////////

	//Create socket
	SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		std::cout << "Failed to create socket" << std::endl;
	}
	else
		std::cout << "Created the socket" << std::endl;
	//////////////////////////////////

	//Address
	sockaddr_in addr;
	addr.sin_port = htons(8080);
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	//////////////////////////////////

	//Bind the socket
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		std::cout << "Bind failed...\n" << WSAGetLastError << std::endl;
	}
	else
		std::cout << "Server bound to port" << std::endl;
	//////////////////////////////////

	//Listening for connections
	if (listen(s, 3) == SOCKET_ERROR) {
		std::cout << "Listening Error: " << WSAGetLastError << std::endl;
	}
	else
		std::cout << "Listening, waiting..." << std::endl;
	//////////////////////////////////

	//Accept connections
	int c = sizeof(struct sockaddr_in);
	struct sockaddr_in client;
	SOCKET new_sock;
	new_sock = accept(s, (struct sockaddr*)&client, &c);

	if (new_sock == INVALID_SOCKET) {
		std::cout << "New socket invalid socket" << WSAGetLastError << std::endl;
	}
	else
		std::cout << "Connection accepted" << std::endl;
	/*while ((new_sock = accept(s, (struct sockaddr*)&client, &c)) == INVALID_SOCKET) {
		std::cout << "connection accepted" << std::endl;

		//Reply to client
		char* message= "Hello Client";
		send(new_sock, message, strlen(message), 0);
	}*/
	
	//recv data
	char vect[512] = { 0 };
	int recv_result = recv(new_sock, vect, 512, 0);
	if (recv_result == SOCKET_ERROR) {
		std::cout << "Error in Receiving: " << WSAGetLastError() << std::endl;
	}
	else
		std::cout << recv_result << std::endl;
	//////////////////////////////////////////

	//Send data
	char* message = "Hello Client";
	send(new_sock, message, strlen(message), 0);
	//////////////////////////////////
	std::string placeholderxxx;
	std::cin >> placeholderxxx;

	//Close socket
	closesocket(s);
	WSACleanup();

    return 0;
}

