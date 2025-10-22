#include "External.h"
//#define Client
// some FTP thing i was working on
#ifdef Client
#include "PersistantSockets.h"
#include <winsockx.h>
#include <string>

using namespace std;

void SendText(SOCKET sock, char* Text) {
	int Datasize = strlen(Text),
		size = Datasize;

	if(!size || sock == INVALID_SOCKET)
		return;

	string Buffer(Text);
	if(Buffer[Datasize-2] != '\r' && Buffer[Datasize-1] != '\n') {
		Buffer += "\r\n";
		size = Datasize = Buffer.length();
	}

	while(size > 0) {
		int sent = send(sock, Buffer.c_str() + (Datasize - size), size, 0);
		size -= sent;
		if(sent == -1)
			break;
	}
	Buffer.clear();
	Buffer.shrink_to_fit();
}

char RecvTextBuffer[1024],
	RecvTextB[1024];

char* RecvText(SOCKET sock) {
	ZeroMemory(RecvTextBuffer, 1024);
	ZeroMemory(RecvTextB, 1024);

	int recieved = 0,
		size;
	while(1) {
		size = 1024 - recieved;
		if((size = recv(sock, RecvTextB + recieved, size, 0)) == SOCKET_ERROR) {
			if(GetLastError() == WSAEWOULDBLOCK)
				continue;
			break;
		}

		recieved += size;
			
		int command = -1;
		for(DWORD i = 0;i < recieved;i++) {
			if(RecvTextB[i] == '\n') {
				command = i + 1;
				break;
			}
		}

		if(command == -1)
				continue;

		memcpy(RecvTextBuffer, RecvTextB, command);
		memcpy(RecvTextB, RecvTextB + command, recieved - command); // adjust the buffers accordingly
		recieved -= command;
		return RecvTextBuffer;
	}
	return "Error!\r\n";
}

bool PatchSocket(SOCKET Sock) {
	BOOL optval = TRUE;
	if(!setsockopt(Sock, SOL_SOCKET, 0x5801, (char*)&optval, sizeof(BOOL)) &&
		!setsockopt(Sock, SOL_SOCKET, 0x4, (char*)&optval, sizeof(BOOL)))
		return true;
	return false;
}

SOCKET ConnectTo(char *ServerOrIP, int port)
{
	XNetStartupParams xnsp;
	ZeroMemory(&xnsp, sizeof(xnsp));
	xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
	xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

	WSADATA ws;
	WSAStartup(MAKEWORD(2,2), &ws);
	HANDLE hEvent = WSACreateEvent();

	//Open up a socket for out TCP/IP session
	SOCKET hSocket = socket(AF_INET, SOCK_STREAM, 0);
	PatchSocket(hSocket);
	XNDNS* pxndns = NULL;

	//Set up socket information
	struct sockaddr_in httpServerAdd = {AF_INET, htons(port)};
	int nErrorCode;

	//Get the ip address
	if((httpServerAdd.sin_addr.s_addr = inet_addr(ServerOrIP)) == INADDR_NONE)// Hostname
	{
		XNetDnsLookup(ServerOrIP, hEvent, &pxndns);
		WaitForSingleObject(hEvent, INFINITE);
		WSAResetEvent(hEvent);
		if(pxndns->iStatus != 0)
		{
			nErrorCode = pxndns->iStatus;
			XNetDnsRelease(pxndns);
			shutdown(hSocket, SD_BOTH);
			closesocket(hSocket);
			goto InvalidReturn;
		}

		bool Connection = false;
		for(int i = 0; i < pxndns->cina; i++)
		{
			httpServerAdd.sin_addr = pxndns->aina[i];
			if(connect(hSocket, (struct sockaddr*)&httpServerAdd, sizeof(httpServerAdd)) == 0)
			{
				Connection = true;
				break;
			}
		}

		XNetDnsRelease(pxndns);

		if(!Connection)//we already tried all the IPs
		{
			nErrorCode = WSAGetLastError();
			shutdown(hSocket, SD_BOTH);
			closesocket(hSocket);
			goto InvalidReturn;
		}

	}
	else//IP
	{
		if(connect(hSocket, (struct sockaddr*)&httpServerAdd, sizeof(httpServerAdd)))
		{
			nErrorCode = WSAGetLastError();
			shutdown(hSocket, SD_BOTH);
			closesocket(hSocket);
			goto InvalidReturn;
		}
	}
	return hSocket;
InvalidReturn:
	//printf("ErrorCode = %i ( 0x%p )\n", nErrorCode, nErrorCode);
	return INVALID_SOCKET;
}

void SetUpClient() {

	SOCKET Sock = ConnectTo("10.1.1.6", 1276);
	if(Sock == INVALID_SOCKET)
		return;

	char Packet[0x400];
	recv(Sock, Packet, 0x400, 0);

	printf(Packet);
	if(!strcmp(Packet, "get\r\n")) {

		byte CPUKey[0x10];
		HvPeekBytes(0x20, CPUKey, 0x10);
		SendText(Sock, va("CPUKey		=%016llX%016llX", *(__int64 *)CPUKey, *(__int64 *)(CPUKey + 8)));

		char Gamertag[16];
		XUserGetName(0, Gamertag, 16);

		SendText(Sock, va("Gamertag		=%s", Gamertag));
		SendText(Sock, va("TitleID		=%p", XamGetCurrentTitleId()));
	}


	SendText(Sock, "bye");
	shutdown(Sock, SD_SEND);
	closesocket(Sock);
	WSACleanup();
}
#endif