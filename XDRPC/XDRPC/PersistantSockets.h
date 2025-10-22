// (C) 2011 Nathan LeRoux
#pragma once

// This is a nice, fairly transparent overlay to the standard socket implementation.
// It basically lets you have a socket that doesn't die when you change games, lol

// Questions? refer to xdk documention :D

// Protip: on 12625, and i'm PRETTY SURE 13146, a devkit xam.xex works just as well as a retail one, and allows you do mess with some other fun stuff
// This probably wont work on retail unless you change the 3 to a 2 in the source code (maybe?) or use a devkit xam.xex,
// or have some other voodoo magic

// XNET stuff
INT PXNetCleanup(); // note: this doesn't actually do anything, hence why i'm overriding it, i dont want to mess with xam's sockets >_>
INT PXNetStartup(const XNetStartupParams *pxnsp);

// WSA stuff
int PWSACancelOverlappedIO(SOCKET s);
int PWSACleanup(); // this doesn't do anything either
int PWSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents);
BOOL PWSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED lpOverlapped, LPDWORD lpcbTransfer, BOOL fWait, LPDWORD lpdwFlags);
int PWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int PWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags,
	struct sockaddr FAR *lpFrom, LPINT lpFromLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int PWSASendTo(SOCKET s, LPWSABUF lpBuffers, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr FAR* lpTo,
	int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int PWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
	LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
int PWSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);

// socket stuff
SOCKET Paccept(SOCKET s, struct sockaddr FAR *addr, int FAR *addrlen);
int Pbind(SOCKET s, const struct sockaddr FAR *name, int namelen);
int Pclosesocket(SOCKET s);
int Pconnect(SOCKET s, const struct sockaddr FAR *name, int namelen);
int Pgetpeername(SOCKET s, struct sockaddr FAR *name, int FAR *namelen);
int Pgetsockname(SOCKET s, struct sockaddr FAR *name, int FAR *namelen);
int Pgetsockopt(SOCKET s, int level, int optname, char FAR *optval, int FAR *optlen);
int Pioctlsocket(SOCKET s, long cmd, u_long FAR *argp);
int Plisten(SOCKET s, int backlog);
int Precv(SOCKET s, char FAR *buf, int len, int flags);
int Precvfrom(SOCKET s, char FAR *buf, int len, int flags, struct sockaddr FAR *from, int FAR *fromlen);
int Pselect(int nfds, fd_set FAR *readfds, fd_set FAR *writefds, fd_set FAR *exceptfds, const struct timeval FAR *timeout);
int Psend(SOCKET s, const char FAR *buf, int len, int flags);
int Psendto(SOCKET s, const char FAR *buf, int len, int flags, const struct sockaddr FAR *to, int tolen);
int Psetsockopt(SOCKET s, int level, int optname, const char FAR *optval, int optlen);
int Pshutdown(SOCKET s, int how);
SOCKET Psocket(int af, int type, int protocol);
int decryptsocket(SOCKET s);

// #defines, if you dont want this to override your crap you better #define PERSISTANT_SOCKET_NOOVERRIDE
#ifndef PERSISTANT_SOCKET_NOOVERRIDE
#define XNetCleanup				PXNetCleanup
#define XNetStartup				PXNetStartup
#define WSACancelOverlappedIO	PWSACancelOverlappedIO
#define WSACleanup				PWSACleanup
#define WSAEventSelect			PWSAEventSelect
#define WSAGetOverlappedResult	PWSAGetOverlappedResult
#define WSARecv					PWSARecv
#define WSARecvFrom				PWSARecvFrom
#define WSASendTo				PWSASendTo
#define WSASend					PWSASend
#define WSAStartup				PWSAStartup
#define accept					Paccept
#define bind					Pbind
#define closesocket				Pclosesocket
#define connect					Pconnect
#define getpeername				Pgetpeername
#define getsockname				Pgetsockname
#define getsockopt				Pgetsockopt
#define ioctlsocket				Pioctlsocket
#define listen					Plisten
#define recv					Precv
#define recvfrom				Precvfrom
#define select					Pselect
#define send					Psend
#define sendto					Psendto
#define setsockopt				Psetsockopt
#define shutdown				Pshutdown
#define socket					Psocket
#endif