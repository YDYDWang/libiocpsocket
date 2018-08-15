#ifndef UNICODE
#define UNICODE
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdio.h>
#include <process.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

typedef void(*EVENT_LISTENER)();

typedef void(*RECEIVE_LISTENER)(char *);

/**typedef EVENT_LISTENER *PEVENT_LISTENER;*/

typedef enum {
	UNKNOWN
	, ACCEPT
	, READ
	, WRITE
} OPERATION;

typedef struct _EVENTS {
	EVENT_LISTENER connect_listener;
	EVENT_LISTENER receive_listener;
	EVENT_LISTENER disconnect_listener;
} EVENTS, *PEVENTS;

typedef struct _SERVER_CONTEXT {
	SOCKET socket;
	PADDRINFOW info;
	WSADATA wsadata;
	HANDLE iocp;
	LPFN_ACCEPTEX acceptex;
	DWORD size;
	DWORD receive_length;
	PEVENTS events;
	GUID guid;
} SERVER_CONTEXT, *PSERVER_CONTEXT;

typedef struct _SOCKET_CONTEXT {
	WSAOVERLAPPED overlap;
	SOCKET socket;
	WSABUF wsabuf;
	DWORD receive_length;
} SOCKET_CONTEXT, *PSOCKET_CONTEXT;

typedef struct _IO_CONTEXT {
	WSAOVERLAPPED overlap;
	WSABUF wsabuf;
	PSOCKET_CONTEXT socket_context;
	OPERATION operation;
} IO_CONTEXT, *PIO_CONTEXT;

typedef struct _BUF {
	WSABUF wsabuf;
	UINT writeIndex;
	UINT readIndex;
} BUF, *PBUF;

BOOL init_server_context(PCWSTR port, DWORD buffer_size, EVENT_LISTENER connect_listener
	, EVENT_LISTENER receive_listener, EVENT_LISTENER disconnect_listener
	, PADDRINFOW hints, PSERVER_CONTEXT *server_context) {
	PSERVER_CONTEXT s = malloc(sizeof(SERVER_CONTEXT));
	*server_context = s;
	if (s == NULL) {
		printf("[FATAL] Fail to allocate memory for SOCKET_CONTEXT\n");
		return FALSE;
	}
	if (!init_wsadata(&s->wsadata)) {
		return FALSE;
	}
	if (!init_server_info(port, hints, &s->info)) {
		return FALSE;
	}
	if (!init_socket(&s->socket, s->info)) {
		return FALSE;
	}
	if (!init_iocp(&s->iocp)) {
		return FALSE;
	}
	if (!init_events(&s->events, connect_listener, receive_listener, disconnect_listener)) {
		return FALSE;
	}
	s->size = buffer_size;
	s->guid = (GUID) WSAID_ACCEPTEX;
	s->receive_length = 0;
	if (!bind_to_iocp_for_server_context(s, s->iocp)) {
		return FALSE;
	}
	if (!init_wasiIoctl(s->socket, s->guid, &s->acceptex, &s->receive_length)) {
		return FALSE;
	}
	return TRUE;
}

BOOL init_socket_context(PSOCKET_CONTEXT *socket_context, PADDRINFOW info, int size) {
	PSOCKET_CONTEXT s = malloc(sizeof(SOCKET_CONTEXT));
	*socket_context = s;
	if (s == NULL) {
		printf("[FATAL] Fail to allocate memory for SOCKET_CONTEXT\n");
		return FALSE;
	}
	s->wsabuf.buf = malloc(sizeof(size));
	s->wsabuf.len = size;
	ZeroMemory(&s->overlap, sizeof(s->overlap));
	s->receive_length = 0;
	if (s->wsabuf.buf == NULL) {
		printf("[FATAL] Fail to allocate memory for SOCKET_CONTEXT->WSABUF.buf\n");
		return FALSE;
	}
	if (!init_socket(&s->socket, info)) {
		return FALSE;
	}
	return TRUE;
}

BOOL init_io_context(PIO_CONTEXT *io_context, PSOCKET_CONTEXT socket_context, int size, OPERATION operation) {
	PIO_CONTEXT io = malloc(sizeof(IO_CONTEXT));
	*io_context = io;
	if (io == NULL) {
		printf("[FATAL] Fail to allocate memory for IO_CONTEXT\n");
		return FALSE;
	}
	io->wsabuf.buf = malloc(sizeof(size));
	io->wsabuf.len = size;
	ZeroMemory(&io->overlap, sizeof(io->overlap));
	io->socket_context = socket_context;
	io->operation = operation;
	//s->receive_length = 0;
	if (io->wsabuf.buf == NULL) {
		printf("[FATAL] Fail to allocate memory for SOCKET_CONTEXT->WSABUF.buf\n");
		return FALSE;
	}
	return TRUE;
}

BOOL init_wsadata(WSADATA *wsa_data) {
	int code = WSAStartup(MAKEWORD(2, 2), &wsa_data);
	if (code != NO_ERROR) {
		printf("[FATAL]WSAStartup failed with error code: %d\n", code);
		return FALSE;
	}
	return TRUE;
}

ADDRINFOW new_hints() {
	ADDRINFOW hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_IP;
	hints.ai_addrlen = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	return hints;
}

BOOL init_server_info(PCWSTR port, PADDRINFOW hints, PADDRINFOW *server_info) {
	int code = GetAddrInfoW(NULL, port, hints, server_info);
	if (code != NO_ERROR) {
		printf("[FATAL]GetAddrInfoW failed with error code: %d\n", WSAGetLastError());
		return FALSE;
	}
	if (server_info == NULL) {
		printf("[FATAL]GetAddrInfoW failed resolve/convert the interface\n");
		return FALSE;
	}
	return TRUE;
}

BOOL init_socket(SOCKET *s, PADDRINFOW info) {
	*s = WSASocketW(info->ai_family
		, info->ai_socktype
		, info->ai_protocol
		, NULL
		, 0
		, WSA_FLAG_OVERLAPPED);
	if (*s == INVALID_SOCKET) {
		printf("[FATAL]WSASocketW failed with error code: %d\n", WSAGetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL bind_to_server(SOCKET socket, PADDRINFOW info) {
	int code = bind(socket
		, info->ai_addr
		, (int)info->ai_addrlen);
	if (code == SOCKET_ERROR) {
		printf("[FATAL]bind failed with error code: %d\n", WSAGetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL listen_to_server(SOCKET socket) {
	int code = listen((socket), SOMAXCONN);
	if (code == SOCKET_ERROR) {
		printf("[FATAL]listen failed with error code: %d\n", WSAGetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL do_listen(SOCKET socket, PADDRINFOW info) {
	if (!bind_to_server(socket, info)) {
		return FALSE;
	}
	return listen_to_server(socket);
}

BOOL init_iocp(HANDLE *iocp) {
	*iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (*iocp == NULL) {
		printf("[FATAL]CreateIoCompletionPort failed with error code: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL do_accept(PSERVER_CONTEXT server_context, PSOCKET_CONTEXT socket_context) {
	if (!bind_to_iocp(socket_context, server_context->iocp)) {
		return FALSE;
	}
	return do_acceptex(server_context->socket, socket_context->socket
		, socket_context->wsabuf.buf, socket_context->receive_length, &socket_context->overlap
		, server_context->acceptex);
}

BOOL bind_to_iocp(PSOCKET_CONTEXT socket_context, HANDLE iocp) {
	iocp = CreateIoCompletionPort((HANDLE) socket_context->socket, iocp, NULL, 0);
	if (iocp == NULL) {
		printf("[FATAL]CreateIoCompletionPort failed with error code: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL bind_to_iocp_for_server_context(PSERVER_CONTEXT server_context, HANDLE iocp) {
	iocp = CreateIoCompletionPort((HANDLE) server_context->socket, iocp, ACCEPT, 0);
	if (iocp == NULL) {
		printf("[FATAL]CreateIoCompletionPort failed with error code: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL init_wasiIoctl(SOCKET socket, GUID guid, LPFN_ACCEPTEX *fn_acceptex, LPDWORD size) {
	int code = WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guid, sizeof(GUID),
		fn_acceptex, sizeof(LPFN_ACCEPTEX),
		size, NULL, NULL);
	if (code != NO_ERROR) {
		printf("[FATAL]WSAIoctl failed with error code: %d\n", WSAGetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL do_acceptex(SOCKET listen_socket, SOCKET accept_socket
	, char *address_info, LPDWORD receive_length, LPOVERLAPPED overlap
	, LPFN_ACCEPTEX lpfn_acceptex) {
	int code = (lpfn_acceptex)(listen_socket, accept_socket
		, address_info, 0
		, sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16
		, receive_length, overlap);
	if (code == SOCKET_ERROR) {
		int error = WSAGetLastError();
		if (error != ERROR_IO_PENDING) {
			printf("[FATAL]LPFN_ACCEPTEX failed with error code: %d\n", error);
			return FALSE;
		} else {
			printf("[DEBUG]ERROR_IO_PENDING with error code: %d\n", error);
		}
	}
	return TRUE;
}

void connect_listener() {
	printf("[DEBUG]connect established\n");
}

void receive_listener() {
	printf("[DEBUG]receive message\n");
}

void disconnect_listener() {
	printf("[DEBUG]disconnect\n");
}

BOOL init_events(PEVENTS *events, EVENT_LISTENER connect_listener
	, EVENT_LISTENER receive_listener, EVENT_LISTENER disconnect_listener) {
	 PEVENTS e = malloc(1, sizeof(EVENTS));
	 e->connect_listener = connect_listener;
	 e->receive_listener = receive_listener;
	 e->disconnect_listener = disconnect_listener;
	 *events = e;
	 if (e == NULL) {
		 printf("[FATAL] Fail to allocate memory for EVENTS\n");
		 return FALSE;
	 }
	 return TRUE;
 }

void do_recv(PIO_CONTEXT io_context, LPDWORD flag) {
	int code = WSARecv(
		io_context->socket_context->socket,
		&io_context->wsabuf,
		1,
		NULL,
		flag,
		&io_context->overlap,
		NULL
	);
	if (code != NOERROR) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			printf("[FATAL]WSARecv failed with error code: %d\n", error);
			// TODO maybe we can disconnect socket
		}
	}
}

unsigned __stdcall process(void *parameter) {
	PSERVER_CONTEXT server_context = parameter;
	DWORD flag = 0;
	printf("DEBUG]Thread inside %d \n", GetCurrentThreadId());
	while (TRUE) {
		OPERATION operation = UNKNOWN;
		LPOVERLAPPED overlap = NULL;
		DWORD receive_length = NULL;
		BOOL code = GetQueuedCompletionStatus(
			server_context->iocp
			, &receive_length
			, &operation
			, &overlap
			, INFINITE);
		if (code == FALSE) {
			printf("[FATAL]GetQueuedCompletionStatus failed with error code: %d\n", GetLastError());
			continue;
		}
		if (ACCEPT == operation) {
			PSOCKET_CONTEXT socket_context = overlap;
			PIO_CONTEXT io_context;
			if (init_io_context(&io_context, socket_context, server_context->size, READ)) {
				do_recv(io_context, &flag);
			}
		} else {
			PIO_CONTEXT io_context = overlap;
			if (io_context->operation == READ) {
				fwrite(io_context->wsabuf.buf, 1, receive_length, stdout);
				do_recv(io_context, &flag);
			} else {
				printf("[DEBUG]Unknown operation %d", io_context->operation);
			}
		}
		//printf("[DEBUG]receive_length: %d \n", receive_length);
	}
	return 0;
}

BOOL new_server_socket(PCWSTR port, DWORD buffer_size, PADDRINFOW hints, EVENT_LISTENER connect_listener
	, EVENT_LISTENER receive_listener, EVENT_LISTENER disconnect_listener) {
	PSERVER_CONTEXT server_context;
	if (init_server_context(port, buffer_size, connect_listener
		, receive_listener, disconnect_listener
		, hints, &server_context)
		&& do_listen(server_context->socket, server_context->info)) {
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);
		unsigned int threadId = NULL;
		for (DWORD i = 0; i < systemInfo.dwNumberOfProcessors; i++) {
			PSOCKET_CONTEXT socket_context;
			if (init_socket_context(&socket_context, server_context->info, buffer_size)
				&& do_accept(server_context, socket_context)) {
				HANDLE thread = _beginthreadex(NULL, 0, process, server_context, 0, &threadId);
				printf("Thread after %d \n", threadId);
			}
		}
	}
}

int main(void) {
	PCWSTR port = L"9999";
	DWORD buffer_size = 4096;
	ADDRINFOW hints = new_hints();
	new_server_socket(port, buffer_size, &hints, connect_listener, receive_listener, disconnect_listener);
	getchar();
}
