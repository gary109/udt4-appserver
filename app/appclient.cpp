#ifndef WIN32
   #include <unistd.h>
   #include <cstdlib>
   #include <cstring>
   #include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#else
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <wspiapi.h>
	#include <ctime>
#endif

#include <signal.h>

#include <map>
#include <deque>
#include <iostream>
#include <udt.h>
#include "cc.h"
//#include "test_util.h"
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#define NO_DEBUG     0
#define DEBUG_LEVEL1 1
#define DEBUG_LEVEL2 2
#define DEBUG_LEVEL3 3
int debug_level = NO_DEBUG;

#define PERROR_GOTO(cond,err,label){        \
        if(cond)                            \
        {                                   \
            if(debug_level >= DEBUG_LEVEL1) \
                perror(err) ;               \
            goto label;                     \
        }}

#define ERROR_GOTO(cond,str,label){                  \
        if(cond)                                     \
        {                                            \
            if(debug_level >= DEBUG_LEVEL2)          \
                fprintf(stderr, "Error: %s\n", str); \
            goto label;                              \
        }}

using namespace std;

#ifdef WIN32
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
//typedef unsigned long uint32_t;
#endif
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* monitor(void*);
#else
DWORD WINAPI monitor(LPVOID);
#endif
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
static int main_running = 0;
static int udt_running = 0;
static int tcp_running = 0;
static void signal_handler(int sig);
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#define PROXY_PORT				6667
#define PROXY_IP				"127.0.0.1"//"192.168.7.24"

#define REMOTE_PORT				5567
#define REMOTE_IP				"127.0.0.1"

#define LOCAL_PORT				7778
#define LOCAL_IP				"127.0.0.1"
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#define CMD_CONNECT				0
#define CMD_ACK					1
#define CMD_DATA_C2S			2
#define CMD_DATA_S2C			3
#define CMD_C_DISCONNECT		4
#define CMD_S_DISCONNECT		5
#define CMD_DATA_C2T			6
#define CMD_DATA_S2T			7
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#define DATA_MAX_LEN			4096
#define UDT_DATA_MAX_LEN		4096
#define TCP_DATA_MAX_LEN		4096
typedef struct _data_buf
{
	char buf[DATA_MAX_LEN];
	int len;
} data_buf_t;

typedef struct _header
{
	unsigned int	cmd;
	unsigned int	cliFD;
	unsigned int	srvFD;
} header_t;

typedef struct _package
{
	header_t	header;
	data_buf_t	payload;
} package_t;
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
map<unsigned int, unsigned int> connectMap;
map<unsigned int, unsigned int>::iterator connectMap_iter;

deque<package_t*> taskQueue;
set<UDTSOCKET> readfds;
set<SYSSOCKET> tcpread;
SYSSOCKET tcpsock;
UDTSOCKET client = NULL;
UDT::TRACEINFO trace;
int udtsize;
char keyin;
int tcp_eid;
int udt_eid;
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
// Test parallel UDT and TCP connections, over shared and dedicated ports.
const int g_IP_Version = AF_INET;
const int g_Socket_Type = SOCK_STREAM;
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int createUDTSocket(UDTSOCKET& usock, int port = 0, bool rendezvous = false);
int createTCPSocket(SYSSOCKET& ssock, int port = 0, bool _bind = true, bool rendezvous = false);
int connect(UDTSOCKET& usock, int port);
int tcp_connect(SYSSOCKET& ssock, int port);
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Debugging function to print a hexdump of data with ascii, for example:
 * 00000000  74 68 69 73 20 69 73 20  61 20 74 65 73 74 20 6d  this is  a test m
 * 00000010  65 73 73 61 67 65 2e 20  62 6c 61 68 2e 00        essage.  blah..
 */
void 
print_hexdump(char *data, int len)
{
    int line;
    int max_lines = (len / 16) + (len % 16 == 0 ? 0 : 1);
    int i;
    printf(" - print_hexdump\n");
    for(line = 0; line < max_lines; line++)
    {
        printf("%08x  ", line * 16);

        /* print hex */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
                printf("%02x ", (uint8_t)data[i]);
            else
                printf("   ");
        }

        printf(" ");
        
        /* print ascii */
        for(i = line * 16; i < (8 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }
        printf(" ");
        for(i = (line * 16) + 8; i < (16 + (line * 16)); i++)
        {
            if(i < len)
            {
                if(32 <= data[i] && data[i] <= 126)
                    printf("%c", data[i]);
                else
                    printf(".");
            }
            else
                printf(" ");
        }

        printf("\n");
    }
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
void
map_insert(map < unsigned int, unsigned int> *mapS, unsigned int key, unsigned int value) {
	mapS->insert(map < unsigned int, unsigned int>::value_type(key, value));
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
void
addTaskQueueItem2Back(deque<package_t*> *q, 
					  unsigned int cmd, 
					  unsigned int cliFD, 
					  unsigned int srvFD, 
					  char* buf, 
					  int len) 
{
	package_t *p = new package_t[1];

	p->header.cmd = cmd;
	p->header.cliFD = cliFD;
	p->header.srvFD = srvFD;

	if (buf == NULL) {
		memset(p->payload.buf, 0, DATA_MAX_LEN);
		p->payload.len = 0;
	}
	else {
		memcpy(p->payload.buf, buf, len);
		p->payload.len = len;
	}

	q->push_back(p);
}
void
addTaskQueueItem2Front(deque<package_t*> *q, 
                       unsigned int cmd, 
					   unsigned int cliFD, 
					   unsigned int srvFD, 
					   char* buf, 
					   int len) 
{
	package_t *p = new package_t[1];

	p->header.cmd = cmd;
	p->header.cliFD = cliFD;
	p->header.srvFD = srvFD;

	if (buf == NULL) {
		memset(p->payload.buf, 0, DATA_MAX_LEN);
		p->payload.len = 0;
	}
	else {
		memcpy(p->payload.buf, buf, len);
		p->payload.len = len;
	}

	q->push_front(p);
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* AppClient_UDT(void* param)
#else
DWORD WINAPI AppClient_UDT(LPVOID param)
#endif
{
#ifndef WIN32
	//ignore SIGPIPE
   	sigset_t ps;
   	sigemptyset(&ps);
   	sigaddset(&ps, SIGPIPE);
   	pthread_sigmask(SIG_BLOCK, &ps, NULL);
#endif
	udt_running = 0;
	///////////////////////////////////////////////////////////////////
	// selecting random local port
	srand(time(NULL));
	int myPort = LOCAL_PORT;//9001 + rand() % 200;
	printf("my port: %d\n", myPort);
	createUDTSocket(client, myPort, true);
	///////////////////////////////////////////////////////////////////
	cout << "Press any key to continue...";
	cin >> keyin;
	///////////////////////////////////////////////////////////////////
	sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PROXY_PORT);
	inet_pton(AF_INET, PROXY_IP, &serv_addr.sin_addr);   // server address here
	memset(&(serv_addr.sin_zero), '\0', 8);
	if (UDT::ERROR == UDT::connect(client, (sockaddr*)&serv_addr, sizeof(serv_addr))) {
		cout << "connect error: " << UDT::getlasterror().getErrorMessage();
		return NULL;
	}
	///////////////////////////////////////////////////////////////////
	udt_eid = UDT::epoll_create();
	UDT::epoll_add_usock(udt_eid, client);
	
	int state;
	package_t udtbuf = { 0 };

	int ssize = 0;
	udtsize = sizeof(udtbuf);
	
	cout << "Run UDT loop ...\n";
	udt_running = 1;
	while(udt_running) {
		state = UDT::epoll_wait(udt_eid, &readfds, NULL, 0 , NULL, NULL);
		
		if(state > 0) {
			for (set<UDTSOCKET>::iterator i = readfds.begin(); i != readfds.end(); ++ i) {
				int rs = 0;
				int rsize = 0;
				while (rsize < udtsize)
				{
					if (UDT::ERROR == (rs = UDT::recv(*i, ((char*)(&udtbuf)) + rsize, udtsize - rsize, 0)))
					{
						cout << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
						
						if((CUDTException::EINVSOCK == UDT::getlasterror().getErrorCode()) ||
						   (CUDTException::ECONNLOST == UDT::getlasterror().getErrorCode()))
						{
							udt_running = 0;
							UDT::epoll_remove_usock(udt_eid, *i);
						}
						
						break;
					}
					else if(rs == 0)
					{
						udt_running = 0;
						break;
					}
					rsize += rs;
				}
				if (rs > 0)
				{
					switch (udtbuf.header.cmd)
					{
						case CMD_S_DISCONNECT:
						{
							addTaskQueueItem2Back(&taskQueue, CMD_S_DISCONNECT, udtbuf.header.cliFD, 0, NULL, 0);
						}
						break;
						case CMD_DATA_S2C:
						{
							connectMap_iter = connectMap.find(udtbuf.header.cliFD);
							if (connectMap_iter != connectMap.end())
							{
								int rs = send(udtbuf.header.cliFD, udtbuf.payload.buf, udtbuf.payload.len, 0);
								if (0 > rs)			cout << "\t CMD_DATA_S2C error1.\n";
								else if (rs == 0)	printf("\t CMD_DATA_S2C disconnect.\n");
							}
						}
						break;
						default:break;
					}
				}
			}	
		}
		else
		{
			if((CUDTException::EINVSOCK == UDT::getlasterror().getErrorCode()) ||
			  (CUDTException::ECONNLOST == UDT::getlasterror().getErrorCode()))
			{
			  cout << "epoll_wait:" << UDT::getlasterror().getErrorMessage() << endl;
			  udt_running = 0;
			//  UDT::epoll_remove_usock(eid, client);
			//  break;
			}
		}
	}

	cout << "release epoll" << endl;
	state = UDT::epoll_release(udt_eid);

	cout << "Close client ...";
	UDT::close(client);
	cout << "ok\n";
	
	cout << "Press any key to continue...";
	cin >> keyin;

#ifndef WIN32
	pthread_detach(pthread_self());
	return NULL;
#else
	return 0;
#endif
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* AppClient_TCP(void* param)
#else
DWORD WINAPI AppClient_TCP(LPVOID param)
#endif
{
#ifndef WIN32
	//ignore SIGPIPE
	sigset_t ps;
	sigemptyset(&ps);
	sigaddset(&ps, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &ps, NULL);
#endif
	SYSSOCKET tcp_serv;
	int state;
	tcp_running = 0;
	package_t udtbuf = { 0 };
	tcp_eid = UDT::epoll_create();
	char* tcpdata = new char[TCP_DATA_MAX_LEN];
	if (createTCPSocket(tcp_serv, REMOTE_PORT) < 0)
	{
		UDT::epoll_release(tcp_eid);
		return NULL;
	}

	listen(tcp_serv, 1024);
	UDT::epoll_add_ssock(tcp_eid, tcp_serv);
	cout << "Run TCP loop ...\n";
	tcp_running = 1;
	while (tcp_running) {
		state = UDT::epoll_wait(tcp_eid, NULL, NULL, 0, &tcpread, NULL);
		if (state > 0) {
			for (set<SYSSOCKET>::iterator i = tcpread.begin(); i != tcpread.end(); ++i) {
				if (*i == tcp_serv) {
					sockaddr_storage clientaddr;
					socklen_t addrlen = sizeof(clientaddr);

					tcpsock = accept(tcp_serv, (sockaddr*)&clientaddr, &addrlen);

					if (tcpsock < 0)
					{
						perror("accept");
						continue;
					}
	
					map_insert(&connectMap, tcpsock, 0);
					UDT::epoll_add_ssock(tcp_eid, tcpsock);
					addTaskQueueItem2Back(&taskQueue, CMD_CONNECT, tcpsock, 0, NULL, 0);

				}else{
					int rs = recv(*i, tcpdata, TCP_DATA_MAX_LEN, 0);
					if (rs <= 0)
					{
						if (rs < 0)
							printf("\tTCP[%d] can't read.\n", *i);
						else
							printf("\tTCP[%d] disconnect.\n", *i);

						UDT::epoll_remove_ssock(tcp_eid, *i);
						#ifndef WIN32
							close(*i);
						#else
							closesocket(*i);
						#endif

						int tmp = 0;
						connectMap_iter = connectMap.find(*i);
						if (connectMap_iter != connectMap.end())
						{
							tmp = connectMap_iter->second;
							connectMap.erase(connectMap_iter);
							addTaskQueueItem2Back(&taskQueue, CMD_C_DISCONNECT, *i, tmp, NULL, 0);
						}
					}
					else{
						connectMap_iter = connectMap.find(*i);
						if (connectMap_iter == connectMap.end())
							continue;
						addTaskQueueItem2Back(&taskQueue, CMD_DATA_C2S, *i, connectMap_iter->second, tcpdata, rs);
					}
				}
			}
		}
		else {
			if ((CUDTException::EINVPARAM == UDT::getlasterror().getErrorCode()) ||
				(CUDTException::ECONNLOST == UDT::getlasterror().getErrorCode())) {
				tcp_running = 0;
				//UDT::epoll_remove_usock(eid,*i);
			}
		}
	}
	cout << "release tcp epoll ..." << endl;
	state = UDT::epoll_release(tcp_eid);
	delete[] tcpdata;

#ifndef WIN32
	close(tcp_serv);
#else
	closesocket(tcp_serv);
#endif

#ifndef WIN32
	pthread_detach(pthread_self());
	return NULL;
#else
	return 0;
#endif
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int 
main(int argc, char* argv[])
{	
	const int test_case = 2;
	signal(SIGINT, &signal_handler);
#ifndef WIN32
	void* (*AppClient[test_case])(void*);
#else
	DWORD(WINAPI *AppClient[test_case])(LPVOID);
#endif
	AppClient[0] = AppClient_TCP;
	AppClient[1] = AppClient_UDT;
	cout << "Start AppClient Mode # Caller" << endl;
	UDT::startup();
#ifndef WIN32
	pthread_t cli_udt, cli_tcp;
	pthread_create(&cli_tcp, NULL, AppClient[0], NULL);
	pthread_create(&cli_udt, NULL, AppClient[1], NULL);
	//pthread_join(cli_main, NULL);
	//pthread_join(cli_udt, NULL);
	//pthread_join(cli_tcp, NULL);
#else
	HANDLE cli_udt, cli_tcp;
	cli_tcp = CreateThread(NULL, 0, AppClient[0], NULL, 0, NULL);
	cli_udt = CreateThread(NULL, 0, AppClient[1], NULL, 0, NULL);
	//WaitForSingleObject(cli_main, INFINITE);
	//WaitForSingleObject(cli_udt, INFINITE);
	//WaitForSingleObject(cli_tcp, INFINITE);
#endif
	////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////
	cout << "Run Task loop ...\n";
	main_running = 1;
	while (main_running)
	{
		if (!taskQueue.empty()) {
			switch (taskQueue.front()->header.cmd)
			{
			case CMD_S_DISCONNECT:
			{
				connectMap_iter = connectMap.find(taskQueue.front()->header.cliFD);
				if (connectMap_iter != connectMap.end())
				{
					UDT::epoll_remove_ssock(tcp_eid, taskQueue.front()->header.cliFD);
#ifndef WIN32
					close(taskQueue.front()->header.cliFD);
#else
					closesocket(taskQueue.front()->header.cliFD);
#endif
				}
				taskQueue.pop_front();
			}
			break;
			case CMD_C_DISCONNECT:
			{
				char* buftmp = (char*)(taskQueue.front());
				int res = 0;
				int ssize = 0;
				//UDT::perfmon(client, &trace);
				while (ssize < udtsize)
				{
					//int scv_size;
					//int var_size = sizeof(int);
					//UDT::getsockopt(client, 0, UDT_SNDDATA, &scv_size, &var_size);
					if (UDT::ERROR == (res = UDT::send(client, buftmp + ssize, udtsize - ssize, 0)))
					{
						cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
						break;
					}

					ssize += res;
				}
				//printf("ok.[%d]\n", res);

				//UDT::perfmon(client, &trace);
				//cout << "\tspeed = " << trace.mbpsSendRate << "Mbits/sec" << endl;

				taskQueue.pop_front();
			}
			break;
			case CMD_DATA_C2T:
			{
				connectMap_iter = connectMap.find(taskQueue.front()->header.cliFD);
				if (connectMap_iter != connectMap.end())
				{
					int rs = send(connectMap_iter->first,
						taskQueue.front()->payload.buf,
						taskQueue.front()->payload.len,
						0);
					if (0 < rs)
					{
					}
					else
					{
						if (0 > rs)
							cout << "\t CMD_DATA_C2T error1.\n";
						else if (rs == 0)
							printf("\t CMD_DATA_C2T disconnect.\n");
						connectMap.erase(connectMap_iter);
					}
				}
				taskQueue.pop_front();
			}
			break;
			case CMD_CONNECT:
			case CMD_DATA_C2S:
			{
				char* buftmp = (char*)(taskQueue.front());
				int rs = 0;
				int ssize = 0;
				//UDT::perfmon(client, &trace);
				while (ssize < udtsize)
				{
					//int scv_size;
					//int var_size = sizeof(int);
					//UDT::getsockopt(client, 0, UDT_SNDDATA, &scv_size, &var_size);
					if (UDT::ERROR == (rs = UDT::send(client, buftmp + ssize, udtsize - ssize, 0)))
					{
						cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
						break;
					}

					ssize += rs;
				}
				//printf("ok.[%d]\n", rs);
				//UDT::perfmon(client, &trace);
				//cout << "\tspeed = " << trace.mbpsSendRate << "Mbits/sec" << endl;

				taskQueue.pop_front();
				break;
			}
			default:
				break;
			}
		}
	}
	////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////
	UDT::cleanup();
	cout << "AppClient # Caller " << " end." << endl;
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* monitor(void* s)
#else
DWORD WINAPI monitor(LPVOID s)
#endif
{
   UDTSOCKET u = *(UDTSOCKET*)s;

   UDT::TRACEINFO perf;

   cout << "SendRate(Mb/s)\tRTT(ms)\tCWnd\tPktSndPeriod(us)\tRecvACK\tRecvNAK" << endl;

   while (true)
   {
      #ifndef WIN32
         sleep(1);
      #else
         Sleep(1000);
      #endif

      if (UDT::ERROR == UDT::perfmon(u, &perf))
      {
         cout << "perfmon: " << UDT::getlasterror().getErrorMessage() << endl;
         break;
      }

      cout << perf.mbpsSendRate << "\t\t" 
           << perf.msRTT << "\t" 
           << perf.pktCongestionWindow << "\t" 
           << perf.usPktSndPeriod << "\t\t\t" 
           << perf.pktRecvACK << "\t" 
           << perf.pktRecvNAK << endl;
   }

   #ifndef WIN32
      return NULL;
   #else
      return 0;
   #endif
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* recvdata(void* usocket)
#else
DWORD WINAPI recvdata(LPVOID usocket)
#endif
{
   UDTSOCKET recver = *(UDTSOCKET*)usocket;
   delete (UDTSOCKET*)usocket;

   char* data;
   int size = 50;
   data = new char[size];

   while (true)
   {
      int rsize = 0;
      int rs;
      while (rsize < size)
      {
         int rcv_size;
         int var_size = sizeof(int);
         UDT::getsockopt(recver, 0, UDT_RCVDATA, &rcv_size, &var_size);
         if (UDT::ERROR == (rs = UDT::recv(recver, data + rsize, size - rsize, 0)))
         {
            cout << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
         }

         rsize += rs;
      }

      if (rsize < size)
         break;
   }

   delete [] data;

   UDT::close(recver);

   #ifndef WIN32
      return NULL;
   #else
      return 0;
   #endif
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int
createUDTSocket(UDTSOCKET& usock, int port, bool rendezvous) {
	addrinfo hints;
	addrinfo* res;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = g_IP_Version;
	hints.ai_socktype = g_Socket_Type;

	char service[16];
	sprintf(service, "%d", port);

	if (0 != getaddrinfo(NULL, service, &hints, &res)) {
		cout << "illegal port number or port is busy.\n" << endl;
		return -1;
	}

	usock = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	//////////////////////////////////////////////////////////////////////////
	bool block = true;
	UDT::setsockopt(usock, 0, UDT_SNDSYN, &block, sizeof(bool));
	UDT::setsockopt(usock, 0, UDT_RCVSYN, &block, sizeof(bool));

	// Windows UDP issue
	// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
#ifdef WIN32
	UDT::setsockopt(usock, 0, UDT_MSS, new int(1052), sizeof(int));
#else
	UDT::setsockopt(usock, 0, UDT_MSS, new int(9000), sizeof(int));
#endif

	// since we will start a lot of connections, we set the buffer size to smaller value.
	int snd_buf = 16000;//8192;
	int rcv_buf = 16000;//8192;

	UDT::setsockopt(usock, 0, UDT_SNDBUF, &snd_buf, sizeof(int));
	UDT::setsockopt(usock, 0, UDT_RCVBUF, &rcv_buf, sizeof(int));

	snd_buf = 16000;//8192;
	rcv_buf = 16000;//8192;

	UDT::setsockopt(usock, 0, UDP_SNDBUF, &snd_buf, sizeof(int));
	UDT::setsockopt(usock, 0, UDP_RCVBUF, &rcv_buf, sizeof(int));

	int fc = 4096;
	UDT::setsockopt(usock, 0, UDT_FC, &fc, sizeof(int));

	bool reuse = true;

	UDT::setsockopt(usock, 0, UDT_REUSEADDR, &reuse, sizeof(bool));
	UDT::setsockopt(usock, 0, UDT_RENDEZVOUS, &rendezvous, sizeof(bool));
	//////////////////////////////////////////////////////////////////////////
	if (UDT::ERROR == UDT::bind(usock, res->ai_addr, res->ai_addrlen)) {
		cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
		return -1;
	}
	freeaddrinfo(res);
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int 
createTCPSocket(SYSSOCKET& ssock, int port,bool _bind, bool rendezvous)
{
   addrinfo hints;
   addrinfo* res;
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_flags = AI_PASSIVE;
   hints.ai_family = g_IP_Version;
   hints.ai_socktype = g_Socket_Type;

   char service[16];
   sprintf(service, "%d", port);

   if (0 != getaddrinfo(NULL, service, &hints, &res))
   {
      cout << "illegal port number or port is busy.\n" << endl;
      return -1;
   }

   ssock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
   if (_bind && bind(ssock, res->ai_addr, res->ai_addrlen) != 0)
   {
      return -1;
   }

   //int rcvbuf = 64000;

   //setsockopt(ssock, SOL_SOCKET, SO_SNDBUF, (char *)& rcvbuf, sizeof(rcvbuf));
   //setsockopt(ssock, SOL_SOCKET, SO_RCVBUF, (char *)& rcvbuf, sizeof(rcvbuf));

   freeaddrinfo(res);
   return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int 
connect(UDTSOCKET& usock, int port) {
   addrinfo hints, *peer;
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_flags = AI_PASSIVE;
   hints.ai_family =  g_IP_Version;
   hints.ai_socktype = g_Socket_Type;

   char buffer[16];
   sprintf(buffer, "%d", port);

   if (0 != getaddrinfo(PROXY_IP, buffer, &hints, &peer))
   {
      return -1;
   }

   UDT::connect(usock, peer->ai_addr, peer->ai_addrlen);

   freeaddrinfo(peer);
   return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
int 
tcp_connect(SYSSOCKET& ssock, int port) {
   addrinfo hints, *peer;
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_flags = AI_PASSIVE;
   hints.ai_family = g_IP_Version;
   hints.ai_socktype = g_Socket_Type;

   char buffer[16];
   sprintf(buffer, "%d", port);

   if (0 != getaddrinfo(REMOTE_IP, buffer, &hints, &peer))
   {
      return -1;
   }

   connect(ssock, peer->ai_addr, peer->ai_addrlen);

   freeaddrinfo(peer);
   return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////
void
signal_handler(int sig) {
	switch (sig) {
	case SIGINT:
		main_running = 0;
		udt_running = 0;
		tcp_running = 0;
		break;
	}
}