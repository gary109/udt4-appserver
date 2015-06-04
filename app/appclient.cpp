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
#include <queue>
#include <iostream>
#include <udt.h>
#include "cc.h"
#include "test_util.h"

#define NO_DEBUG     0
#define DEBUG_LEVEL1 1
#define DEBUG_LEVEL2 2
#define DEBUG_LEVEL3 3
int debug_level = DEBUG_LEVEL3;

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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* monitor(void*);
#else
DWORD WINAPI monitor(LPVOID);
#endif

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static int running = 1;
static void signal_handler(int sig);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define PROXY_PORT				6666
#define PROXY_IP				"192.168.7.24"

#define REMOTE_PORT				5566
#define REMOTE_IP				"127.0.0.1"

#define LOCAL_PORT				7777
#define LOCAL_IP				"127.0.0.1"
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define UDT_DATA_MAX_LEN		4096
#define TCP_DATA_MAX_LEN		4096
typedef struct tcp_data_buf
{
	int id;
	unsigned int cliFD;
	unsigned int srvFD;
    char buf[TCP_DATA_MAX_LEN];
    int len;
} tcp_data_buf_t;

typedef struct udt_data_buf
{
	int id;
	unsigned int cliFD;
	unsigned int srvFD;
    char buf[UDT_DATA_MAX_LEN];
    int len;
} udt_data_buf_t;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Test parallel UDT and TCP connections, over shared and dedicated ports.
const int g_IP_Version = AF_INET;
const int g_Socket_Type = SOCK_STREAM;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int createUDTSocket(UDTSOCKET& usock, int port = 0, bool rendezvous = false);
int createTCPSocket(SYSSOCKET& ssock, int port = 0, bool _bind = true, bool rendezvous = false);
int connect(UDTSOCKET& usock, int port);
int tcp_connect(SYSSOCKET& ssock, int port);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Debugging function to print a hexdump of data with ascii, for example:
 * 00000000  74 68 69 73 20 69 73 20  61 20 74 65 73 74 20 6d  this is  a test m
 * 00000010  65 73 73 61 67 65 2e 20  62 6c 61 68 2e 00        essage.  blah..
 */
void print_hexdump(char *data, int len)
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void map_insert(map < unsigned int, unsigned int > *mapStudent, unsigned int key, unsigned int value)
{ 
	mapStudent->insert(map < unsigned int, unsigned int>::value_type(key, value)); 
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef WIN32
void* AppClient_1(void* param)
#else
DWORD WINAPI AppClient_1(LPVOID param)
#endif
{
#ifndef WIN32
	//ignore SIGPIPE
   	sigset_t ps;
   	sigemptyset(&ps);
   	sigaddset(&ps, SIGPIPE);
   	pthread_sigmask(SIG_BLOCK, &ps, NULL);
#endif
	char pause;	
	int eid = UDT::epoll_create();

	sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP, &serv_addr.sin_addr);   // server address here
    memset(&(serv_addr.sin_zero), '\0', 8);

    // selecting random local port
    srand(time(NULL));
    int myPort = LOCAL_PORT;//9001 + rand() % 200;
    printf("my port: %d\n", myPort);

    sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(myPort);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(my_addr.sin_zero), '\0', 8);
	
	UDTSOCKET client = UDT::socket(AF_INET, SOCK_STREAM, 0);
	//////////////////////////////////////////////////////////////////////////////////////
	bool block = true;
	UDT::setsockopt(client, 0, UDT_SNDSYN, &block, sizeof(bool));
	UDT::setsockopt(client, 0, UDT_RCVSYN, &block, sizeof(bool));

	// Windows UDP issue
	// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
	#ifdef WIN32
	   UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
	#else
	   UDT::setsockopt(client, 0, UDT_MSS, new int(9000), sizeof(int));
	#endif

	UDT::setsockopt(client, 0, UDT_SNDBUF, new char(8192), sizeof(char));
	UDT::setsockopt(client, 0, UDT_RCVBUF, new char(8192), sizeof(char));

	UDT::setsockopt(client, 0, UDP_SNDBUF, new char(8192), sizeof(char));
	UDT::setsockopt(client, 0, UDP_RCVBUF, new char(8192), sizeof(char));

	int fc = 4096;//16;
	UDT::setsockopt(client, 0, UDT_FC, &fc, sizeof(int));
	bool reuse = true;
	UDT::setsockopt(client, 0, UDT_REUSEADDR, &reuse, sizeof(bool));
	bool rendezvous = true;
	UDT::setsockopt(client, 0, UDT_RENDEZVOUS, &rendezvous, sizeof(bool));
	//////////////////////////////////////////////////////////////////////////////////////
	printf("bind ...");
    if (UDT::ERROR == UDT::bind(client, (sockaddr*)&my_addr, sizeof(my_addr))) {
        cout << "bind error: " << UDT::getlasterror().getErrorMessage();
        return NULL;
    }
	printf("ok\n");

	cout << "Press any key to continue...";
	cin >> pause;





	printf("connect to server ...");
    if (UDT::ERROR == UDT::connect(client, (sockaddr*)&serv_addr, sizeof(serv_addr))) {
        cout << "connect error: " << UDT::getlasterror().getErrorMessage();
        return NULL;
    }
	printf("ok\n");


	UDT::epoll_add_usock(eid, client);
	
	// create TCP sockets
	//vector<SYSSOCKET> tcp_socks;
  
	printf("Create TCP serve ...");
	SYSSOCKET tcp_serv;
	if (createTCPSocket(tcp_serv, REMOTE_PORT) < 0)
	{
      //PERROR_GOTO(true, "createTCPSocket", done);
	   UDT::epoll_release(eid);
		return NULL;
	}
	printf("ok\n");

	printf("listen ...");
	listen(tcp_serv, 1024);
	printf("ok\n");

	UDT::epoll_add_ssock(eid, tcp_serv);

	
	cout << "Run loop ...\n";
			
	SYSSOCKET tcpsock;
	set<UDTSOCKET> readfds;
	set<SYSSOCKET> tcpread;

	int state;
	char* tcpdata = new char[TCP_DATA_MAX_LEN];

	queue<udt_data_buf_t*> udtQueue;
	queue<tcp_data_buf_t*> tcpQueue;

	map<unsigned int, unsigned int> connectMap;
	map<unsigned int, unsigned int>::iterator connectMap_iter;

	udt_data_buf_t udtbuf={0};
	tcp_data_buf_t tcpbuf={0};

	UDT::TRACEINFO trace;

	int ssize = 0;
	int udtsize = sizeof(udtbuf);

	while(running)
	{
		state = UDT::epoll_wait(eid, &readfds, NULL, 0 , &tcpread, NULL);
		
		if(state > 0)
		{
			for (set<SYSSOCKET>::iterator i = tcpread.begin(); i != tcpread.end(); ++ i)
			{
				printf("==================================================\n");
				if(*i == tcp_serv)
				{	
					printf("Read data from TCP...is tcp_serv\n");
					sockaddr_storage clientaddr;
					socklen_t addrlen = sizeof(clientaddr);

					tcpsock = accept(tcp_serv, (sockaddr*)&clientaddr, &addrlen);
					
					if(tcpsock < 0)
					{
						perror("accept");
						continue;
					}
					
					udtQueue.push(new udt_data_buf_t[1]);
					udtQueue.back()->id = 0;
					udtQueue.back()->cliFD = tcpsock;
					udtQueue.back()->srvFD = 0;
					memset(udtQueue.back()->buf, 0, UDT_DATA_MAX_LEN);
					udtQueue.back()->len = 0;


					cout << "\tudtQueue.back().id:"<<udtQueue.back()->id << endl;
					cout << "\tudtQueue.back().cliFD:"<< udtQueue.back()->cliFD << endl;
					cout << "\tudtQueue.back().srvFD:"<< udtQueue.back()->srvFD << endl;
					cout << "\tudtQueue.back().len:"<< udtQueue.back()->len << endl;

					UDT::epoll_add_ssock(eid, tcpsock);
				}
				else
				{
					printf("Recv data from TCP...is other tcp sock\n");

					connectMap_iter = connectMap.find(*i);
					if(connectMap_iter == connectMap.end())
						continue;

					int rs = recv(*i, tcpdata , TCP_DATA_MAX_LEN, 0);
					printf("\ttcpread: rs=%d\n",rs);
					if (rs <= 0)
					{
						printf("\tTCP[%d] disconnect processing...\n",*i);

						if(rs < 0)
							printf("\tTCP[%d] can't read.\n",*i);
						else
							printf("\tTCP[%d] disconnect.\n",*i);

						printf("\t Create udtQueue...\n");
						
						UDT::epoll_remove_ssock(eid, *i);
						#ifndef WIN32
							close(*i);
						#else
							closesocket(*i);
						#endif

						connectMap_iter = connectMap.find(*i);
						if(connectMap_iter != connectMap.end())
						{
							printf("\t udtQueue push tcpdata\n");

							udtQueue.push(new udt_data_buf_t[1]);
							udtQueue.back()->id = 4;
							udtQueue.back()->cliFD = *i;
							udtQueue.back()->srvFD = connectMap_iter->second;
							memset(udtQueue.back()->buf, 0, UDT_DATA_MAX_LEN);
							udtQueue.back()->len = 0;

							cout << "\tudtQueue.back().id:"<<udtQueue.back()->id << endl;
							cout << "\tudtQueue.back().cliFD:"<< udtQueue.back()->cliFD << endl;
							cout << "\tudtQueue.back().srvFD:"<< udtQueue.back()->srvFD << endl;
							cout << "\tudtQueue.back().len:"<< udtQueue.back()->len << endl;

							connectMap.erase(connectMap_iter);
						}
						else
						{
							printf("\t Can't find.\n");
						}
					}
					else
					{
						printf("\tCreate udtQueue...\n");
						connectMap_iter = connectMap.find(*i);
						if(connectMap_iter != connectMap.end())
						{
													
							printf("\tudtQueue push tcpdata\n");

							udtQueue.push(new udt_data_buf_t[1]);
							udtQueue.back()->id = 2;
							udtQueue.back()->cliFD = *i;
							udtQueue.back()->srvFD = connectMap_iter->second;
							memcpy(udtQueue.back()->buf, tcpdata, rs);
							udtQueue.back()->len = rs;

							cout << "\tudtQueue.back().id:"<<udtQueue.back()->id << endl;
							cout << "\tudtQueue.back().cliFD:"<< udtQueue.back()->cliFD << endl;
							cout << "\tudtQueue.back().srvFD:"<< udtQueue.back()->srvFD << endl;
							cout << "\tudtQueue.back().len:"<< udtQueue.back()->len << endl;
						
						}
						else
						{
							printf("\t Can't find.\n");
						}
					}
				}
			}

			for (set<UDTSOCKET>::iterator i = readfds.begin(); i != readfds.end(); ++ i)
			{
				printf("==================================================\n");
				cout << "Recv UDT data ...\n";
				int rs = 0;
				int rsize = 0;
				int size = sizeof(udtbuf);
				while (rsize < size)
				{
					if (UDT::ERROR == (rs = UDT::recv(*i, ((char*)(&udtbuf)) + rsize, size - rsize, 0)))
					{
						cout << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
						
						if((CUDTException::EINVSOCK == UDT::getlasterror().getErrorCode()) ||
						   (CUDTException::ECONNLOST == UDT::getlasterror().getErrorCode()))
						{
							running = 0;
							UDT::epoll_remove_usock(eid, *i);
						}
						
						break;
					}
					else if(rs == 0)
					{
						running = 0;
						break;
					}
					rsize += rs;
				}

				cout << "\tbuf.id:"<<udtbuf.id << endl;
				cout << "\tbuf.cliFD:"<< udtbuf.cliFD << endl;
				cout << "\tbuf.srvFD:"<< udtbuf.srvFD << endl;
				cout << "\tbuf.len:"<< udtbuf.len << endl;
				printf("\trs:%d",rs);

				if(rs > 0)
				{
					switch(udtbuf.id)
					{
						case 0: 
							printf("\t[C->S] Recv connect request.\n");	
							break;
						case 1:
							printf("\t[C->S] Recv connect ack.\n");
							
							map_insert(&connectMap, udtbuf.cliFD, udtbuf.srvFD);

							break;
						case 2:
							printf("\t[C->S] data transfer.\n");
							break;
						case 3:
							printf("\t[S->C] data transfer.\n");

							connectMap_iter = connectMap.find(udtbuf.cliFD);
							if(connectMap_iter != connectMap.end())
							{
								tcpQueue.push(new tcp_data_buf_t[1]);
								tcpQueue.back()->id = 6;
								tcpQueue.back()->cliFD = udtbuf.cliFD;
								tcpQueue.back()->srvFD = udtbuf.srvFD;
								memcpy(tcpQueue.back()->buf, udtbuf.buf,  udtbuf.len);
								tcpQueue.back()->len = udtbuf.len;
								
								printf("\t[C->C*] data transfer.\n");
								cout << "\ttcpQueue.back().id:"<<tcpQueue.back()->id << endl;
								cout << "\ttcpQueue.back().cliFD:"<< tcpQueue.back()->cliFD << endl;
								cout << "\ttcpQueue.back().srvFD:"<< tcpQueue.back()->srvFD << endl;
								cout << "\ttcpQueue.back().len:"<< tcpQueue.back()->len << endl;
							}
							else
							{
								printf("\t Can't find.\n");
							}
							break;
						case 4:
							printf("\tServer did disconnect.\n");
							cout << "\tudtQueue.back().id:"<<udtbuf.id << endl;							
							cout << "\tudtQueue.back().cliFD:"<< udtbuf.cliFD << endl;
							cout << "\tudtQueue.back().srvFD:"<< udtbuf.srvFD << endl;
							cout << "\tudtQueue.back().len:"<< udtbuf.len << endl;
							UDT::epoll_remove_ssock(eid, udtbuf.cliFD);
							#ifndef WIN32
							   close(udtbuf.cliFD);
							#else
							   closesocket(udtbuf.cliFD);
							#endif
							connectMap_iter = connectMap.find(udtbuf.cliFD);
							if(connectMap_iter != connectMap.end())
								connectMap.erase(connectMap_iter);
							break;
						case 5:
							printf("\t[C->S] Recv disconnect ack.\n");
							break;
						default:	
							printf("\tOthers command.\n");	
							break;
					}

				}
			}

			if(!tcpQueue.empty())
			{
				printf("==================================================\n");
				cout << "\ttcp Queue entry ...\n";
				cout << "\tTCP send processing ...";
				int rs = send(tcpQueue.front()->cliFD, tcpQueue.front()->buf, tcpQueue.front()->len, 0);
				if(0 > rs)
				{
					cout << "error1.\n";
				}
				else if(rs == 0)
				{
					printf("error2.\n");
				}
				else
				{
					printf("ok.[%d]\n",rs);;
					tcpQueue.pop();
				}
				
			}

			if(!udtQueue.empty())
			{
				printf("==================================================\n");
				cout << "udt Queue entry ...\n";
				cout << "\tUDT send processing ...";
				
				char* buftmp =  (char*)(udtQueue.front());
				int rs=0;
				ssize = 0;
				UDT::perfmon(client, &trace);
				while (ssize < udtsize)
				{
					int scv_size;
					//int var_size = sizeof(int);
					//UDT::getsockopt(client, 0, UDT_SNDDATA, &scv_size, &var_size);
					if (UDT::ERROR == (rs = UDT::send(client, buftmp + ssize, udtsize - ssize, 0)))
					{
						cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
						break;
					}

					ssize += rs;
				}
				printf("ok.[%d]\n",rs);
				UDT::perfmon(client, &trace);
				cout << "\tspeed = " << trace.mbpsSendRate << "Mbits/sec" << endl;
				udtQueue.pop();
			}
		}
		else
		{
			if((CUDTException::EINVSOCK == UDT::getlasterror().getErrorCode()) ||
			  (CUDTException::ECONNLOST == UDT::getlasterror().getErrorCode()))
			{
			  cout << "epoll_wait:" << UDT::getlasterror().getErrorMessage() << endl;
			  running = 0;
			//  UDT::epoll_remove_usock(eid, client);
			//  break;
			}
		}
	}

	cout << "release epoll" << endl;
	state = UDT::epoll_release(eid);

	delete [] tcpdata;

	cout << "Close client ...";
	UDT::close(client);
	cout << "ok\n";
	
#ifndef WIN32
	close(tcp_serv);
#else
	closesocket(tcp_serv);
#endif
	cout << "Press any key to continue...";
	cin >> pause;

   return NULL;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int 
main(int argc, char* argv[])
{	
	const int test_case = 1;

	signal(SIGINT, &signal_handler);

#ifndef WIN32
   void* (*AppClient[test_case])(void*);
#else
   DWORD (WINAPI *AppClient[test_case])(LPVOID);
#endif

   // Automatically start up and clean up UDT module.
	UDTUpDown _udt_;
	UDT::startup();

	AppClient[0] = AppClient_1;

	cout << "Start AppClient Mode # 1 " << endl;

	for (int i = 0; i < test_case; ++ i)
   {
      


#ifndef WIN32
      pthread_t srv;
      pthread_create(&srv, NULL, AppClient[i], NULL);
      pthread_join(srv, NULL);
#else
      HANDLE srv;
      srv = CreateThread(NULL, 0, AppClient[i], NULL, 0, NULL);
      WaitForSingleObject(srv, INFINITE);
#endif
    UDT::cleanup();
      cout << "AppClient # " << i + 1 << " completed." << endl;
   }


	return NULL;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int 
createUDTSocket(UDTSOCKET& usock, int port, bool rendezvous)
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

   usock = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

   // since we will start a lot of connections, we set the buffer size to smaller value.
   int snd_buf = 16000;
   int rcv_buf = 16000;
   UDT::setsockopt(usock, 0, UDT_SNDBUF, &snd_buf, sizeof(int));
   UDT::setsockopt(usock, 0, UDT_RCVBUF, &rcv_buf, sizeof(int));
   snd_buf = 8192;
   rcv_buf = 8192;
   UDT::setsockopt(usock, 0, UDP_SNDBUF, &snd_buf, sizeof(int));
   UDT::setsockopt(usock, 0, UDP_RCVBUF, &rcv_buf, sizeof(int));
   int fc = 1024;//16;
   UDT::setsockopt(usock, 0, UDT_FC, &fc, sizeof(int));
   bool reuse = true;
   UDT::setsockopt(usock, 0, UDT_REUSEADDR, &reuse, sizeof(bool));
   UDT::setsockopt(usock, 0, UDT_RENDEZVOUS, &rendezvous, sizeof(bool));

   if (UDT::ERROR == UDT::bind(usock, res->ai_addr, res->ai_addrlen))
   {
      cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
      return -1;
   }

   freeaddrinfo(res);
   return 0;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int 
connect(UDTSOCKET& usock, int port)
{
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int 
tcp_connect(SYSSOCKET& ssock, int port)
{
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
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void 
signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}
