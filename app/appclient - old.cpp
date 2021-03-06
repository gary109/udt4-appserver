#ifndef WIN32
   #include <unistd.h>
   #include <cstdlib>
   #include <cstring>
   #include <netdb.h>
#else
	#include "helpers/winhelpers.h"
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <wspiapi.h>
	#include <ctime>
#endif

#include <signal.h>
#include "appcommon.h"

#include <iostream>
#include <udt.h>
#include "cc.h"
#include "test_util.h"

using namespace std;

#define BACKLOG 10
#define ADDRSTRLEN (INET6_ADDRSTRLEN + 9)

#define SOCK_TYPE_TCP 1
#define SOCK_TYPE_UDP 2
#define SOCK_IPV4     3
#define SOCK_IPV6     4

#define SIN(sa) ((struct sockaddr_in *)sa)
#define SIN6(sa) ((struct sockaddr_in6 *)sa)
#define PADDR(a) ((struct sockaddr *)a)

typedef struct socket {
    int fd;                       /* Socket file descriptor to send/recv on */
    int type;                     /* SOCK_STREAM or SOCK_DGRAM */
    struct sockaddr_storage addr; /* IP and port */
    socklen_t addr_len;           /* Length of sockaddr type */
} socket_t;

#define SOCK_FD(s) ((s)->fd)
#define SOCK_LEN(s) ((s)->addr_len)
#define SOCK_PADDR(s) ((struct sockaddr *)&(s)->addr)
#define SOCK_TYPE(s) ((s)->type)


#ifndef WIN32
void* monitor(void*);
#else
DWORD WINAPI monitor(LPVOID);
#endif


static int _argc = 7;
static char* _argv[] = {
		{ "appclient.exe" },
		{ "192.168.7.24"},
		{ "3347"},
		{ "122.147.155.173"},
		{ "6890"},
		{ "192.168.7.24"},
		{ "1122"}
};

int debug_level = DEBUG_LEVEL1;//NO_DEBUG;
int ipver = SOCK_IPV4;
static int running = 1;
static void signal_handler(int sig);

#define MSG_MAX_LEN 1024
typedef struct data_buf
{
    char buf[MSG_MAX_LEN];
    int len;
} data_buf_t;
////////////////////////////////////////////////////////////////////////////////////////////////
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
////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Receives data from the socket. Calles recv() or recvfrom() depending on the
 * type of socket. Ignores the 'from' argument if type is for TCP, or puts
 * remove address in from socket for UDP. Reads up to len bytes and puts it in
 * data. Returns number of bytes sent, or 0 if remote host disconnected, or -1
 * on error.
 */
int 
sock_recv(socket_t *sock, socket_t *from, char *data, int len)
{
	

    int bytes_recv = 0;
    socket_t tmp;
    printf(" - sock_recv\n");
    switch(sock->type)
    {
        case SOCK_STREAM:
            bytes_recv = recv(sock->fd, data, len, 0);
            break;

        case SOCK_DGRAM:
            if(!from)
                from = &tmp; /* In case caller wants to ignore from socket */
            from->fd = sock->fd;
            from->addr_len = sock->addr_len;
            bytes_recv = recvfrom(from->fd, data, len, 0,
                                  SOCK_PADDR(from), &SOCK_LEN(from));
            break;
    }
    
    PERROR_GOTO(bytes_recv < 0, "recv", error);
    ERROR_GOTO(bytes_recv == 0, "disconnect", disconnect);

    if(debug_level >= DEBUG_LEVEL3)
    {
        printf("sock_recv: type=%d, fd=%d, bytes=%d\n",
               sock->type, sock->fd, bytes_recv);
        print_hexdump(data, bytes_recv);
    }
    
    return bytes_recv;
    
  disconnect:
    return 0;
    
  error:
    return -1;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Reads data that is ready on the TCP socket and stores it in the internal
 * buffer. The routine client_send_udp_data() send that data to the tunnel.
 */
int client_recv_tcp_data(socket_t *client)
{
    int ret;
    data_buf_t buf;
	printf(" - client_recv_tcp_data client_fd:%d\n",client->fd);
    ret = sock_recv(client, NULL, buf.buf, sizeof(buf.buf));
    if(ret < 0)
        return -1;
    if(ret == 0)
        return -2;

    buf.len = ret;
	
	print_hexdump(buf.buf, buf.len);

    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
static _inline_ void client_remove_tcp_fd_from_set(socket_t *c, fd_set *set)
{
	printf(" - client_remove_tcp_fd_from_set c->fd:%d\n",c->fd);
    if(SOCK_FD(c) >= 0)
        FD_CLR(SOCK_FD(c), set);
}

static _inline_ int client_tcp_fd_isset(socket_t *c, fd_set *set)
{
	printf(" - client_tcp_fd_isset c->fd:%d\n",c->fd);
    return SOCK_FD(c) >= 0 ? FD_ISSET(SOCK_FD(c), set) : 0;
}
static _inline_ void client_add_tcp_fd_to_set(socket_t *c, fd_set *set)
{
	printf(" - client_add_tcp_fd_to_set c->fd:%d\n",c->fd);
    if(SOCK_FD(c) >= 0)
        FD_SET(SOCK_FD(c), set);
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Frees the socket structure.
 */
void 
sock_free(socket_t *s)
{
	printf(" - sock_free\n");

    free(s);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Closes the file descriptor for the socket.
 */
void 
sock_close(socket_t *s)
{
	printf(" - sock_close\n");

    if(s->fd != -1)
    {
#ifdef WIN32
        closesocket(s->fd);
#else
        close(s->fd);
#endif
        s->fd = -1;
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Gets the string representation of the IP address and port from addr. Will
 * store result in buf, which len must be at least INET6_ADDRLEN + 6. Returns a
 * pointer to buf. String will be in the form of "ip_address:port".
 */
#ifdef WIN32
char *sock_get_str(socket_t *s, char *buf, int len)
{
	

    DWORD plen = len;
	printf(" - sock_get_str\n");
    if(WSAAddressToString(SOCK_PADDR(s), SOCK_LEN(s), NULL, buf, &plen) != 0)
        return NULL;

    return buf;
}
#else
char *sock_get_str(socket_t *s, char *buf, int len)
{
    void *src_addr;
    char addr_str[INET6_ADDRSTRLEN];
    uint16_t port;
    
    switch(s->addr.ss_family)
    {
        case AF_INET:
            src_addr = (void *)&SIN(&s->addr)->sin_addr;
            port = ntohs(SIN(&s->addr)->sin_port);
            break;

        case AF_INET6:
            src_addr = (void *)&SIN6(&s->addr)->sin6_addr;
            port = ntohs(SIN6(&s->addr)->sin6_port);
            break;
            
        default:
            return NULL;
    }

    if(inet_ntop(s->addr.ss_family, src_addr,
                 addr_str, sizeof(addr_str)) == NULL)
        return NULL;

    snprintf(buf, len, (s->addr.ss_family == AF_INET6) ? "[%s]:%hu" : "%s:%hu",
             addr_str, port);

    return buf;
}
#endif /*WIN32*/
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Accept a new connection and return a newly allocated socket representing
 * the remote connection.
 */
socket_t *
sock_accept(socket_t *serv)
{
	
    socket_t *client;
    printf(" - sock_accept\n");
    client = (socket_t *)calloc(1, sizeof(*client));
    if(!client)
        goto error;

    client->type = serv->type;
    client->addr_len = sizeof(struct sockaddr_storage);
    client->fd = accept(serv->fd, SOCK_PADDR(client), &client->addr_len);
    PERROR_GOTO(SOCK_FD(client) < 0, "accept", error);
        
    return client;
    
  error:
    if(client)
        free(client);

    return NULL;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * If the socket is a server, start listening. If it's a client, connect to
 * to destination specified in sock_create(). Returns -1 on error or -2 if
 * the sockect is already connected.
 */
int sock_connect(socket_t *sock, int is_serv)
{
	

    struct sockaddr *paddr;
    int ret;
	printf(" - sock_connect\n");
    if(sock->fd != -1)
        return -2;
        
    paddr = SOCK_PADDR(sock);
    
    /* Create socket file descriptor */
    sock->fd = socket(paddr->sa_family, sock->type, 0);
    PERROR_GOTO(sock->fd < 0, "socket", error);
    
    if(is_serv)
    {
		 int yes=1;

		// 避開這個錯誤訊息："address already in use"
		setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(int));

        /* Bind socket to address and port */
        ret = bind(sock->fd, paddr, sock->addr_len);
        PERROR_GOTO(ret != 0, "bind", error);
        
        /* Start listening on the port if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = listen(sock->fd, BACKLOG);
            PERROR_GOTO(ret != 0, "listen", error);
        }
    }
    else
    {
        /* Connect to the server if tcp */
        if(sock->type == SOCK_STREAM)
        {
            ret = connect(sock->fd, paddr, sock->addr_len);
            PERROR_GOTO(ret != 0, "connect", error);
        }
    }

    return 0;
    
  error:
    return -1;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * Allocates and returns a new socket structure.
 * host - string of host or address to listen on (can be NULL for servers)
 * port - string of port number or service (can be NULL for clients)
 * ipver - SOCK_IPV4 or SOCK_IPV6
 * sock_type - SOCK_TYPE_TCP or SOCK_TYPE_UDP
 * is_serv - 1 if is a server socket to bind and listen on port, 0 if client
 * conn - call socket(), bind(), and listen() if is_serv, or connect()
 *        if not is_serv. Doesn't call these if conn is 0.
 */
socket_t *
sock_create(char *host, char *port, int ipver, int sock_type,
                      int is_serv, int conn)
{
	

    socket_t *sock = NULL;
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct sockaddr *paddr;
    int ret;
    printf(" - sock_create\n");
    sock = (socket_t*)calloc(1, sizeof(*sock));
    if(!sock)
        return NULL;

    paddr = SOCK_PADDR(sock);
    sock->fd = -1;

    switch(sock_type)
    {
        case SOCK_TYPE_TCP:
            sock->type = SOCK_STREAM;
            break;
        case SOCK_TYPE_UDP:
            sock->type = SOCK_DGRAM;
            break;
        default:
            goto error;
    }

    /* If both host and port are null, then don't create any socket or
       address, but still set the AF. */
    if(host == NULL && port == NULL)
    {
        sock->addr.ss_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
        goto done;
    }
    
    /* Setup type of address to get */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (ipver == SOCK_IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = sock->type;
    hints.ai_flags = is_serv ? AI_PASSIVE : 0;

    /* Get address from the machine */
    ret = getaddrinfo(host, port, &hints, &info);
    PERROR_GOTO(ret != 0, "getaddrinfo", error);
    memcpy(paddr, info->ai_addr, info->ai_addrlen);
    sock->addr_len = info->ai_addrlen;

    if(conn)
    {
        if(sock_connect(sock, is_serv) != 0)
            goto error;
    }

  done:
    if(info)
        freeaddrinfo(info);
    
    return sock;
    
  error:
    if(sock)
        free(sock);
    if(info)
        freeaddrinfo(info);
    
    return NULL;
}
/////////////////////////////////////////////////////////////////////////////////////////////////
int 
p2p_client(int argc, char* argv[])
{
	// Automatically start up and clean up UDT module.
	//UDTUpDown _udt_;

	UDTSOCKET client = UDT::socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(6890);
    inet_pton(AF_INET, "122.147.155.173", &serv_addr.sin_addr);   // server address here
    memset(&(serv_addr.sin_zero), '\0', 8);

    // selecting random local port
    srand(time(NULL));
    int myPort = 9001 + rand() % 200;
    printf("my port: %d\n", myPort);

    sockaddr_in my_addr;
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(myPort);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(my_addr.sin_zero), '\0', 8);


    // Connecting to server

    // binding my port
    if (UDT::ERROR == UDT::bind(client, (sockaddr*)&my_addr, sizeof(my_addr))) {
        cout << "bind error: " << UDT::getlasterror().getErrorMessage();
        return 0;
    }

    // connect to the server
    if (UDT::ERROR == UDT::connect(client, (sockaddr*)&serv_addr, sizeof(serv_addr))) {
        cout << "connect error: " << UDT::getlasterror().getErrorMessage();
        return 42;
    }

    char data[6];
    if (UDT::ERROR == UDT::recv(client, data, 6, 0)) {
        cout << "recv error:" << UDT::getlasterror().getErrorMessage() << endl;
        return 0;
    }

    sockaddr_in peer_addr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = *(uint32_t*)data;
    peer_addr.sin_port = *(unsigned short*)(data + 4);

    cout << "addr received: " << inet_ntoa(peer_addr.sin_addr) << ":" << ntohs(peer_addr.sin_port) << endl;
    UDT::close(client);

    client = UDT::socket(AF_INET, SOCK_STREAM, 0);
    bool rendezvous = true;
    UDT::setsockopt(client, 0, UDT_RENDEZVOUS, &rendezvous, sizeof(bool));

    if (UDT::ERROR == UDT::bind(client, (sockaddr*)&my_addr, sizeof(my_addr))) {
        cout << "bind error: " << UDT::getlasterror().getErrorMessage();
        return 0;
    }



   //cout << "server is ready at port: " << myPort << endl;

   //if (UDT::ERROR == UDT::listen(client, 10))
   //{
   //   cout << "listen: " << UDT::getlasterror().getErrorMessage() << endl;
   //   return 0;
   //}


 //  sockaddr_storage clientaddr;
 //  int addrlen = sizeof(clientaddr);
	//UDTSOCKET recver;
	//if (UDT::INVALID_SOCK == (recver = UDT::accept(client, (sockaddr*)&clientaddr, &addrlen)))
	//{
	//	cout << "accept: " << UDT::getlasterror().getErrorMessage() << endl;
 //       return 0;
	//}

 //     char clienthost[NI_MAXHOST];
 //     char clientservice[NI_MAXSERV];
 //     getnameinfo((sockaddr *)&clientaddr, addrlen, clienthost, sizeof(clienthost), clientservice, sizeof(clientservice), NI_NUMERICHOST|NI_NUMERICSERV);
 //     cout << "new connection: " << clienthost << ":" << clientservice << endl;


    if (UDT::ERROR == UDT::connect(client, (sockaddr*)&peer_addr, sizeof(peer_addr))) {
        cout << "connect error: " << UDT::getlasterror().getErrorMessage();
        return 42;
    }
    cout << "SUCCESS!\n";

	//      if (UDT::ERROR == (ss = UDT::send(client, data + ssize, size - ssize, 0)))
   //      {
   //         cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
   //         break;
   //      }
	int rs;
	//char *hello = "hello";

	//if (UDT::ERROR == (rs = UDT::recv(client, hello, strlen(hello), 0)))
 //   {
	//	cout << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
 //   }
 
	 #ifndef WIN32
      pthread_create(new pthread_t, NULL, monitor, &client);
   #else
      CreateThread(NULL, 0, monitor, &client, 0, NULL);
   #endif


     //#ifndef WIN32
     //    pthread_t rcvthread;
     //    pthread_create(&rcvthread, NULL, recvdata, new UDTSOCKET(client));
     //    pthread_detach(rcvthread);
     // #else
     //    CreateThread(NULL, 0, recvdata, new UDTSOCKET(client), 0, NULL);
     // #endif



	char* recvdata;
	int size = 50;
	recvdata = new char[size];
	int i=0;
	while(1)
	{
		i++;

		//if (UDT::ERROR == (rs = UDT::send(client, "Windows - hello!", strlen("Windows - hello!"), 0)))
  //      {
		//	cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
  //          break;
  //      }

		memset(recvdata,'\0',size);
         int rcv_size;
         int var_size = sizeof(int);
         UDT::getsockopt(client, 0, UDT_RCVDATA, &rcv_size, &var_size);
         if (UDT::ERROR == (rs = UDT::recv(client, recvdata, size, 0)))
         {
            cout << "recv:" << UDT::getlasterror().getErrorMessage() << endl;
            break;
         }
		 if(rs > 0)
		 {
			 printf("recv(%d):%s\n",i,recvdata);
		 }
		 else if(rs == 0)
		 {
			break;
		 }

		

	#ifndef WIN32
         sleep(2);// give another client time to connect too
	#else
         Sleep(2000);// give another client time to connect too
	#endif
	}


	UDT::close(client);
	delete [] recvdata;
	return 0;
}


int 
select_client(int argc, char* argv[])
{

	

	// Automatically start up and clean up UDT module.
   UDTUpDown _udt_;

	SOCKET               s;
	 SOCKADDR_IN          ServerAddr;
	 int                  Port = 5150;
	 int                  Ret, Ret1;
	 string Data;
	 char     DataServe[8];
	 memset(DataServe, 0, 8);
	 char pause;
	 if (argc <= 1)
	 {
	  printf("USAGE: tcpclient <Server IP address>.\n");
	  return 0;
	 }

	 // Create a new socket to make a client connection.
	 if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
	 {
	  printf("socket failed with error %d\n", WSAGetLastError());
	  WSACleanup();
	  return 0;
	 }
	 // Setup a SOCKADDR_IN structure that will be used to connect
	 // to a listening server on port 5150. For demonstration
	 // purposes, we required the user to supply an IP address
	 // on the command line and we filled this field in with the 
	 // data from the user.
	 ServerAddr.sin_family = AF_INET;
	 ServerAddr.sin_port = htons(Port);    
	 ServerAddr.sin_addr.s_addr = inet_addr(argv[1]);
	 // Make a connection to the server with socket s.
	 printf("We are trying to connect to %s:%d...\n",
	 inet_ntoa(ServerAddr.sin_addr), htons(ServerAddr.sin_port));

	 if (connect(s, (SOCKADDR *) &ServerAddr, sizeof(ServerAddr)) == SOCKET_ERROR)
	 {
	  printf("connect failed with error %d\n", WSAGetLastError());
	  closesocket(s);

	  return 0;
	 }
	 printf("Our connection succeeded.\n");
	 // At this point you can start sending or receiving data on
	 // the socket s. We will just send a hello message to the server.
	 printf("We will now try to send a hello message.\n");
	 for(int i = 0; i<3; i++)
	 {
	  cin>>Data;
	  if ((Ret = send(s, Data.c_str()/*"Hello"*/, Data.size(), 0)) == SOCKET_ERROR)
	  {
	   printf("send failed with error %d\n", WSAGetLastError());
	   closesocket(s);

	   return 0;
	  }
	  printf("We successfully sent %d byte(s).\n", Ret);
	 }
	 // When you are finished sending and receiving data on socket s,
	 // you should close the socket.
	 printf("We are closing the connection.\n");
	 closesocket(s);

	 cin>>pause;
	 return 0;
}


void 
signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            running = 0;
    }
}


int 
main(int argc, char* argv[])
{
	UDTUpDown _udt_;

	char *lhost, *lport, *phost, *pport, *rhost, *rport;

	UDTSOCKET udt_sock;

	socket_t *tcp_serv = NULL;
	socket_t *tcp_sock = NULL;
    socket_t *udp_sock = NULL;
	
	char addrstr[ADDRSTRLEN];
	int ret;
    int i;
	int num_fds;
	fd_set client_fds;
    fd_set read_fds;
	struct timeval curr_time;
    struct timeval check_time;
    struct timeval check_interval;
    struct timeval timeout;

	signal(SIGINT, &signal_handler);
	
	i = 1;
	lhost = (_argc - i == 5) ? NULL : _argv[i++];
    lport = _argv[i++];
    phost = _argv[i++];
    pport = _argv[i++];
    rhost = _argv[i++];
    rport = _argv[i++];


	/* Check validity of ports (can't check ip's b/c might be host names) */
    ERROR_GOTO(!isnum(lport), "Invalid local port.", done);
    ERROR_GOTO(!isnum(pport), "Invalid proxy port.", done);
    ERROR_GOTO(!isnum(rport), "Invalid remote port.", done);



	/* Create a TCP server socket to listen for incoming connections */
    tcp_serv = sock_create(lhost, lport, ipver, SOCK_TYPE_TCP, 1, 1);
    ERROR_GOTO(tcp_serv == NULL, "Error creating TCP socket.", done);
    if(debug_level >= DEBUG_LEVEL1)
    {
        printf("Listening on TCP %s\n",
               sock_get_str(tcp_serv, addrstr, sizeof(addrstr)));
    }

	FD_ZERO(&client_fds);

    /* Initialize all the timers */
    timerclear(&timeout);
    check_interval.tv_sec = 0;
    check_interval.tv_usec = 500000;
    //gettimeofday(&check_time, NULL);
	
	while(running)
    {
        if(!timerisset(&timeout))
            timeout.tv_usec = 50000;

        read_fds = client_fds;
        FD_SET(SOCK_FD(tcp_serv), &read_fds);

        ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
        PERROR_GOTO(ret < 0, "select", done);
        num_fds = ret;


		if(num_fds == 0)
            continue;

		
		if(FD_ISSET(SOCK_FD(tcp_serv), &read_fds))
        {
			printf("[1-1]\n");

            tcp_sock = sock_accept(tcp_serv);
            if(tcp_sock == NULL)
                continue;
			
			client_add_tcp_fd_to_set(tcp_sock, &client_fds);
            num_fds--;
			
			printf("[1-2]\n");
        }
		// Check for TCP data
		else if(FD_ISSET(SOCK_FD(tcp_sock), &read_fds))
		{
			printf("[2-1]\n");
			ret = client_recv_tcp_data(tcp_sock);
			if(ret == -1)
			{
				printf("[2-2]\n");
				client_remove_tcp_fd_from_set(tcp_sock, &read_fds);
				sock_close(tcp_sock);
                continue;
			}
			else if(ret == -2)
			{
				printf("[2-3]\n");
				client_remove_tcp_fd_from_set(tcp_sock, &read_fds);
				sock_close(tcp_sock);
			}
			num_fds--;
		}

	}

done:
    if(debug_level >= DEBUG_LEVEL1)
        printf("Cleaning up...\n");
	if(tcp_serv)
    {
        sock_close(tcp_serv);
        sock_free(tcp_serv);
    }
	if(tcp_sock)
    {
        sock_close(tcp_sock);
        sock_free(tcp_sock);
    }
    if(udp_sock)
    {
        sock_close(udp_sock);
        sock_free(udp_sock);
    }
	if(udt_sock)
	{
		UDT::close(udt_sock);
	}
    if(debug_level >= DEBUG_LEVEL1)
        printf("Goodbye.\n");
    return 0;


   //if ((3 != argc) || (0 == atoi(argv[2])))
   //{
   //   cout << "usage: appclient server_ip server_port" << endl;
   //   return 0;
   //}

   //// Automatically start up and clean up UDT module.
   //UDTUpDown _udt_;

   //struct addrinfo hints, *local, *peer;

   //memset(&hints, 0, sizeof(struct addrinfo));

   //hints.ai_flags = AI_PASSIVE;
   //hints.ai_family = AF_INET;
   //hints.ai_socktype = SOCK_STREAM;
   ////hints.ai_socktype = SOCK_DGRAM;

   //if (0 != getaddrinfo(NULL, "9000", &hints, &local))
   //{
   //   cout << "incorrect network address.\n" << endl;
   //   return 0;
   //}

   //UDTSOCKET client = socket(local->ai_family, local->ai_socktype, local->ai_protocol);

   //// UDT Options
   ////UDT::setsockopt(client, 0, UDT_CC, new CCCFactory<CUDPBlast>, sizeof(CCCFactory<CUDPBlast>));
   ////UDT::setsockopt(client, 0, UDT_MSS, new int(9000), sizeof(int));
   ////UDT::setsockopt(client, 0, UDT_SNDBUF, new int(10000000), sizeof(int));
   ////UDT::setsockopt(client, 0, UDP_SNDBUF, new int(10000000), sizeof(int));
   ////UDT::setsockopt(client, 0, UDT_MAXBW, new int64_t(12500000), sizeof(int));

   //// Windows UDP issue
   //// For better performance, modify HKLM\System\CurrentControlSet\Services\Afd\Parameters\FastSendDatagramThreshold
   //#ifdef WIN32
   //   UDT::setsockopt(client, 0, UDT_MSS, new int(1052), sizeof(int));
   //#endif

   //// for rendezvous connection, enable the code below
	
   //UDT::setsockopt(client, 0, UDT_RENDEZVOUS, new bool(true), sizeof(bool));
   //if (UDT::ERROR == UDT::bind(client, local->ai_addr, local->ai_addrlen))
   //{
   //   cout << "bind: " << UDT::getlasterror().getErrorMessage() << endl;
   //   return 0;
   //}
 


   //freeaddrinfo(local);

   //if (0 != getaddrinfo(argv[1], argv[2], &hints, &peer))
   //{
   //   cout << "incorrect server/peer address. " << argv[1] << ":" << argv[2] << endl;
   //   return 0;
   //}

   //// connect to the server, implict bind
   //if (UDT::ERROR == UDT::connect(client, peer->ai_addr, peer->ai_addrlen))
   //{
   //   cout << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
   //   return 0;
   //}

   //freeaddrinfo(peer);

   //// using CC method
   ////CUDPBlast* cchandle = NULL;
   ////int temp;
   ////UDT::getsockopt(client, 0, UDT_CC, &cchandle, &temp);
   ////if (NULL != cchandle)
   ////   cchandle->setRate(500);

   //int size = 100000;
   //char* data = new char[size];

   //#ifndef WIN32
   //   pthread_create(new pthread_t, NULL, monitor, &client);
   //#else
   //   CreateThread(NULL, 0, monitor, &client, 0, NULL);
   //#endif

   //for (int i = 0; i < 1000000; i ++)
   //{
   //   int ssize = 0;
   //   int ss;
   //   while (ssize < size)
   //   {
   //      if (UDT::ERROR == (ss = UDT::send(client, data + ssize, size - ssize, 0)))
   //      {
   //         cout << "send:" << UDT::getlasterror().getErrorMessage() << endl;
   //         break;
   //      }

   //      ssize += ss;
   //   }

   //   if (ssize < size)
   //      break;
   //}

   //UDT::close(client);
   //delete [] data;
   //return 0;
}

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
