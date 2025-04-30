/*
Copyright 2025 William Johnson <williamj.inbox@gmail.com>

Licensed under the Apache License, Version 2.0 (the 
"License"); you may not use this file except in compliance 
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, 
software distributed under the License is distributed on an 
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific 
language governing permissions and limitations under the License.

DEPLOYMENT NOTES:

1. Change the g_daemon_port to prevent autonomous landers.

2. Keep a secure note of all keys you generate for daemon deployment
   and configure your client to point to the location of your server(s).
*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN64
#include "win.h"
#elif __linux__
#include "lin.h"
#endif

/* daemon port - this is the port bind, the server (this) listens
   and accepts client requests to this port */
static const char g_daemon_port[] = "1382";

/* delimitor used to separate metrics */
static const char g_delimitor[] = ":";

/* bytes in kb, base-2 interpretation as opposed to SI units */
static const uint16_t g_bytes_per_kb = 1024;

/* number of db processes to query */
static uint8_t g_process_count;

/* process check for list */
static const char *g_process_check_for[] = {
  "mysql", 
  "mysqld.exe", 
  "mysqld", 
  "mariadbd", 
  "memcached", 
  "db2sysc", 
  "cassandra", 
  "redis-server", 
  "mongod", 
  "mongos", 
  "tnslsnr", 
  "oracle", 
  "sqlservr", 
  "postgres"
};

/* internal buffer length to handle network-io */
static const uint16_t g_max_buffer_len = 512;

static void *g_handle;

/* mount point for checking disk stats */
#ifdef _WIN64
static const char g_mount_point[] = "C:\\";
#elif __linux__
static const char g_mount_point[] = "/";
#endif

/* sleep function in milliseconds */
void sleep_ms(uint32_t ms) {
#ifdef WIN32
    Sleep(ms);
#elif __linux__
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
#endif
}

/* available memory in kb */
uint64_t available_memory() {
#ifdef _WIN64
  MEMORYSTATUSEX mi;
  mi.dwLength = sizeof(mi);
  GlobalMemoryStatusEx(&mi);
  return mi.ullAvailPhys / g_bytes_per_kb;
#elif __linux__
  FILE *frd = fopen("/proc/meminfo", "r");
  if (frd == NULL)
    return 0;
  char line_t[256];
  while (fgets(line_t, sizeof(line_t), frd)) {
    uint64_t frv;
    if (sscanf(line_t, "MemAvailable: %llu kB", &frv) == 1) {
      fclose(frd);
      return frv;
    }
  }
  fclose(frd);
  return 0;
#endif
}

/* available disk space in kb */
uint64_t available_space() {
#ifdef _WIN64
  ULARGE_INTEGER lpFBA, lpTNB, lpTNFB;
  if ( GetDiskFreeSpaceEx(g_mount_point, &lpFBA, &lpTNB, &lpTNFB) )
    return lpFBA.QuadPart / g_bytes_per_kb;
  return 0;
#elif __linux__
  struct statvfs stat;
  if ( statvfs(g_mount_point, &stat) == 0 )
    return (stat.f_bsize * stat.f_bfree) / g_bytes_per_kb;
  return 0;
#endif
}

/* accurate percentile for cpu usage */
double cpu_load()
{
#ifdef _WIN64
  /*
  apparently {HQUERY, HCOUNTER, PDH_HQUERY, 
  PDH_HCOUNTER} belong to the same family
  */
  HANDLE c;
  HANDLE q;
  PDH_FMT_COUNTERVALUE cv;
  if (PdhOpenQuery(NULL, 0, &q) != ERROR_SUCCESS)
      return 0.0;
  if (PdhAddCounter(q, TEXT("\\Processor Information(_Total)\\% Processor Utility"), 0, &c) != ERROR_SUCCESS) {
      PdhCloseQuery(q);
      return 0.0;
  }
  PdhCollectQueryData(q);
  sleep_ms(200);
  PdhCollectQueryData(q);
  if (PdhGetFormattedCounterValue(c, PDH_FMT_DOUBLE, NULL, &cv) != ERROR_SUCCESS)
    return 0.0;
  PdhCloseQuery(q);
  return cv.doubleValue / 100.0;
#elif __linux__
  if ( !update_cpu_stats() )
    return 0.0;
  return get_cpu_usage();
#endif
}

/* signals that a live database is running */
uint8_t is_database_running() {
#ifdef _WIN64
  return has_process(g_process_check_for, g_process_count);
#elif __linux__
  for ( uint32_t q = 0; q < g_process_count; q++ ) {
    if ( get_process_id(g_process_check_for[q]) != -1 )
      return 1;
  }
  return 0;
#endif
}

/* total disk space in kb */
uint64_t total_disk_space() {
#ifdef _WIN64
  ULARGE_INTEGER lpFBA, lpTNB, lpTNFB;
  if ( GetDiskFreeSpaceEx(g_mount_point, &lpFBA, &lpTNB, &lpTNFB) )
    return lpTNB.QuadPart/g_bytes_per_kb;
  return 0;
#elif __linux__
  struct statvfs stat;
  if ( statvfs(g_mount_point, &stat) == 0 )
    return (stat.f_blocks * stat.f_frsize)/g_bytes_per_kb;
  return 0;
#endif
}

/* total physical memory on server box */
uint64_t total_physical_memory() {
#ifdef _WIN64
  MEMORYSTATUSEX mi;
  mi.dwLength = sizeof(mi);
  GlobalMemoryStatusEx(&mi);
  return mi.ullTotalPhys / g_bytes_per_kb;
#elif __linux__
  int error = sysinfo(&sys_info);
  if ( error == 0 )
    return sys_info.totalram/g_bytes_per_kb;
  return 0;
#endif
}

/* current uptime */
uint32_t uptime_in_secs() {
#ifdef _WIN64
  return GetTickCount() / 1000;
#elif __linux__
  int error = sysinfo(&sys_info);
  if ( error == 0 )
    return sys_info.uptime;
  return 0;
#endif
}

/* compiles a pulse string */
char* make_pulse_string()
{
  uint64_t total_ds = total_disk_space();
  uint64_t free_ds = available_space();
  uint64_t total_mem = total_physical_memory();
  uint64_t free_mem = available_memory();
  char *ps = (char*)malloc(g_max_buffer_len * sizeof(char));
  int psi = snprintf(ps, 100, "%.4f", cpu_load());
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%d", is_database_running());
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%d", uptime_in_secs());
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%llu", total_ds);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%llu", free_ds);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%.4f", 1.0-(float)free_ds/total_ds);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%d", total_mem);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%d", free_mem);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%.4f", 1.0-(float)free_mem/total_mem);
  return ps;
}

/* allocates memory for a fixed length comparison */
void allocate_key_buffer(char **key_t, const char *sock_data, uint16_t ak_len)
{
  *key_t = (char*)malloc((ak_len+1) * sizeof(char));
  strncpy(*key_t, sock_data, ak_len);
  (*key_t)[ak_len] = '\0'; // attach null terminator
}

#if _WIN64
#define PROCESS_CLIENT_FUNC DWORD WINAPI process_client(LPVOID lpParam)
#elif __linux__
#define PROCESS_CLIENT_FUNC DWORD WINAPI process_client(LPVOID lpParam)
#endif

/* process the client */
PROCESS_CLIENT_FUNC
{
  TP *tp = (TP*)lpParam;

  /* byte count */
  uint32_t bc = 0;

  /* key buffer */
  char *key_t = NULL;

  /* authority key length */
  uint16_t ak_len = strlen(tp->m_ak);

  /* socket data */
  char sock_data[g_max_buffer_len];

  /* max length of data chunk from on-going socket */
  socklen_t sock_data_len = g_max_buffer_len;

  /* consistently repeat to capture on-going byte stream */
  do
  {
    bc = recv(tp->m_responder, sock_data, sock_data_len, 0);

    /* proceed if authority key provided unless key length is zero */
    if ( ak_len == 0 || bc >= ak_len )
    {
      if ( ak_len > 0 )
        allocate_key_buffer(&key_t, sock_data, ak_len);

      /* check authority key given by client is 
         equal to the key defined in this instance */
      if ( ak_len == 0 || strcmp(key_t, tp->m_ak) == 0 )
      {
        char *ip_addr = inet_ntoa(tp->m_sa.sin_addr);
        if ( ak_len > 0 )
          printf("valid authority key provided by client: %s\n", ip_addr);
        char *ps = make_pulse_string();
        if ( send(tp->m_responder, ps, strlen(ps), 0) != SOCKET_ERROR )
          printf("%s => %s\n", ps, ip_addr);
        free(ps);
      }
      if ( ak_len > 0 )
        free(key_t);
      closesocket(tp->m_responder);
      shutdown(tp->m_responder, SD_BOTH);
      bc = 0;
    }
  }
  while(bc > 0); /* terminates when byte count equal to zero */
  if ( tp->m_last != NULL )
    CloseHandle(tp->m_last);
  free(tp);
  return 0;
}

#ifdef _WIN64
/* entry point for windows */
int win(char *ak)
{
  /* winsock */
  WSADATA wsa_data;

  /* address info structs */
  struct addrinfo *result = NULL;
  struct addrinfo hints;

  /* start winsock 2.2 - ec = error code should problem arise */
  uint32_t ec = WSAStartup(MAKEWORD(2,2), &wsa_data);
  if ( ec != 0 ) {
    printf("winsock library failed with code: %d", ec);
    return 1;
  }

  /* fills structure with zeros */
  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_INET;        /* IPv4 */
  hints.ai_socktype = SOCK_STREAM;  /* 2-way OOB binary data (send, receive) */
  hints.ai_protocol = IPPROTO_TCP;  /* transmission control protocol */
  hints.ai_flags = AI_PASSIVE;      /* socket address used in bind func */

  /* pull info */
  ec = getaddrinfo(NULL, g_daemon_port, &hints, &result);
  if ( ec != 0 ) {
    printf("getaddrinfo failed with error: %d\n", ec);
    WSACleanup();
    return 1;
  }

  /* init a socket */
  g_listener = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if ( g_listener == INVALID_SOCKET ) {
    printf("socket failed with error: %d\n", WSAGetLastError());
    freeaddrinfo(result);
    WSACleanup();
  }

  /* bind to address and port of our choosing */
  ec = bind(g_listener, result->ai_addr, (int)result->ai_addrlen);
  if ( ec == SOCKET_ERROR ) {
    printf("binding failed with error: %d\n", WSAGetLastError());
    freeaddrinfo(result);
    closesocket(g_listener);
    WSACleanup();
    return 1;
  }

  /* release memory for linked list of addinfo structures */
  freeaddrinfo(result);

  /* the socket is setup to listen, this is non-blocking, the accept 
     function inside the indefinite loop (below) is blocking */
  ec = listen(g_listener, SOMAXCONN);
  if ( ec == SOCKET_ERROR ) {
    printf("listener failed with error: %d\n", WSAGetLastError());
    closesocket(g_listener);
    WSACleanup();
    return 1;
  }

  g_handle = NULL;

  /* --- REPEAT */
  while(1)
  {
    printf("awaiting connection(s)...\n");

    /* --- ADDR */
    struct sockaddr_in sa = {0};
    socklen_t sock_len = sizeof(sa);

    /* --- ACCEPT */
    SOCKET responder = accept(g_listener, (struct sockaddr *) &sa, &sock_len);
    if (responder == INVALID_SOCKET) {
      printf("accept failed with error: %d\n", WSAGetLastError());
      if ( g_handle != NULL ) {
        WaitForSingleObject(g_handle, 5000);
        CloseHandle(g_handle);
      }
      closesocket(g_listener);
      WSACleanup();
      return 1;
    }

    // --- INIT THREAD
    TP *tp = (TP*)malloc(sizeof(TP));
    tp->m_ak = ak;
    tp->m_responder = responder;
    tp->m_sa = sa;
    tp->m_last = g_handle;
    tp->m_this = tp;
    g_handle = CreateThread(NULL, 0, process_client, (LPVOID)tp, 0, NULL);
  }
  return 0;
}
#elif __linux__
int lin(char *ak) {

  /* file descriptors */
  int32_t server, client;

  /* addr struct length */
  socklen_t client_addr_length;

  /* socket data buffered length */
  char sock_data[g_max_buffer_len];

  /* server and client addr structs */
  struct sockaddr_in serv_addr, cli_addr;

  /* ip address buffer */
  char *ip_addr = NULL;

  /* socket option preference */
  int opt = 1;
  
  /* length of authority key */
  uint16_t ak_len = strlen(ak);

  /* null terminated key buffer */
  char *key_t = NULL;

  /* poll the cpu */
  update_cpu_stats();
  sleep(1);

  while(1)
  {
    ip_addr = (char*)malloc((INET6_ADDRSTRLEN+1) * sizeof(char));

  	server = socket(AF_INET, SOCK_STREAM, 0);
  	if ( server < 0 ) {
  		perror("socket opening ERROR");
  		continue;
  	}

    /* fill with zeros */
  	bzero((char*)&serv_addr, sizeof(serv_addr));

    /* set socket options */
    if ( setsockopt(server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(atoi(g_daemon_port));

    /* bind to ip and port */
    if ( bind(server, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 )
    {
        perror("socket binding ERROR");
        close(server);
        continue;
    }

    printf("awaiting connection(s)...\n");

    /* listen */
    listen(server, 10);
    client_addr_length = sizeof(cli_addr);
    client = accept(server, (struct sockaddr*)&cli_addr, &client_addr_length);
    if ( client < 0 ) {
      perror("socket accept ERROR");
      close(server);
      continue;
    }

    /* cleanse the struct with zeros before read */
    bzero(sock_data, g_max_buffer_len);

    /* read data chunk */
    if ( read(client, sock_data, g_max_buffer_len-1) < 0 ) {
      perror("socket read ERROR");
      close(client);
      close(server);
      continue;
    }
    bzero(ip_addr, INET6_ADDRSTRLEN);

    /* ipv6 addresses consist of a maximum 39 characters */
    get_client_ip((struct sockaddr*)&cli_addr, ip_addr);

    if ( ak_len > 0 )
      allocate_key_buffer(&key_t, sock_data, ak_len);

    /* pulse string */
    char* ps;

    /* check authoriy key given by client is 
       equal to the key defined in this instance */
    if ( ak_len == 0 || strcmp(key_t, ak) == 0 )
    {
      if ( ak_len > 0 )
        printf("valid authority key (%s) provided by client (%s)\n", ak, ip_addr);

      /* compile pulse string and send back */
      ps = make_pulse_string();
      if ( write(client, ps, strlen(ps)) < 0 )
        perror("socket write ERROR");
      else
        printf("%s => %s\n", ps, ip_addr);
      free(ps);
    }
    else
    {
      printf("invalid authority key (%s) provided by client (%s)\n", sock_data, ip_addr);
    }
    if ( ak_len > 0 )
      free(key_t);
    free(ip_addr);
    close(client);
    close(server);
    sleep_ms(200);
  }
  return 0;
}
#endif

/* extracts a key from the command line argument */
uint8_t extract_key(char *str, size_t n)
{
  size_t l = strlen(str);
  if ( n > l )
    return 0;
  memmove(str, str+n, l-n+1);
  return 1;
}

/*
sums the number of process names provided in 
g_process_check_for meaning its not necessary to 
hardcode the number of processes in the array
*/
uint8_t process_names_count()
{
  uint8_t c = 0;
  while ( g_process_check_for[++c] != NULL )
    continue;
  return c;
}

/* routine to cleanly exit */
void clean_exit(int s)
{
#ifdef _WIN64
  if ( g_handle != NULL )
  {
    WaitForSingleObject(g_handle, 5000);
    CloseHandle(g_handle);
  }
  closesocket(g_listener);
  WSACleanup();
#endif
}

/*
accepts override using the -k flag: ./server -kKEY_TEXT
*/
int main(int argc, char *argv[])
{
  signal(SIGINT, clean_exit);

  argc -= 1;
  char *ak = "";
  if ( argc >= 1 ) {
    if ( strlen(argv[1]) >= 3 ) {
      if ( argv[1][0] == '-' && argv[1][1] == 'k' ) {
        if ( extract_key(argv[1], 2) != 0 )
          ak = argv[1];
  }}}
  g_process_count = process_names_count();
  
  printf("\nPulse Server... (CTRL+C to exit)\n");
  if ( strlen(ak) )
    printf("Authority key set to: %s\n\n", ak);
  else
    printf("Key-less mode, any client can probe this server\n\n");
  
#ifdef _WIN64
  return win(ak);
#elif __linux__
  return lin(ak);
#endif
}
