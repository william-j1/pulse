/*

ABOUT:

Copyright (c) 2024 William Johnson <williamj.inbox@gmail.com>

Drops useful summary data concerning an active live data server. May be
utilised by an autonomous client to sweep across a cluster of servers to
pinpoint those approaching load capacities and maintain an eye on running
database processes.

Clients may thereafter be configured to dispatch alerts to admin personnel
to address these key infrastructural concerns.

DEPLOYMENT NOTES:

1. Change the g_daemon_key value.

2. Change the g_daemon_port to prevent autonomous landers.

3. Keep a secure note of all keys you generate for daemon deployment
   and configure your client to point to the location of your server(s).

*/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN64

/*
compile on windows: gcc server.c -o pulse.exe -lpsapi -lws2_32
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>

#elif __linux__

#include <stdlib.h>
#include <linux/kernel.h> /* for struct sysinfo */
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct cpu_stats {
    uint64_t user;
    uint64_t nice;
    uint64_t system;
    uint64_t idle;
    uint64_t iowait;
    uint64_t irq;
    uint64_t softirq;
    uint64_t steal;
    uint64_t guest;
    uint64_t guest_nice;
};

/* system info struct */
struct sysinfo s_info;
struct cpu_stats prev_stats, curr_stats;

int get_cpu_stats(struct cpu_stats* stats) {
  FILE* file = fopen("/proc/stat", "r");
  if (file == NULL)
    return -1;
  fscanf(file, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
         &stats->user, &stats->nice, &stats->system, &stats->idle,
         &stats->iowait, &stats->irq, &stats->softirq, &stats->steal,
         &stats->guest, &stats->guest_nice);
  fclose(file);
  return 0;
}
double calculate_cpu_usage(struct cpu_stats* prev, struct cpu_stats* curr) {
    uint64_t prev_idle = prev->idle + prev->iowait;
    uint64_t curr_idle = curr->idle + curr->iowait;
    uint64_t prev_non_idle = prev->user + prev->nice + prev->system + prev->irq + prev->softirq + prev->steal;
    uint64_t curr_non_idle = curr->user + curr->nice + curr->system + curr->irq + curr->softirq + curr->steal;
    uint64_t prev_total = prev_idle + prev_non_idle;
    uint64_t curr_total = curr_idle + curr_non_idle;
    uint64_t total_diff = curr_total - prev_total;
    uint64_t idle_diff = curr_idle - prev_idle;
    return (double)(total_diff - idle_diff) / total_diff;
}

/* iterate processes in /proc for ident */
pid_t process_id(const char *pname) {
  DIR* dir;
  struct dirent* ent;
  char* endptr;
  char buffert[512];
  if ( !(dir = opendir("/proc")) )
      return -1;
  while((ent = readdir(dir)) != NULL) {
      long lpid = strtol(ent->d_name, &endptr, 10);
      if (*endptr != '\0')
          continue;
      snprintf(buffert, sizeof(buffert), "/proc/%ld/cmdline", lpid);
      FILE* fp = fopen(buffert, "r");
      if (fp) {
          if (fgets(buffert, sizeof(buffert), fp) != NULL) {
              char *tokent = strtok(buffert, " ");
              char *splitt = strtok(tokent, "/");
              while ( splitt != NULL ) {
                if ( strcmp(splitt, pname) == 0 ) {
                  fclose(fp);
                  closedir(dir);
                  return (pid_t)lpid;
                }
                splitt = strtok(NULL, "/");
              }
          }
          fclose(fp);
      }
  }
  closedir(dir);
  return -1;
}

#endif

#if _POSIX_C_SOURCE >= 199309L
#include <time.h> // +nanosleep
#endif

/* daemon key for pulse - this is the key which the clients must
   provide for the connection to be successful */
static const char g_daemon_key[] = "";

/* daemon port - this is the port bind, the server (this) listens
   and accepts client requests to this port */
static const char g_daemon_port[] = "1382";

/* delimitor used to separate metrics */
static const char g_delimitor[] = ":";

/* bytes in kb, base-2 interpretation as opposed to SI units */
static const uint16_t g_bytes_per_kb = 1024;

/* number of db processes to enquire */
static uint8_t g_process_count;

/* list of process names to expect, if you want to add game servers, add the process name in this array */
static const char *g_db_process_list[] = {"mysql", "mysqld.exe", "mysqld", "mariadbd", "memcached", "db2sysc", "cassandra", "redis-server", "mongod", "mongos", "tnslsnr", "oracle", "sqlservr", "postgres"};

/* internal buffer length to handle network-io */
static const uint16_t g_max_buffer_len = 512;

/* mount point for checking disk stats */
#ifdef _WIN64
static const char g_mount_point[] = "C:\\";
#elif __linux__
static const char g_mount_point[] = "/";
#endif

/* sleep function in milliseconds */
void sleep_ms(uint32_t milliseconds) {
#ifdef WIN32
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
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

/* current cpu load using prior tick computation */
double cpu_load()
{
#ifdef _WIN64
  FILETIME it; /* idle time */
  FILETIME kt; /* kernel time */
  FILETIME ut; /* user time */
  if ( GetSystemTimes(&it, &kt, &ut) ) {
    static uint64_t previousTotalTicks = 0;
    static uint64_t previousIdleTicks = 0;
    uint64_t idleTicks = (((uint64_t)(it.dwHighDateTime))<<32)|((uint64_t)it.dwLowDateTime);
    uint64_t totalTicks = (((uint64_t)(kt.dwHighDateTime))<<32)|((uint64_t)kt.dwLowDateTime);
    totalTicks += (((uint64_t)(ut.dwHighDateTime))<<32)|((uint64_t)ut.dwLowDateTime);
    uint64_t ttd = totalTicks - previousTotalTicks;
    uint64_t itd = idleTicks - previousIdleTicks;
    double delta = (ttd > 0) ? ((double)itd)/ttd : 0;
    previousTotalTicks = totalTicks;
    previousIdleTicks = idleTicks;
    return 1.0 - delta;
  }
  return 0.0;
#elif __linux__
  prev_stats = curr_stats;
  if ( get_cpu_stats(&curr_stats) != 0 )
    return 0;
  double usage = calculate_cpu_usage(&prev_stats, &curr_stats);
  return usage;
#endif
}

/* signals that a live database is running */
uint8_t database_running() {
  uint32_t q = 0;
#ifdef _WIN64
  DWORD processIds[1024], bytesNeeded, procCount;
  HANDLE hProcess = NULL;
  TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
  uint32_t p = 0;
  if ( !EnumProcesses(processIds, sizeof(processIds), &bytesNeeded) )
    return 0;
  procCount = bytesNeeded / sizeof(DWORD);
  for ( ; p < procCount; p++ ) {
    if( processIds[p] != 0 ) {
      hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                             FALSE,
                             processIds[p]);
      if (hProcess != NULL)
      {
        HMODULE hMod;
        DWORD cbNeeded;
        if ( EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded) )
        {
          GetModuleBaseName(hProcess,
                            hMod,
                            szProcessName,
                            sizeof(szProcessName)/sizeof(TCHAR));
          CloseHandle(hProcess);
          for ( q = 0; q < g_process_count; q++ ) {
            if ( strcmp(g_db_process_list[q], szProcessName) == 0 )
              return 1;
  }}}}}
  return 0;
#elif __linux__
  for ( q = 0; q < g_process_count; q++ ) {
    if ( process_id(g_db_process_list[q]) != -1 )
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
  int error = sysinfo(&s_info);
  if ( error == 0 )
    return s_info.totalram/g_bytes_per_kb;
  return 0;
#endif
}

/* current uptime */
uint32_t uptime_in_secs() {
#ifdef _WIN64
  return GetTickCount() / 1000;
#elif __linux__
  int error = sysinfo(&s_info);
  if ( error == 0 )
    return s_info.uptime;
  return 0;
#endif
}

/* compiles a pulse string */
char* make_pulse_string()
{
  uint64_t total_ds = total_disk_space();
  uint64_t free_ds = available_space();
  uint32_t total_mem = total_physical_memory();
  uint32_t free_mem = available_memory();
  char *ps = (char*)malloc(g_max_buffer_len * sizeof(char));
  int psi = snprintf(ps, 100, "%.4f", cpu_load());
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%s", g_delimitor);
  psi += snprintf(ps+psi, g_max_buffer_len-psi, "%d", database_running());
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

#ifdef _WIN64
/* entry point for windows */
int winmain(char *ak)
{
  /* winsock library */
  WSADATA wsa_data;

  /* listener and responder */
  SOCKET listener = INVALID_SOCKET;
  SOCKET responder = INVALID_SOCKET;

  /* address info structs */
  struct addrinfo *result = NULL;
  struct addrinfo hints;

  /* socket work variables */
  char socket_data[g_max_buffer_len];

  /* max length of data chunk from on-going socket */
  socklen_t socket_data_len = g_max_buffer_len;

  /* byte count received */
  uint32_t bc = 0;

  /* null terminated key buffer */
  char *keybuffer_t = NULL;

  /* length of authority key */
  uint16_t ak_len = strlen(ak);

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
  listener = socket(result->ai_family,
                    result->ai_socktype,
                    result->ai_protocol);
  if ( listener == INVALID_SOCKET ) {
    printf("socket failed with error: %d\n", WSAGetLastError());
    freeaddrinfo(result);
    WSACleanup();
  }

  /* bind to address and port of our choosing */
  ec = bind(listener, result->ai_addr, (int)result->ai_addrlen);
  if ( ec == SOCKET_ERROR ) {
    printf("binding failed with error: %d\n", WSAGetLastError());
    freeaddrinfo(result);
    closesocket(listener);
    WSACleanup();
    return 1;
  }

  /* release memory for linked list of addinfo structures */
  freeaddrinfo(result);

  /* the socket is setup to listen, this is non-blocking, the accept 
     function inside the indefinite loop (below) is blocking */
  ec = listen(listener, SOMAXCONN);
  if ( ec == SOCKET_ERROR ) {
    printf("listener failed with error: %d\n", WSAGetLastError());
    closesocket(listener);
    WSACleanup();
    return 1;
  }

  /* repeat */
  while(1)
  {
    printf("awaiting connection(s)...\n");

    /* record address of client */
    struct sockaddr_in sa = {0};
    socklen_t socklen = sizeof(sa);

    /* accept the connection */
    responder = accept(listener, (struct sockaddr *) &sa, &socklen);
    if (responder == INVALID_SOCKET) {
      printf("accept failed with error: %d\n", WSAGetLastError());
      closesocket(listener);
      WSACleanup();
      return 1;
    }

    /* consistently repeat to capture on-going byte stream */
    do
    {
      /* receive a data chunk up to the buffer length */
      bc = recv(responder, socket_data, socket_data_len, 0);

      /* proceed if authority key provided unless key length is zero */
      if ( ak_len == 0 || bc >= ak_len )
      {
        if ( ak_len > 0 )
        {
          /* length specific comparison */
          keybuffer_t = (char*)malloc((ak_len+1) * sizeof(char));
          strncpy(keybuffer_t, socket_data, ak_len);
          keybuffer_t[ak_len] = '\0'; // attach null terminator
        }

        /* check authority key given by client is 
           equal to the key defined in this instance */
        if ( ak_len == 0 || strcmp(keybuffer_t, ak) == 0 )
        {
          /* pull ip */
          char *c_ipaddr = inet_ntoa(sa.sin_addr);

          /* server-side logs visible through a screen session */
          if ( ak_len > 0 )
            printf("valid authority key provided by client: %s\n", c_ipaddr);

          /* compile a pulse string and send back to the client */
          char *ps = make_pulse_string();

          if ( send(responder, ps, strlen(ps), 0) != SOCKET_ERROR )
            printf("%s => %s\n", ps, c_ipaddr);
          free(ps);
        }
        if ( ak_len > 0 )
          free(keybuffer_t);
        closesocket(responder);
        shutdown(responder, SD_BOTH);
        bc = 0;
      }
    }
    while(bc > 0); /* terminates when byte count equal to zero */

    /* do events */
    sleep_ms(200);
  }
  closesocket(listener);
  WSACleanup();
  return 0;
}
#elif __linux__
char *get_client_ip(const struct sockaddr *sa, char *ipstr, uint16_t mlen)
{
	switch(sa->sa_family)
  {
		case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), ipstr, mlen);
		break;
		case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), ipstr, mlen);
		break;
		default:
		strncpy(ipstr, "Unknown AF", mlen);
		return NULL;
	}
	return ipstr;
}
int linmain(char *ak) {

  /* socket handles */
  int32_t socket_server, socket_client;

  /* addr struct length */
  socklen_t client_addr_length;

  /* socket data buffer length */
  char socket_data[g_max_buffer_len];

  /* server and client addr structs */
  struct sockaddr_in serv_addr, cli_addr;

  /* ip address buffer */
  char c_ipaddr[64];

  /* socket option preference */
  int opt = 1;
  
  /* length of authority key */
  uint16_t ak_len = strlen(ak);

  /* null terminated key buffer */
  char *keybuffer_t = NULL;

  /* poll the cpu */
  get_cpu_stats(&curr_stats);
  sleep(1);

  while(1)
  {
  	socket_server = socket(AF_INET, SOCK_STREAM, 0);
  	if ( socket_server < 0 ) {
  		perror("socket opening ERROR");
  		continue;
  	}

    /* fill with zeros */
  	bzero((char*)&serv_addr, sizeof(serv_addr));

    /* set socket options */
    if ( setsockopt(socket_server, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(atoi(g_daemon_port));

    /* bind to ip and port */
    if ( bind(socket_server, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 )
    {
        perror("socket binding ERROR");
        close(socket_server);
        continue;
    }

    printf("awaiting connection(s)...\n");

    /* listen */
    listen(socket_server, 10);
    client_addr_length = sizeof(cli_addr);
    socket_client = accept(socket_server, (struct sockaddr*)&cli_addr, &client_addr_length);
    if ( socket_client < 0 ) {
      perror("socket accept ERROR");
      close(socket_server);
      continue;
    }

    /* cleanse the struct with zeros before read */
    bzero(socket_data, g_max_buffer_len);

    /* read data chunk */
    if ( read(socket_client, socket_data, g_max_buffer_len-1) < 0 ) {
      perror("socket read ERROR");
      close(socket_client);
      close(socket_server);
      continue;
    }
    bzero(c_ipaddr, 64);

    /* ipv6 addresses consist of a maximum 39 characters */
    get_client_ip((struct sockaddr*)&cli_addr, c_ipaddr, 64);

    if ( ak_len > 0 )
    {
      /* length specific comparison */
      keybuffer_t = (char*)malloc((ak_len+1) * sizeof(char));
      strncpy(keybuffer_t, socket_data, ak_len);
      keybuffer_t[ak_len] = '\0'; // attach null terminator
    }

    /* pulse string */
    char* ps;

    /* check authoriy key given by client is 
       equal to the key defined in this instance */
    if ( ak_len == 0 || strcmp(keybuffer_t, ak) == 0 )
    {
      if ( ak_len > 0 )
        printf("valid authority key (%s) provided by client (%s)\n", ak, c_ipaddr);

      /* compile pulse string and send back */
      ps = make_pulse_string();
      if ( write(socket_client, ps, strlen(ps)) < 0 )
        perror("socket write ERROR");
      else
        printf("%s => %s\n", ps, c_ipaddr);
      free(ps);
    }
    else
    {
      printf("invalid authority key (%s) provided by client (%s)\n", socket_data, c_ipaddr);
    }
    if ( ak_len > 0 )
      free(keybuffer_t);
    close(socket_client);
    close(socket_server);
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
g_db_process_list meaning its not necessary to 
hardcode the number of processes in the array
*/
uint8_t process_names_count()
{
  uint8_t c = 0;
  while ( g_db_process_list[++c] != NULL )
    continue;
  return c;
}

/*
accepts override using the -k flag: ./server -kKEY_TEXT
*/
int main(int argc, char *argv[])
{
  argc -= 1;
  char *ak = (char *)g_daemon_key;
  if ( argc >= 1 ) {
    if ( strlen(argv[1]) >= 3 ) {
      if ( argv[1][0] == '-' && argv[1][1] == 'k' ) {
        if ( extract_key(argv[1], 2) != 0 )
          ak = argv[1];
  }}}
  g_process_count = process_names_count();

  printf("Pulse Server\n\n");
  if ( strlen(ak) )
    printf("Authority key set to: %s\n\n", ak);
  else
    printf("Key-less mode, any client can probe this server\n\n");
#ifdef _WIN64
  return winmain(ak);
#elif __linux__
  return linmain(ak);
#endif
}
