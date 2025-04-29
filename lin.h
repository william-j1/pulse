
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
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
