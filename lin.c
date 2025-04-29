#include "lin.h"

const char *get_client_ip(const struct sockaddr *sa, char *ipstr, uint16_t mlen)
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

const uint8_t get_cpu_stats(struct cpu_stats* stats)
{
  FILE* file = fopen("/proc/stat", "r");
  if (file == NULL)
    return 0;
  fscanf(
    file, 
    "cpu %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
    &stats->user, 
    &stats->nice, 
    &stats->system, 
    &stats->idle,
    &stats->iowait,
    &stats->irq,
    &stats->softirq,
    &stats->steal,
    &stats->guest,
    &stats->guest_nice
  );
  fclose(file);
  return 1;
}

const double get_cpu_usage()
{
    uint64_t prev_idle = cpu_p.idle + cpu_p.iowait;
    uint64_t curr_idle = cpu_c.idle + cpu_c.iowait;
    uint64_t prev_non_idle = cpu_p.user + cpu_p.nice + cpu_p.system + cpu_p.irq + cpu_p.softirq + cpu_p.steal;
    uint64_t curr_non_idle = cpu_c.user + cpu_c.nice + cpu_c.system + cpu_c.irq + cpu_c.softirq + cpu_c.steal;
    uint64_t prev_total = prev_idle + prev_non_idle;
    uint64_t curr_total = curr_idle + curr_non_idle;
    uint64_t total_diff = curr_total - prev_total;
    uint64_t idle_diff = curr_idle - prev_idle;
    return (double)(total_diff - idle_diff) / total_diff;
}

/* iterate processes in /proc for ident */
const pid_t get_process_id(const char *pname)
{
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

const uint8_t update_cpu_stats()
{
  cpu_p = cpu_c;
  return get_cpu_stats(&cpu_c);
}
