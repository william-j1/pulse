#include <stdio.h>
#include <stdint.h>
#include <string.h>
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

#ifndef __LIN_H
#define __LIN_H

/*
https://www.man7.org/linux/man-pages/man5/proc_stat.5.html
*/
struct cpu_stats
{
  /* user mode time   */   uint64_t user;
  /* low priority um  */   uint64_t nice;
  /* system mode time */   uint64_t system;
  /* idle time */          uint64_t idle;
  /* io spent */           uint64_t iowait;
  /* hw interrupts */      uint64_t irq;
  /* sw interrupts */      uint64_t softirq;
  /* stolen by a vcpu */   uint64_t steal;
  /* hypervisor time */    uint64_t guest;
  /* scheduling proirity */uint64_t guest_nice;
};

/* system info struct */
static struct sysinfo sys_info;

/* past and current (cpu_p, cpu_c)
   stats to manipulate for
   delta change in respect 
   cpu timings */
static struct cpu_stats cpu_p, cpu_c;

const char *get_client_ip(const struct sockaddr *sa, char *ipstr, uint16_t mlen);
const uint8_t get_cpu_stats(struct cpu_stats* stats);
const double get_cpu_usage();
const pid_t get_process_id(const char *pname);
const uint8_t update_cpu_stats();

#endif // __LIN_H