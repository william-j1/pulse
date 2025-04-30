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
*/
#ifndef __LIN_H
#define __LIN_H

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
#include <inttypes.h>
#include <time.h>
#include <pthread.h>

/* threading property parameter */
typedef struct
{
  /* authority key */
  char *m_ak;

  /* response socket */
  int32_t m_responder;

  /* af addr/port */
  struct sockaddr_in m_sa;

  void *m_last;
} TP;

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

const char *get_client_ip(const struct sockaddr *sa, char *ip_addr);
const uint8_t get_cpu_stats(struct cpu_stats* stats);
const double get_cpu_usage();
const pid_t get_process_id(const char *pname);
const uint8_t update_cpu_stats();

#endif // __LIN_H