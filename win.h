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
#ifndef __WIN_H
#define __WIN_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <stdint.h>

/* threading property parameter */
typedef struct
{
  /* authority key */
  char *m_ak;

  /* response socket */
  SOCKET m_responder;

  /* af addr/port */
  struct sockaddr_in m_sa;

  /* point to last */
  HANDLE m_last;

  /* point to this */
  void *m_this;
} TP;

/* SOCKET (UINT_PTR) for server */
static SOCKET g_listener = INVALID_SOCKET;

const uint8_t has_process(const char *p_list[], const uint8_t p_count);

#endif // __WIN_H