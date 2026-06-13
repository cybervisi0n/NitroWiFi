#include <nitro.h>
#include <nitroWiFi.h>
#include <nitroWiFi/decomp/decomp_defs_nitrowifi.h>

#ifdef SDK_BUILD_WIN64
#include <winsock2.h>
#endif
#ifdef SDK_BUILD_LINUX
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#endif

#ifndef SDK_BUILD_ARM
#include <SDL2/SDL.h>
#include <SDL2/SDL_thread.h>
#endif

#include "nitroWiFi/cps.h"

#ifndef SDK_BUILD_ARM
static SDL_mutex * s_SocketSharedMutex = NULL;
static SDL_mutex * s_SocketThreadStartupMutex = NULL;
#endif

static char * analyze_format(char *param_1,char *param_2,undefined4 param_3,char *param_4);
static int arprequest(undefined4 param_1);
static char * byte2a(char *param_1,uint param_2);
static void calc_checksum(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
static uint calc_checksum_do(ushort *param_1,uint param_2,uint param_3);
static byte * check_frag(byte *param_1,undefined4 *param_2);
static int * check_listener(int param_1,undefined2 *param_2);
static undefined4 check_socket(int param_1,undefined2 *param_2,int param_3);
static BOOL check_tcpudpsum(undefined4 param_1,int param_2,int param_3,uint param_4);
static BOOL default_link_is_on(void);
static int dhcp_analyze_response(uint param_1,int param_2,undefined4 param_3,uint param_4);
static BOOL dhcp_discover_server(void);
static void dhcp_release_server(void);
static undefined4 dhcp_request_server(uint *param_1,int param_2);
static undefined4 dhcp_send_discover(void);
static undefined4 dhcp_send_request(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
static int dhcp_setcommon(undefined2 *param_1,undefined param_2,uint *param_3);
static void dispatch_arp(ushort *param_1,uint param_2,undefined4 param_3,undefined4 param_4);
static void dispatch_icmp(int param_1,char *param_2,undefined4 param_3,undefined4 param_4);
static void dispatch_ip(byte *param_1,uint param_2,undefined4 param_3,int param_4);
static void dispatch_tcp(undefined4 param_1,int param_2,int param_3);
static void dispatch_udp(int param_1,undefined2 *param_2,int param_3);
static char * dns_skipname(char *aName);
static void dt_ack(undefined4 param_1,int param_2,uint param_3,undefined4 param_4);
static void dt_fin(undefined4 param_1,undefined4 param_2,undefined4 param_3);
static void dt_rst(undefined4 param_1,undefined4 param_2);
static void dt_syn(int param_1,undefined4 param_2,undefined4 param_3);
static void dt_synack(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4);
static void dt_syn_LISTEN(int param_1,undefined2 *param_2,int param_3);
static void empty_func(void);
static int * find_socket(undefined4 param_1,undefined4 param_2);
static undefined4 find_specific_socket(undefined4 param_1,undefined4 param_2,undefined4 param_3);
static void get_seqno(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
static unsigned long get_targetip(unsigned long param_1);
static void handle_arg(undefined *param_1,byte *param_2,int *param_3,undefined4 param_4);
static uchar * inq_arpcache(unsigned long param_1);
static ushort invert_checksum(ushort param_1);
static undefined4 ip_islocal(uint param_1);
static undefined4 ip_isme(unsigned long param_1);
static undefined4 is_broadcast(uint param_1);
static BOOL is_multicast(uint param_1);
static void justify_string(char *param_1,char *param_2,int param_3,int param_4,int param_5);
static undefined4 maccmp(short *param_1,short *param_2);
static undefined4 no_need_inq(undefined4 param_1);
static int pad_mem(undefined param_1,uint param_2,int param_3,uint param_4);
static void parse_mss(int param_1,int param_2);
static void process_icmp_reply(int param_1,int param_2,int param_3);
static void put_in_buffer(undefined4 param_1,undefined4 param_2,char *param_3,int param_4,int param_5,
                  int param_6);
static undefined4 rawip(char *param_1,uint *param_2);
static uchar * receive_packet(int *param_1);
static void reg_arpcache(undefined4 param_1,unsigned long param_2,int param_3);
static void reply_arp(int param_1);
static void reply_icmp(int param_1,undefined *param_2,undefined4 param_3);
static void reset_network_vars(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
static int resolve_common(char *aName,uint param_2,ushort aIdent,undefined4 param_4,uint param_5);
static undefined4 resolve_sub(char * aName, CPSInAddr aDnsIP, undefined2 param_3);
static void return_integer(undefined4 param_1,int param_2,int *param_3,int param_4,undefined4 param_5);
static CPSInAddr rev_resolve_sub(undefined4 param_1,int param_2,undefined2 param_3,undefined4 param_4,
               undefined4 param_5);
static void scavenger(void * arg);
static void send_arprequest(CPSInAddr aIP);
static void send_ether(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
               undefined2 param_6);
static void send_ip(int param_1,uint param_2,int param_3,int param_4,uint param_5,undefined param_6);
static void send_ip_frag(int param_1,int param_2,undefined4 param_3,int param_4,unsigned long param_5,
                 undefined2 param_6);
static void send_packet(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
static void send_ping(undefined4 param_1,undefined4 param_2,int param_3);
static void send_tcp(undefined4 param_1,int param_2,int param_3,byte param_4);
static void send_udp(void * aBuf,int aLen,CPSSoc * aSoc);
static void set_fixed_ip(void);
#ifndef SDK_PORT
static void strlwr(byte *param_1);
static void CreateSocketEvent(CPSSoc * aSoc);
#endif
static int strtol10(byte *param_1,char **param_2);
static void tcpip(void * arg);
static void tcp_send_ack(undefined4 param_1,undefined2 param_2,undefined4 param_3,undefined4 param_4);
static void tcp_send_finack(undefined4 param_1,undefined2 param_2,undefined4 param_3,undefined4 param_4);
static void tcp_send_handshake(int param_1,undefined param_2,undefined2 param_3,undefined4 param_4);
static void tcp_send_rst(int param_1,undefined2 *param_2,int param_3,undefined4 param_4);
static u32 tcp_write_do(u8 * buf, u32 len, CPSSoc * aSoc, int param_4);
static void tcp_write_do2(u8* buf, u32 len, u8* buf2, u32 len2, CPSSoc * aSoc, undefined4 param_6);
static void throw_packet(void);
static void tostring(char *param_1,int param_2,undefined4 param_3);
static u8 * udp_read_raw(u32 *len,CPSSoc * aSoc);
static undefined4 valid_IP(int param_1,int param_2);

static void * scavenger_callback;
static unsigned long helper_threads_priority;
static CPSArpCache * arpcache;
static CPSFragTable * fragtable;
static u8 scavenger_force_exit;
static u32 mymss;
static CPSInAddr offered_myip;
static u32 yield_wait;
static u8 * wlan_buf;
static u32 wlan_buflen;
static u32 mode;
static u32 wlan_getpnt;
static u32 wlan_putpnt;
static u8 ip_conflict;
static OSThread tcpip_thread;
static OSThread scavenger_thread;
static u8 * tcpip_stack;
static u16 eport;
int CPSNoIpReason;

#ifdef SDK_PORT
u8 win_tcpip_thread_stack[0x800];
u8 win_scavenger_thread_stack[0x800];

#ifdef SDK_BUILD_WIN64
WSAEVENT WIN_EventArray[WSA_MAXIMUM_WAIT_EVENTS];
CPSSoc * WIN_SocEventArray[WSA_MAXIMUM_WAIT_EVENTS];
u8 WIN_EventTotal = 0;
#endif

#ifdef SDK_BUILD_LINUX
u8 WIN_SocketTotal = 0;
#define MAX_NUM_OPEN_SOCKETS 128
CPSSoc * WIN_SocketArray[MAX_NUM_OPEN_SOCKETS] = {0};
#endif

static SDL_Thread * WIN_socThread = 0;
static u8 s_stopSocThread = 0;
static u8 s_SocThreadReady = 0;
#endif

MATHRandContext32 CPSiRand32ctx;

void *(*CPSiAlloc)(u32);
void (*CPSiFree)(void *);
BOOL (*link_is_on)(void);
void (*dhcp_callback)(void);

/*---------------------------------------------------------------------------*
 *
 * PORT Platform Only Procedures
 * 
 *---------------------------------------------------------------------------*/
#ifdef SDK_PORT
void CreateSocketEvent(CPSSoc * aSoc) {
  #ifdef SDK_BUILD_WIN64
  SDL_LockMutex(s_SocketSharedMutex);
  WIN_EventArray[WIN_EventTotal] = WSACreateEvent();

  aSoc->WIN_eventArrayNum = WIN_EventTotal;
  WIN_SocEventArray[WIN_EventTotal] = aSoc;

  WIN_EventTotal++;
  SDL_UnlockMutex(s_SocketSharedMutex);
  #endif
  #ifdef SDK_BUILD_LINUX
  SDL_LockMutex(s_SocketSharedMutex);
  WIN_SocketArray[WIN_SocketTotal] = aSoc;
  WIN_SocketTotal++;
  SDL_UnlockMutex(s_SocketSharedMutex);
  #endif
}

static int WIN_CPS_SocThreadFunc(void * arg){
  //CPSSoc * mySoc = (CPSSoc *)arg;
  #ifdef SDK_BUILD_WIN64
  DWORD dwEvent;

  WSANETWORKEVENTS NetworkEvents;

  while(TRUE){
    //int numBytes = recvfrom(mySoc->WIN_socket, mySoc->rcvbuf.data + mySoc->rcvbufp, mySoc->rcvbuf.size - mySoc->rcvbufp, 0, (struct sockaddr *)&server, &sz);
    //if( numBytes == SOCKET_ERROR )
    //{
    //  printf("WIN_CPS_SocThreadFunc WinError: %d\n", WSAGetLastError());
    //}

    //mySoc->rcvbufp += numBytes;
    if(s_stopSocThread) {
      return 0;
    }

    dwEvent = WSAWaitForMultipleEvents(WIN_EventTotal, WIN_EventArray, FALSE, 10, FALSE);

    switch (dwEvent) {
      case WSA_WAIT_FAILED:
        //printf("WSAWaitForMultipleEvents: %d\n", WSAGetLastError());
        if(WIN_EventTotal == 0) {
          return 0;
        }
        break;
      case WAIT_IO_COMPLETION:
      case WSA_WAIT_TIMEOUT:
        break;
      default:
        {
          DWORD socNum = dwEvent - WSA_WAIT_EVENT_0;

          //printf("We got some kind of network event on socket %d!\n", socNum);
          if(WSAEnumNetworkEvents(WIN_SocEventArray[socNum]->WIN_socket, WIN_EventArray[socNum], &NetworkEvents) == SOCKET_ERROR) {
            printf("WSAEnumNetworkEvents() failed with error %d\n", WSAGetLastError());
          }

          if(NetworkEvents.lNetworkEvents & FD_ACCEPT)
          {
            //printf("FD_ACCEPT\n");
          }

          if(NetworkEvents.lNetworkEvents & FD_READ)
          {
            //printf("FD_READ\n");
            SDL_LockMutex(s_SocketSharedMutex);
            struct sockaddr_in server;
            server.sin_family = AF_INET;
            server.sin_port = htons(WIN_SocEventArray[socNum]->remote_port);
            server.sin_addr.S_un.S_addr = WIN_SocEventArray[socNum]->remote_ip;
            int sz = sizeof(server);
            int numBytes = recvfrom(WIN_SocEventArray[socNum]->WIN_socket, WIN_SocEventArray[socNum]->rcvbuf.data + WIN_SocEventArray[socNum]->rcvbufp, WIN_SocEventArray[socNum]->rcvbuf.size - WIN_SocEventArray[socNum]->rcvbufp, 0, (struct sockaddr *)&server, &sz);
            if(numBytes > 0) {
              if(WIN_SocEventArray[socNum]->state == CPS_STT_DATAGRAM && (WIN_SocEventArray[socNum]->udpread_callback != NULL)) {
                WIN_SocEventArray[socNum]->udpread_callback(WIN_SocEventArray[socNum]->rcvbuf.data + WIN_SocEventArray[socNum]->rcvbufp, numBytes, WIN_SocEventArray[socNum]);
              }
              WIN_SocEventArray[socNum]->rcvbufp += numBytes;
            }
            SDL_UnlockMutex(s_SocketSharedMutex);
          }
        }


        break;
    }
  }
  #endif
  #ifdef SDK_BUILD_LINUX

  while(TRUE)
  {
    if(s_stopSocThread) {
      s_SocThreadReady = 0;
      return 0;
    }
    fd_set sockset;
    FD_ZERO(&sockset);
    int maxfd = 0;
    for(int i=0; i < MAX_NUM_OPEN_SOCKETS; i++) {
      if(WIN_SocketArray[i] != NULL) {
        FD_SET(WIN_SocketArray[i]->WIN_socket, &sockset);
        if(WIN_SocketArray[i]->WIN_socket > maxfd) {
          maxfd = WIN_SocketArray[i]->WIN_socket;
        }
      }
    }
    struct timeval myTimeout;
    myTimeout.tv_usec = 1000;
    myTimeout.tv_sec = 0;
    s_SocThreadReady = 1;
    int nready = select(maxfd+1, &sockset, NULL, NULL, &myTimeout);
    SDL_LockMutex(s_SocketSharedMutex);
    for(int i=0; i < MAX_NUM_OPEN_SOCKETS; i++) {
      if(WIN_SocketArray[i] != NULL && FD_ISSET(WIN_SocketArray[i]->WIN_socket, &sockset)) {
        printf("received event on socket %d\n", WIN_SocketArray[i]->WIN_socket);
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(WIN_SocketArray[i]->remote_port);
        server.sin_addr.s_addr = WIN_SocketArray[i]->remote_ip;
        int sz = sizeof(server);
        int recvSizeFree = WIN_SocketArray[i]->rcvbuf.size - WIN_SocketArray[i]->rcvbufp;
        if(recvSizeFree <= 0) {
          printf("network.c WARNING: no free space left in recvBuf\n");
        }
        //int numBytes = recvfrom(WIN_SocketArray[i]->WIN_socket, WIN_SocketArray[i]->rcvbuf.data + WIN_SocketArray[i]->rcvbufp, WIN_SocketArray[i]->rcvbuf.size - WIN_SocketArray[i]->rcvbufp, 0, (struct sockaddr *)&server,&sz);
        int numBytes = recv(WIN_SocketArray[i]->WIN_socket, WIN_SocketArray[i]->rcvbuf.data + WIN_SocketArray[i]->rcvbufp, WIN_SocketArray[i]->rcvbuf.size - WIN_SocketArray[i]->rcvbufp, 0);
        if(numBytes > 0) {
          if(WIN_SocketArray[i]->state == CPS_STT_DATAGRAM && (WIN_SocketArray[i]->udpread_callback != NULL)) {
            WIN_SocketArray[i]->udpread_callback(WIN_SocketArray[i]->rcvbuf.data + WIN_SocketArray[i]->rcvbufp, numBytes, WIN_SocketArray[i]);
          }
          WIN_SocketArray[i]->rcvbufp += numBytes;
        }
      }
    }
    SDL_UnlockMutex(s_SocketSharedMutex);

  }
  #endif
  s_SocThreadReady = 0;
  return 0;
}
#endif

/*---------------------------------------------------------------------------*
 *
 * Local Procedures
 * 
 *---------------------------------------------------------------------------*/

static char * analyze_format(char *param_1,char *param_2,undefined4 param_3,char *param_4)
{
  undefined4 uVar1;
  char *local_10;
  
  param_2[1] = '\0';
  param_2[2] = '\0';
  param_2[4] = '\0';
  param_2[5] = '\0';
  param_2[6] = '\0';
  param_2[7] = '\0';
  if (*param_1 == '-') {
    param_2[1] = '\x01';
    param_1 = param_1 + 1;
  }
  else if (*param_1 == '+') {
    param_2[2] = '+';
    param_1 = param_1 + 1;
  }
  else if (*param_1 == ' ') {
    param_2[2] = ' ';
    param_1 = param_1 + 1;
  }
  if (*param_1 == '0') {
    param_2[3] = '0';
  }
  else {
    param_2[3] = ' ';
  }
  local_10 = param_4;
  //uVar1 = strtol10(param_1,&local_10);
  *(undefined4 *)(param_2 + 4) = uVar1;
  if (0x1f < *(uint *)(param_2 + 4)) {
    param_2[4] = '\x1f';
    param_2[5] = '\0';
    param_2[6] = '\0';
    param_2[7] = '\0';
  }
  if ((*local_10 == 'l') || (*local_10 == 'L')) {
    local_10 = local_10 + 1;
  }
  *param_2 = *local_10;
  return local_10 + 1;
}

static int arprequest(undefined4 param_1)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  do {
    if (7 < uVar2) {
      return 0;
    }
    //send_arprequest(param_1);
    for (uVar3 = 0; uVar3 < 0x14; uVar3 = uVar3 + 1) {
      if (CPSMyIp == 0) {
        return 0;
      }
      OS_Sleep(100);
      //iVar1 = inq_arpcache(param_1);
      if (iVar1 != 0) {
        return iVar1;
      }
    }
    uVar2 = uVar2 + 1;
  } while( TRUE );
}

static char * byte2a(char *param_1,uint param_2)
{
  BOOL bVar1;
  char cVar2;
  uint extraout_r1;
  char *pcVar3;
  uint uVar4;
  
  bVar1 = FALSE;
  uVar4 = 100;
  while (uVar4 != 1) {
    if ((bVar1) || (pcVar3 = param_1, uVar4 <= param_2)) {
      pcVar3 = param_1 + 1;
      //cVar2 = _u32_div_f(param_2,uVar4);
      *param_1 = cVar2 + '0';
      //_u32_div_f(param_2,uVar4);
      bVar1 = TRUE;
      param_2 = extraout_r1;
    }
    //uVar4 = _s32_div_f(uVar4,10);
    param_1 = pcVar3;
  }
  *param_1 = (char)param_2 + '0';
  param_1[1] = '.';
  param_1[2] = '\0';
  return param_1 + 2;
}

static void calc_checksum(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  undefined2 uVar1;
  
  //uVar1 = calc_checksum_do(param_1,param_2,0,param_4,param_4);
  invert_checksum(uVar1);
  return;
}

static uint calc_checksum_do(ushort *param_1,uint param_2,uint param_3)
{
  int iVar1;
  uint uVar2;
  
  if (((uint)param_1 & 1) == 0) {
    iVar1 = CPS_htons(param_3 & 0xffff);
    for (; 1 < param_2; param_2 = param_2 - 2) {
      iVar1 = iVar1 + (uint)*param_1;
      param_1 = param_1 + 1;
    }
    param_3 = CPS_htonl(iVar1);
  }
  else {
    for (; 1 < param_2; param_2 = param_2 - 2) {
      //param_3 = param_3 + CONCAT11(*(byte *)param_1,*(byte *)((int)param_1 + 1));
      param_1 = param_1 + 1;
    }
  }
  if (param_2 != 0) {
    param_3 = param_3 + (uint)*(byte *)param_1 * 0x100;
  }
  uVar2 = (param_3 & 0xffff) + (param_3 >> 0x10);
  return uVar2 + (uVar2 >> 0x10) & 0xffff;
}

static byte * check_frag(byte *param_1,undefined4 *param_2)
{
  int iVar1;
  byte bVar2;
  undefined2 uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uchar *puVar8;
  unsigned long uVar9;
  byte *pbVar10;
  CPSFragTable *pCVar11;
  uint uVar12;
  unsigned short uVar13;
  uint uVar14;
  CPSFragTable *pCVar15;
  
  *param_2 = 0;
  uVar4 = CPS_htons(*(undefined2 *)(param_1 + 6));
  if ((uVar4 & 0x3fff) == 0) {
    return param_1;
  }
  bVar2 = *param_1;
  iVar1 = (bVar2 & 0xf) * 4;
  uVar13 = *(unsigned short *)(param_1 + 4);
  iVar5 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar6 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  uVar6 = iVar5 << 0x10 | uVar6;
  pCVar15 = (CPSFragTable *)0x0;
  uVar12 = 0;
  for (pCVar11 = fragtable;
      (uVar12 < 8 &&
      (((pCVar11->frags == 0 || (pCVar11->ipfrom != uVar6)) || (pCVar11->id != uVar13))));
      pCVar11 = pCVar11 + 1) {
    if ((pCVar11->frags == 0) && (pCVar15 == (CPSFragTable *)0x0)) {
      pCVar15 = pCVar11;
    }
    uVar12 = uVar12 + 1;
  }
  iVar5 = CPS_htons(*(undefined2 *)(param_1 + 2));
  iVar5 = iVar5 + (bVar2 & 0xf) * -4;
  uVar14 = uVar4 & 0x1fff;
  uVar7 = iVar5 + uVar14 * 8;
  if (uVar12 == 8) {
    if ((pCVar15 == (CPSFragTable *)0x0) || (0x1000 < uVar7)) {
      return (byte *)0x0;
    }
    puVar8 = (uchar *)(*CPSiAlloc)(iVar1 + 0x100e);
    pCVar15->buf = puVar8;
    if (pCVar15->buf == (uchar *)0x0) {
      OSi_TWarning("network.c",0x731,"Failed to allocate IP fragment buffer\n");
      return (byte *)0x0;
    }
    pCVar15->ipfrom = uVar6;
    pCVar15->id = uVar13;
    pCVar15->last = 0;
    uVar9 = CPSi_GetTick();
    pCVar15->when = uVar9;
    pCVar15->ofs0 = pCVar15->buf + iVar1 + 0xe;
    MI_CpuCopy8(param_1,pCVar15->buf + 0xe,iVar1);
    pCVar11 = pCVar15;
  }
  if ((pCVar11->frags == 8) || (0x1000 < uVar7)) {
    pCVar11->frags = 0;
    OSi_TWarning("network.c",0x743,"Freeing too big IP fragment\n");
    (*CPSiFree)(pCVar11->buf);
    pbVar10 = (byte *)0x0;
  }
  else {
    uVar13 = (unsigned_short)uVar14 + (short)(iVar5 + 7U >> 3);
    if ((uVar4 & 0x2000) == 0) {
      pCVar11->size = (unsigned_short)uVar7;
      pCVar11->last = uVar13;
    }
    pCVar11->from[pCVar11->frags] = (unsigned_short)uVar14;
    pCVar11->to[pCVar11->frags] = uVar13;
    pCVar11->frags = pCVar11->frags + 1;
    MI_CpuCopy8(param_1 + iVar1,pCVar11->ofs0 + uVar14 * 8,iVar5);
    if (pCVar11->last == 0) {
      pbVar10 = (byte *)0x0;
    }
    else {
      uVar13 = 0;
      uVar4 = 0;
      while (uVar4 < pCVar11->frags) {
        if ((uVar13 < pCVar11->from[uVar4]) || (pCVar11->to[uVar4] <= uVar13)) {
          uVar4 = uVar4 + 1;
        }
        else {
          uVar13 = pCVar11->to[uVar4];
          uVar4 = 0;
        }
      }
      if (uVar13 < pCVar11->last) {
        pbVar10 = (byte *)0x0;
      }
      else {
        puVar8 = pCVar11->buf;
        pbVar10 = puVar8 + 0xe;
        uVar3 = CPS_htons(pCVar11->size + (*pbVar10 & 0xf) * 4);
        *(undefined2 *)(puVar8 + 0x10) = uVar3;
        pCVar11->frags = 0;
        *param_2 = 1;
      }
    }
  }
  return pbVar10;
}

static int * check_listener(int param_1,undefined2 *param_2)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  
  //iVar1 = OS_GetThreadList();
  do {
    if (iVar1 == 0) {
      return (int *)0x0;
    }
    //piVar2 = (int *)OSi_GetSpecificData(iVar1,0);
    if ((((piVar2 != (int *)0x0) && (*piVar2 != 0)) && (*(char *)(piVar2 + 2) == '\x01')) &&
       ((uVar3 = CPS_htons(param_2[1]), *(ushort *)((int)piVar2 + 10) == uVar3 &&
        ((*(short *)(piVar2 + 6) == 0 ||
         (uVar3 = CPS_htons(*param_2), *(ushort *)(piVar2 + 6) == uVar3)))))) {
      if (piVar2[7] == 0) {
        return piVar2;
      }
      iVar4 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
      uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
      if (piVar2[7] == (iVar4 << 0x10 | uVar3)) {
        return piVar2;
      }
    }
    //iVar1 = OS_GetNextThread(iVar1);
  } while( TRUE );
}

static undefined4 check_socket(int param_1,undefined2 *param_2,int param_3)
{
  BOOL bVar1;
  BOOL bVar2;
  uint uVar3;
  int iVar4;
  BOOL bVar5;
  undefined4 uVar6;
  
  uVar6 = 0;
  bVar2 = FALSE;
  bVar1 = FALSE;
  bVar5 = FALSE;
  if ((*(char *)(param_3 + 8) != '\n') && (*(char *)(param_3 + 8) != '\v')) {
    bVar5 = TRUE;
  }
  if (bVar5) {
    uVar3 = CPS_htons(param_2[1]);
    if (*(ushort *)(param_3 + 10) == uVar3) {
      bVar1 = TRUE;
    }
  }
  if (bVar1) {
    uVar3 = CPS_htons(*param_2);
    if (*(ushort *)(param_3 + 0x18) == uVar3) {
      bVar2 = TRUE;
    }
  }
  if (bVar2) {
    iVar4 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
    uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
    if (*(uint *)(param_3 + 0x1c) == (iVar4 << 0x10 | uVar3)) {
      uVar6 = 1;
    }
  }
  return uVar6;
}

static BOOL check_tcpudpsum(undefined4 param_1,int param_2,int param_3,uint param_4)
{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  //uVar1 = calc_checksum_do(param_1,param_2,param_4 & 0xffff,param_4,param_4);
  //iVar2 = calc_checksum_do(param_3 + 0xc,8,uVar1);
  uVar3 = iVar2 + param_2;
  if ((uVar3 & 0x10000) != 0) {
    uVar3 = uVar3 + 1 & 0xffff;
  }
  return uVar3 != 0xffff;
}

static BOOL default_link_is_on(void)
{
  return 1;
}

static int dhcp_analyze_response(uint param_1,int param_2,undefined4 param_3,uint param_4)
{
  byte bVar1;
  int iVar2;
  char *pcVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  byte *pbVar7;
  int iVar8;
  unsigned_long uVar9;
  uint local_38;
  
  local_38 = param_4;
  iVar2 = CPSi_GetTick();
  iVar8 = 0;
  do {
    while( TRUE ) {
      //iVar5 = (*link_is_on)();
      //if (((iVar5 == 0) || (iVar8 != 0)) ||
      //   (iVar5 = CPSi_GetTick(),
      //   (iVar5 - iVar2) + (param_2 + 1) * -0xf < 0 == SBORROW4(iVar5 - iVar2,(param_2 + 1) * 0xf)))
      //{
      //  return iVar8;
      //}
      iVar5 = CPS_SocGetLength();
      if (iVar5 != 0) break;
      //OS_YieldThread__();
    }
    //pcVar3 = (char *)CPS_SocRead(&local_38);
    if ((0xf0 < local_38) && (*pcVar3 == '\x02')) {
      iVar5 = CPS_htons(*(undefined2 *)(pcVar3 + 4));
      uVar4 = CPS_htons(*(undefined2 *)(pcVar3 + 6));
      if ((param_1 == (iVar5 << 0x10 | uVar4)) &&
         (/*iVar5 = maccmp(pcVar3 + 0x1c,CPSMyMac),*/ iVar5 == 0)) {
        iVar8 = 3;
        //uVar9 = CONCAT22(CONCAT11(pcVar3[0x10],pcVar3[0x11]),CONCAT11(pcVar3[0x12],pcVar3[0x13]));
        if ((((pcVar3[0xec] == 'c') && (pcVar3[0xed] == -0x7e)) && (pcVar3[0xee] == 'S')) &&
           (pbVar7 = (byte *)(pcVar3 + 0xf0), pcVar3[0xef] == 'c')) {
          while (pbVar6 = pbVar7, pbVar6 < pcVar3 + local_38) {
            pbVar7 = pbVar6 + 1;
            bVar1 = *pbVar6;
            if (bVar1 == 0xff) break;
            if (bVar1 != 0) {
              if (bVar1 < 0x34) {
                if (bVar1 < 0x33) {
                  if ((bVar1 < 7) && (bVar1 != 0)) {
                    if (bVar1 == 1) {
                     //CPSNetMask = CONCAT22(CONCAT11(pbVar6[2],pbVar6[3]),
                     //                      CONCAT11(pbVar6[4],pbVar6[5]));
                    }
                    else if (bVar1 == 3) {
                     //CPSGatewayIp = CONCAT22(CONCAT11(pbVar6[2],pbVar6[3]),
                     //                        CONCAT11(pbVar6[4],pbVar6[5]));
                    }
                    else if (bVar1 == 6) {
                      if (*pbVar7 < 8) {
                        CPSDnsIp[1] = 0;
                      }
                      else {
                       //CPSDnsIp[1] = CONCAT22(CONCAT11(pbVar6[6],pbVar6[7]),
                       //                       CONCAT11(pbVar6[8],pbVar6[9]));
                      }
                      //CPSDnsIp[0] = CONCAT22(CONCAT11(pbVar6[2],pbVar6[3]),
                      //                       CONCAT11(pbVar6[4],pbVar6[5]));
                    }
                  }
                }
                else {
                  //lease_time = CONCAT22(CONCAT11(pbVar6[2],pbVar6[3]),CONCAT11(pbVar6[4],pbVar6[5]))
                  //;
                }
              }
              else if (bVar1 < 0x36) {
                if (bVar1 == 0x35) {
                  if (pbVar6[2] == 2) {
                    iVar8 = 1;
                    //offered_myip = uVar9;
                  }
                  else if (pbVar6[2] == 5) {
                    iVar8 = 2;
                    CPSMyIp = uVar9;
                  }
                }
              }
              else if (bVar1 == 0x36) {
                //CPSDhcpServerIp =
                //     CONCAT22(CONCAT11(pbVar6[2],pbVar6[3]),CONCAT11(pbVar6[4],pbVar6[5]));
              }
              pbVar7 = pbVar7 + *pbVar7 + 1;
            }
          }
        }
      }
    }
    CPS_SocConsume(local_38);
  } while( TRUE );
}

static BOOL dhcp_discover_server(void)
{
  undefined4 uVar1;
  int iVar2;
  int unaff_r5;
  
  CPS_SocUse();
  CPS_SocDatagramMode();
  CPS_SocBind(0x44,0x43,0xffffffff);
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    uVar1 = dhcp_send_discover();
    //unaff_r5 = dhcp_analyze_response(uVar1,iVar2);
    if (unaff_r5 == 1) break;
  }
  CPS_SocRelease();
  return unaff_r5 == 1;
}

static void dhcp_release_server(void)
{
  undefined *puVar1;
  int iVar2;
  undefined4 in_r3;
  
  CPS_SocUse();
  CPS_SocDatagramMode();
  CPS_SocBind(0x44,0x43,CPSDhcpServerIp);
  //puVar1 = (undefined *)dhcp_setcommon(scavenger_sndbuf + 0x2a,7,0);
  *puVar1 = 0xff;
  //iVar2 = pad_mem(0,300,puVar1 + 1,puVar1 + -0x10570,in_r3);
  //CPS_SocWrite(scavenger_sndbuf + 0x2a,iVar2 + -0x10571);
  CPS_SocRelease();
  return;
}

static undefined4 dhcp_request_server(uint *param_1,int param_2)
{
  undefined4 uVar1;
  int iVar2;
  int unaff_r6;
  
  CPS_SocUse();
  CPS_SocDatagramMode();
  if (param_2 == 1) {
    CPS_SocBind(0x44,0x43,CPSDhcpServerIp);
  }
  else {
    CPS_SocBind(0x44,0x43,0xffffffff);
  }
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    //uVar1 = dhcp_send_request(param_2);
    //unaff_r6 = dhcp_analyze_response(uVar1,iVar2);
    if (unaff_r6 != 0) break;
  }
  CPS_SocRelease();
  if (unaff_r6 == 2) {
    //*param_1 = lease_time >> 1;
    //sleep_save = lease_time * 3 >> 3;
    uVar1 = 1;
  }
  else {
    //sleep_save = sleep_save >> 1;
    //*param_1 = sleep_save;
    if (param_2 == 1) {
      //if (sleep_save < 0x3c) {
      //  *param_1 = 1;
      //  sleep_save = lease_time >> 3;
      //}
    }
    else if ((param_2 == 2) /*&& (sleep_save < 0x3c)*/) {
      *param_1 = 1;
    }
    uVar1 = 0;
  }
  return uVar1;
}

static undefined4 dhcp_send_discover(void)
{
  undefined *puVar1;
  int iVar2;
  undefined4 in_r3;
  undefined4 local_10;
  
  local_10 = in_r3;
  //puVar1 = (undefined *)dhcp_setcommon(scavenger_sndbuf + 0x2a,1,&local_10);
  //if (offered_myip != 0) {
  //  *puVar1 = 0x32;
  //  puVar1[1] = 4;
  //  puVar1[2] = (char)(offered_myip >> 0x18);
  //  puVar1[3] = (char)(offered_myip >> 0x10);
  //  puVar1[4] = (char)(offered_myip >> 8);
  //  puVar1[5] = (char)offered_myip;
  //  puVar1 = puVar1 + 6;
  //}
  *puVar1 = 0xff;
  //iVar2 = pad_mem(0,300,puVar1 + 1,puVar1 + -0x10570);
  //CPS_SocWrite(scavenger_sndbuf + 0x2a,iVar2 + -0x10571);
  return local_10;
}

static undefined4 dhcp_send_request(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  undefined *puVar1;
  int iVar2;
  undefined4 local_20;
  
  local_20 = param_4;
  //puVar1 = (undefined *)dhcp_setcommon(scavenger_sndbuf + 0x2a,3,&local_20);
  if (param_1 == 0) {
    *puVar1 = 0x32;
    puVar1[1] = 4;
    //puVar1[2] = (char)(offered_myip >> 0x18);
    //puVar1[3] = (char)(offered_myip >> 0x10);
    //puVar1[4] = (char)(offered_myip >> 8);
    //puVar1[5] = (char)offered_myip;
    puVar1[6] = 0x36;
    puVar1[7] = 4;
    puVar1[8] = (char)(CPSDhcpServerIp >> 0x18);
    puVar1[9] = (char)(CPSDhcpServerIp >> 0x10);
    puVar1[10] = (char)(CPSDhcpServerIp >> 8);
    puVar1[0xb] = (char)CPSDhcpServerIp;
    puVar1 = puVar1 + 0xc;
  }
  *puVar1 = 0xff;
  //iVar2 = pad_mem(0,300,puVar1 + 1,puVar1 + -0x10570);
  //CPS_SocWrite(scavenger_sndbuf + 0x2a,iVar2 + -0x10571);
  return local_20;
}

static int dhcp_setcommon(undefined2 *param_1,undefined param_2,uint *param_3)
{
  undefined2 uVar1;
  uint uVar2;
  
  MI_CpuClear8(param_1,0xec);
  uVar1 = CPS_htons(0x101);
  *param_1 = uVar1;
  *(undefined *)(param_1 + 1) = 6;
  uVar2 = MATH_Rand32(&CPSiRand32ctx,0);
  if (param_3 != (uint *)0x0) {
    *param_3 = uVar2;
  }
  uVar1 = CPS_htons(uVar2 >> 0x10);
  param_1[2] = uVar1;
  uVar1 = CPS_htons(uVar2 & 0xffff);
  param_1[3] = uVar1;
  uVar1 = CPS_htons(CPSMyIp >> 0x10);
  param_1[6] = uVar1;
  uVar1 = CPS_htons(CPSMyIp & 0xffff);
  param_1[7] = uVar1;
  MI_CpuCopy8(CPSMyMac,param_1 + 0xe,6);
  uVar1 = CPS_htons(0x6382);
  param_1[0x76] = uVar1;
  uVar1 = CPS_htons(0x5363);
  param_1[0x77] = uVar1;
  uVar1 = CPS_htons(0x3501);
  param_1[0x78] = uVar1;
  *(undefined *)(param_1 + 0x79) = param_2;
  *(undefined *)((int)param_1 + 0xf3) = 0x3d;
  *(undefined *)(param_1 + 0x7a) = 7;
  *(undefined *)((int)param_1 + 0xf5) = 1;
  MI_CpuCopy8(CPSMyMac,param_1 + 0x7b,6);
  *(undefined *)(param_1 + 0x7e) = 0xc;
  *(undefined *)((int)param_1 + 0xfd) = 10;
  MI_CpuCopy8("NintendoDS",param_1 + 0x7f,10);
  *(undefined *)(param_1 + 0x84) = 0x37;
  *(undefined *)((int)param_1 + 0x109) = 3;
  *(undefined *)(param_1 + 0x85) = 1;
  *(undefined *)((int)param_1 + 0x10b) = 3;
  *(undefined *)(param_1 + 0x86) = 6;
  return (int)param_1 + 0x10d;
}

static void dispatch_arp(ushort *param_1,uint param_2,undefined4 param_3,undefined4 param_4)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  BOOL bVar5;
  BOOL bVar6;
  
  //if (((((0x1b < param_2) &&
  //      (iVar1 = maccmp(param_1 + 4,CPSMyMac,param_3,param_4,param_4), iVar1 != 0)) &&
  //     (CPSMyIp != 0)) &&
  //    ((uVar2 = CPS_htons(1), *param_1 == uVar2 && (uVar2 = CPS_htons(0x800), param_1[1] == uVar2)))
  //    ) && ((uVar2 = CPS_htons(0x604), param_1[2] == uVar2 &&
  //          ((iVar1 = CPS_htons(param_1[3]), iVar1 == 1 || (iVar1 == 2)))))) {
  //  iVar3 = CPS_htons(param_1[7]);
  //  uVar2 = CPS_htons(param_1[8]);
  //  uVar2 = iVar3 << 0x10 | uVar2;
  //  bVar5 = uVar2 != CPSMyIp;
  //  iVar3 = CPS_htons(param_1[0xc]);
  //  uVar4 = CPS_htons(param_1[0xd]);
  //  bVar6 = CPSMyIp == (iVar3 << 0x10 | uVar4);
  //  if (bVar5) {
  //    reg_arpcache(param_1 + 4,uVar2,bVar6);
  //  }
  //  if ((iVar1 == 1) && (bVar6)) {
  //    reply_arp(param_1);
  //  }
  //  else if ((iVar1 == 2) && ((bVar6 && (!bVar5)))) {
  //    ip_conflict = '\x01';
  //  }
  //}
  return;
}

static void dispatch_icmp(int param_1,char *param_2,undefined4 param_3,undefined4 param_4)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  //iVar1 = calc_checksum(param_2,param_3,param_3,param_4,param_4);
  //if (iVar1 == 0xffff) {
  //  iVar1 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  //  uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  //  iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
  //  uVar4 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
  //  iVar1 = valid_IP(iVar1 << 0x10 | uVar2,iVar3 << 0x10 | uVar4);
  //  if (iVar1 != 0) {
  //    if (*param_2 == '\0') {
  //      process_icmp_reply(param_1,param_2,param_3);
  //    }
  //    else if (*param_2 == '\b') {
  //      reply_icmp(param_1,param_2,param_3);
  //    }
  //  }
  //}
  return;
}

static void dispatch_ip(byte *param_1,uint param_2,undefined4 param_3,int param_4)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  byte *pbVar6;
  byte *pbVar7;
  int local_28;
  
  local_28 = param_4;
  iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
  uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
  iVar4 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar5 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  if ((iVar2 << 0x10 | uVar3) != (iVar4 << 0x10 | uVar5)) {
    iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
    uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
    iVar2 = ip_isme(iVar2 << 0x10 | uVar3);
    if (iVar2 == 0) {
      return;
    }
    uVar3 = CPS_htons(*(undefined2 *)(param_1 + 2));
    if (param_2 < uVar3) {
      return;
    }
    //iVar2 = calc_checksum(param_1,(*param_1 & 0xf) << 2);
    if (iVar2 != 0xffff) {
      return;
    }
    iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
    uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
    if (CPSMyIp == (iVar2 << 0x10 | uVar3)) {
      iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
      uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
      //reg_arpcache(param_1 + -8,iVar2 << 0x10 | uVar3,1);
    }
  }
  pbVar6 = (byte *)check_frag(param_1,&local_28);
  if (pbVar6 != (byte *)0x0) {
    bVar1 = *pbVar6;
    pbVar7 = pbVar6 + (bVar1 & 0xf) * 4;
    iVar2 = CPS_htons(*(undefined2 *)(pbVar6 + 2));
    iVar2 = iVar2 + (bVar1 & 0xf) * -4;
    bVar1 = pbVar6[9];
    if (bVar1 == 0x11) {
      //dispatch_udp(pbVar6,pbVar7,iVar2);
    }
    else if (CPSMyIp != 0) {
      if (bVar1 == 1) {
        //dispatch_icmp(pbVar6,pbVar7,iVar2);
      }
      else if (bVar1 == 6) {
        //dispatch_tcp(pbVar6,pbVar7,iVar2);
      }
    }
    if (local_28 != 0) {
      OSi_TWarning("network.c",0x793,"Freeing IP fragment buffer\n");
      (*CPSiFree)(pbVar6 + -0xe);
    }
  }
  return;
}

static void dispatch_tcp(undefined4 param_1,int param_2,int param_3)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = check_tcpudpsum(param_2,param_3,param_1,6);
  if (iVar2 != 0) {
    return;
  }
  param_3 = param_3 - ((int)(*(byte *)(param_2 + 0xc) & 0xf0) >> 2);
  bVar1 = *(byte *)(param_2 + 0xd) & 0x17;
  if (bVar1 < 0x11) {
    if (0xf < bVar1) {
LAB_00014964:
      //dt_ack(param_1,param_2,param_3);
      return;
    }
    if ((bVar1 < 3) && ((*(byte *)(param_2 + 0xd) & 0x17) != 0)) {
      if (bVar1 == 1) {
        dt_fin(param_1,param_2,param_3);
        return;
      }
      if (bVar1 == 2) {
        if ((*(byte *)(param_2 + 0xd) & 0x28) != 0) {
          return;
        }
        dt_syn(param_1,param_2,param_3);
        return;
      }
    }
  }
  else if ((bVar1 < 0x13) && (0x10 < bVar1)) {
    if (bVar1 == 0x11) goto LAB_00014964;
    if (bVar1 == 0x12) {
      if ((*(byte *)(param_2 + 0xd) & 0x28) != 0) {
        return;
      }
      //dt_synack(param_1,param_2,param_3);
      return;
    }
  }
  if ((*(byte *)(param_2 + 0xd) & 4) == 0) {
    //tcp_send_rst(param_1,param_2,param_3,0);
  }
  else {
    dt_rst(param_1,param_2);
  }
  return;
}

static void dispatch_udp(int param_1,undefined2 *param_2,int param_3)
{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int *piVar5;
  int iVar6;
  
  uVar2 = CPS_htons(0);
//  if (((ushort)param_2[3] == uVar2) ||
//     (iVar3 = check_tcpudpsum(param_2,param_3,param_1,0x11), iVar3 == 0)) {
//    uVar4 = OS_DisableInterrupts();
//    for (iVar3 = OS_GetThreadList(); iVar3 != 0; iVar3 = OS_GetNextThread(iVar3)) {
//      piVar5 = (int *)OSi_GetSpecificData(iVar3,0);
//      if (((piVar5 != (int *)0x0) && (*piVar5 != 0)) && (*(char *)(piVar5 + 2) == '\n')) {
//        uVar2 = CPS_htons(param_2[1]);
//        if (*(ushort *)((int)piVar5 + 10) == uVar2) {
//          if (*(short *)(piVar5 + 6) != 0) {
//            uVar2 = CPS_htons(*param_2);
//            if (*(ushort *)(piVar5 + 6) != uVar2) goto LAB_00014bac;
//          }
//          if ((piVar5[7] != 0) && (piVar5[7] != -1)) {
//            iVar6 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
//            uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
//            if (piVar5[7] != (iVar6 << 0x10 | uVar2)) goto LAB_00014bac;
//          }
//          iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
//          uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
//          piVar5[5] = iVar3 << 0x10 | uVar2;
//          if (piVar5[7] == 0) {
//            iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
//            uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
//            piVar5[7] = iVar3 << 0x10 | uVar2;
//            uVar1 = CPS_htons(*param_2);
//            *(undefined2 *)(piVar5 + 6) = uVar1;
//          }
//          if (piVar5[0x11] == 0) {
//            if ((uint)piVar5[0xf] < param_3 - 8U) {
//              piVar5[0x11] = piVar5[0xf];
//            }
//            else {
//              piVar5[0x11] = param_3 - 8U;
//            }
//            MI_CpuCopy8(param_2 + 4,piVar5[0x10],piVar5[0x11]);
//            if (piVar5[1] == 3) {
//              piVar5[1] = 0;
//              OS_WakeupThreadDirect(*piVar5);
//            }
//            else if ((piVar5[0xe] != 0) &&
//                    (iVar3 = (*(code *)piVar5[0xe])(piVar5[0x10],piVar5[0x11],piVar5), iVar3 != 0))
//            {
//              piVar5[0x11] = 0;
//            }
//          }
//          break;
//        }
//      }
LAB_00014bac:
//    }
//    OS_RestoreInterrupts(uVar4);
//  }
  return;
}

static char * dns_skipname(char *aName)
{
  uint uVar1;
  
  while( TRUE ) {
    uVar1 = (uint)*aName;
    if (uVar1 == 0) {
      return aName + 1;
    }
    if ((uVar1 & 0xc0) == 0xc0) break;
    aName = aName + 1 + uVar1;
  }
  return aName + 2;
}

static void dt_ack(undefined4 param_1,int param_2,uint param_3,undefined4 param_4)
{
  BOOL bVar1;
  byte bVar2;
  undefined2 uVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  
  //puVar4 = (undefined4 *)find_socket(param_1,param_2,param_3,param_4,param_4);
  if (puVar4 == (undefined4 *)0x0) {
    //tcp_send_rst(param_1,param_2,param_3,0);
    return;
  }
  bVar2 = *(byte *)(param_2 + 0xd);
  iVar5 = CPS_htons(*(undefined2 *)(param_2 + 8));
  uVar6 = CPS_htons(*(undefined2 *)(param_2 + 10));
  uVar6 = iVar5 << 0x10 | uVar6;
  if (0 < (int)(uVar6 - puVar4[0xc])) {
    puVar4[0xc] = uVar6;
  }
  iVar5 = CPS_htons(*(undefined2 *)(param_2 + 4));
  uVar6 = CPS_htons(*(undefined2 *)(param_2 + 6));
  if ((*(char *)(puVar4 + 2) == '\x04') && (puVar4[9] != (iVar5 << 0x10 | uVar6))) {
    //tcp_send_ack(puVar4,0);
    return;
  }
  uVar3 = CPS_htons(*(undefined2 *)(param_2 + 0xe));
  *(undefined2 *)(puVar4 + 0xb) = uVar3;
  switch(*(undefined *)(puVar4 + 2)) {
  case 0:
    goto LAB_000144b8;
  case 1:
    break;
  case 2:
LAB_000144b8:
    //tcp_send_rst(param_1,param_2,param_3,0);
    goto LAB_00014704;
  case 3:
    *(undefined *)(puVar4 + 2) = 4;
    if (puVar4[1] == 1) {
      puVar4[1] = 0;
      //OS_WakeupThreadDirect(*puVar4);
    }
    if (param_3 == 0) goto LAB_00014704;
    goto LAB_000144fc;
  case 4:
LAB_000144fc:
    puVar4[0xd] = puVar4[0xd] + 1;
    bVar1 = (uint)(puVar4[0xf] - puVar4[0x11]) < param_3;
    if (bVar1) {
      param_3 = puVar4[0xf] - puVar4[0x11];
    }
    if (param_3 != 0) {
      uVar7 = OS_DisableInterrupts();
      //MI_CpuCopy8(param_2 + ((int)(*(byte *)(param_2 + 0xc) & 0xf0) >> 2),
      //            puVar4[0x10] + puVar4[0x11],param_3);
      puVar4[0x11] = puVar4[0x11] + param_3;
      puVar4[9] = puVar4[9] + param_3;
      OS_RestoreInterrupts(uVar7);
      if (puVar4[1] == 2) {
        puVar4[1] = 0;
        //OS_WakeupThreadDirect(*puVar4);
      }
    }
    if ((bVar1) || ((bVar2 & 1) == 0)) {
      if (param_3 != 0) {
        //tcp_send_ack(puVar4,0);
      }
    }
    else {
      *(undefined *)(puVar4 + 2) = 6;
      puVar4[9] = puVar4[9] + 1;
      //tcp_send_finack(puVar4,0);
      if ((param_3 == 0) && (puVar4[1] == 2)) {
        puVar4[1] = 0;
        //OS_WakeupThreadDirect(*puVar4);
      }
    }
    goto LAB_00014704;
  case 5:
    break;
  case 6:
    goto LAB_000146b4;
  case 7:
    goto LAB_00014630;
  case 8:
LAB_00014630:
    if ((bVar2 & 1) == 0) {
      if (param_3 != 0) {
        puVar4[9] = puVar4[9] + param_3;
        //tcp_send_ack(puVar4,0);
      }
      *(undefined *)(puVar4 + 2) = 8;
    }
    else {
      puVar4[9] = puVar4[9] + param_3 + 1;
      //tcp_send_ack(puVar4,0);
      *(undefined *)(puVar4 + 2) = 0;
      if (puVar4[1] == 2) {
        puVar4[1] = 0;
        //OS_WakeupThreadDirect(*puVar4);
      }
    }
    goto LAB_00014704;
  case 9:
LAB_000146b4:
    *(undefined *)(puVar4 + 2) = 0;
    if (puVar4[1] == 2) {
      puVar4[1] = 0;
      //OS_WakeupThreadDirect(*puVar4);
    }
    goto LAB_00014704;
  }
  if ((bVar2 & 1) != 0) {
    puVar4[9] = puVar4[9] + 1;
  }
  //tcp_send_ack(puVar4,0);
LAB_00014704:
  OS_YieldThread();
  return;
}

static void dt_fin(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
  char cVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)find_socket(param_1,param_2);
  if (puVar2 != (undefined4 *)0x0) {
    cVar1 = *(char *)(puVar2 + 2);
    if (cVar1 == '\x04') {
      puVar2[9] = puVar2[9] + 1;
      //tcp_send_finack(puVar2,0);
      *(undefined *)(puVar2 + 2) = 6;
    }
    else if (cVar1 == '\a') {
      puVar2[9] = puVar2[9] + 1;
      //tcp_send_ack(puVar2,0);
      *(undefined *)(puVar2 + 2) = 9;
    }
    else if (cVar1 == '\b') {
      puVar2[9] = puVar2[9] + 1;
      //tcp_send_ack(puVar2,0);
      *(undefined *)(puVar2 + 2) = 0;
      if (puVar2[1] == 2) {
        puVar2[1] = 0;
        //OS_WakeupThreadDirect(*puVar2);
      }
    }
    else {
      //tcp_send_rst(param_1,param_2,param_3,0);
    }
  }
  return;
}

static void dt_rst(undefined4 param_1,undefined4 param_2)
{
  undefined4 *puVar1;
  
  //puVar1 = (undefined4 *)find_socket(param_1,param_2);
  if (puVar1 != (undefined4 *)0x0) {
    OS_YieldThread();
    *(undefined *)(puVar1 + 2) = 0;
    if ((puVar1[1] == 1) || (puVar1[1] == 2)) {
      puVar1[1] = 0;
      //OS_WakeupThreadDirect(*puVar1);
    }
  }
  return;
}

static void dt_syn(int param_1,undefined4 param_2,undefined4 param_3)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  iVar1 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
  uVar4 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
  iVar1 = valid_IP(iVar1 << 0x10 | uVar2,iVar3 << 0x10 | uVar4);
  if ((iVar1 != 0) && (iVar1 = find_specific_socket(param_1,param_2,param_3), iVar1 == 0)) {
    //iVar1 = check_listener(param_1,param_2);
    if (iVar1 == 0) {
      OS_YieldThread();
      //iVar1 = check_listener(param_1,param_2);
      if (iVar1 != 0) {
        //dt_syn_LISTEN(param_1,param_2,iVar1);
      }
    }
    else {
      //dt_syn_LISTEN(param_1,param_2,iVar1);
    }
  }
  return;
}

static void dt_synack(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)
{
  undefined2 uVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  
  //puVar2 = (undefined4 *)find_socket(param_1,param_2,param_3,param_4,param_4);
  if ((puVar2 == (undefined4 *)0x0) || (*(char *)(puVar2 + 2) != '\x02')) {
    //tcp_send_rst(param_1,param_2,param_3,0);
  }
  else {
    OS_YieldThread();
    iVar3 = CPS_htons(*(undefined2 *)(param_2 + 4));
    uVar4 = CPS_htons(*(undefined2 *)(param_2 + 6));
    puVar2[9] = (iVar3 << 0x10 | uVar4) + 1;
    iVar3 = CPS_htons(*(undefined2 *)(param_2 + 8));
    uVar4 = CPS_htons(*(undefined2 *)(param_2 + 10));
    puVar2[0xc] = iVar3 << 0x10 | uVar4;
    uVar1 = CPS_htons(*(undefined2 *)(param_2 + 0xe));
    *(undefined2 *)(puVar2 + 0xb) = uVar1;
    //parse_mss(param_2,puVar2);
    //tcp_send_ack(puVar2,0);
    *(undefined *)(puVar2 + 2) = 4;
    if (puVar2[1] == 1) {
      puVar2[1] = 0;
      //OS_WakeupThreadDirect(*puVar2);
    }
  }
  return;
}

static void dt_syn_LISTEN(int param_1,undefined2 *param_2,int param_3)
{
  undefined2 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  
  *(undefined *)(param_3 + 8) = 3;
  uVar2 = CPSi_GetTick();
  *(undefined4 *)(param_3 + 0x10) = uVar2;
  iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0x10));
  uVar4 = CPS_htons(*(undefined2 *)(param_1 + 0x12));
  *(uint *)(param_3 + 0x14) = iVar3 << 0x10 | uVar4;
  uVar1 = CPS_htons(*param_2);
  *(undefined2 *)(param_3 + 0x18) = uVar1;
  iVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar4 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  *(uint *)(param_3 + 0x1c) = iVar3 << 0x10 | uVar4;
  iVar3 = CPS_htons(param_2[2]);
  uVar4 = CPS_htons(param_2[3]);
  *(uint *)(param_3 + 0x24) = (iVar3 << 0x10 | uVar4) + 1;
  //parse_mss(param_2,param_3);
  //tcp_send_handshake(param_3,0x12,0);
  return;
}

static void empty_func(void)
{
  return;
}

static int * find_socket(undefined4 param_1,undefined4 param_2)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  //iVar1 = OS_GetThreadList();
  while( TRUE ) {
    if (iVar1 == 0) {
      return (int *)0x0;
    }
    //piVar2 = (int *)OSi_GetSpecificData(iVar1,0);
    //if (((piVar2 != (int *)0x0) && (*piVar2 != 0)) &&
    //   (iVar3 = check_socket(param_1,param_2,piVar2), iVar3 != 0)) break;
    //iVar1 = OS_GetNextThread(iVar1);
  }
  return piVar2;
}

static undefined4 find_specific_socket(undefined4 param_1,undefined4 param_2,undefined4 param_3)
{
  int iVar1;
  undefined4 uVar2;
  
  //iVar1 = find_socket(param_1,param_2);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    if (*(char *)(iVar1 + 8) == '\x01') {
      //dt_syn_LISTEN(param_1,param_2,iVar1);
    }
    else if ((*(char *)(iVar1 + 8) == '\x03') || (*(char *)(iVar1 + 8) == '\x04')) {
      *(int *)(iVar1 + 0x28) = *(int *)(iVar1 + 0x28) + -1;
      //dt_syn_LISTEN(param_1,param_2,iVar1);
    }
    else {
      //tcp_send_rst(param_1,param_2,param_3,0);
    }
    uVar2 = 1;
  }
  return uVar2;
}

static void get_seqno(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  //MATH_Rand32(&CPSiRand32ctx,0,param_3,param_4,param_4);
  return;
}

static unsigned long get_targetip(unsigned long param_1)
{
  int iVar1;
  unsigned long uVar2;
  
  iVar1 = ip_islocal(param_1);
  uVar2 = CPSGatewayIp;
  if (iVar1 != 0) {
    uVar2 = param_1;
  }
  return uVar2;
}

static void handle_arg(undefined *param_1,byte *param_2,int *param_3,undefined4 param_4)
{
  byte bVar1;
  
  bVar1 = *param_2;
  if (bVar1 < 0x65) {
    if (bVar1 < 99) {
      if (bVar1 == 0x58) {
        //return_integer(param_1,param_2,param_3,0,0x10,param_4);
      }
    }
    else if (bVar1 == 99) {
      *param_3 = *param_3 + 4;
      *param_1 = (char)*(undefined4 *)(*param_3 + -4);
      param_1[1] = 0;
    }
    else if (bVar1 == 100) {
      //return_integer(param_1,param_2,param_3,1,10,param_4);
    }
  }
  else if (bVar1 < 0x76) {
    if (bVar1 == 0x75) {
      //return_integer(param_1,param_2,param_3,0,10,param_4);
    }
  }
  else if (bVar1 == 0x78) {
    //return_integer(param_1,param_2,param_3,0,0x10,param_4);
    #ifdef SDK_BUILD_WIN64
    strlwr(param_1);
    #endif
  }
  return;
}

static uchar * inq_arpcache(unsigned_long param_1)
{
  unsigned_short uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uchar *puVar5;
  
  uVar2 = OS_DisableInterrupts();
  puVar5 = (uchar *)0x0;
  if ((param_1 == 0x7f000001) || (param_1 == CPSMyIp)) {
    puVar5 = CPSMyMac;
  }
  else {
    iVar3 = is_broadcast(param_1);
    if ((iVar3 == 0) && (iVar3 = is_multicast(param_1), iVar3 == 0)) {
      for (uVar4 = 0; uVar4 < 8; uVar4 = uVar4 + 1) {
        if (param_1 == arpcache[uVar4].ip) {
          uVar1 = CPSi_GetTick();
          arpcache[uVar4].when = uVar1;
          puVar5 = (uchar *)(uVar4 * 0xc + 0x10084);
          break;
        }
      }
    }
    else {
      //puVar5 = mac_broadcast;
    }
  }
  OS_RestoreInterrupts(uVar2);
  return puVar5;
}

static ushort invert_checksum(ushort param_1)
{
  param_1 = param_1 ^ 0xffff;
  if (param_1 == 0) {
    param_1 = 0xffff;
  }
  return param_1;
}

static undefined4 ip_islocal(uint param_1)
{
  BOOL bVar1;
  undefined4 uVar2;
  
  uVar2 = 1;
  bVar1 = TRUE;
  if ((param_1 != 0xffffffff) && (param_1 != 0x7f000001)) {
    bVar1 = FALSE;
  }
  if ((!bVar1) && ((param_1 & CPSNetMask) != (CPSMyIp & CPSNetMask))) {
    uVar2 = 0;
  }
  return uVar2;
}

static undefined4 ip_isme(unsigned_long param_1)
{
  BOOL bVar1;
  int iVar2;
  BOOL bVar3;
  BOOL bVar4;
  undefined4 uVar5;
  
  uVar5 = 1;
  bVar1 = TRUE;
  bVar3 = TRUE;
  bVar4 = TRUE;
  if ((CPSMyIp != 0) && (param_1 != CPSMyIp)) {
    bVar4 = FALSE;
  }
  if ((!bVar4) && (param_1 != 0x7f000001)) {
    bVar3 = FALSE;
  }
  if ((!bVar3) && (iVar2 = is_broadcast(param_1), iVar2 == 0)) {
    bVar1 = FALSE;
  }
  if ((!bVar1) && (iVar2 = is_multicast(param_1), iVar2 == 0)) {
    uVar5 = 0;
  }
  return uVar5;
}

static undefined4 is_broadcast(uint param_1)
{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  iVar1 = ip_islocal(param_1);
  if ((iVar1 != 0) && (~CPSNetMask == (param_1 & ~CPSNetMask))) {
    uVar2 = 1;
  }
  return uVar2;
}

static BOOL is_multicast(uint param_1)
{
  return (param_1 & 0xf0000000) == 0xe0000000;
}

static void justify_string(char *param_1,char *param_2,int param_3,int param_4,int param_5)
{
  char cVar1;
  size_t sVar2;
  char *pcVar3;
  int iVar4;
  
  sVar2 = strlen(param_2);
  iVar4 = (*(int *)(param_3 + 4) - sVar2) - (uint)(param_5 != 0);
  cVar1 = (char)param_5;
  if (*(char *)(param_3 + 1) == '\0') {
    if ((param_5 == 0) || (param_4 != 0x20)) {
      pcVar3 = param_1;
      if (param_5 != 0) {
        pcVar3 = param_1 + 1;
        *param_1 = cVar1;
      }
      while (0 < iVar4) {
        *pcVar3 = (char)param_4;
        pcVar3 = pcVar3 + 1;
        iVar4 = iVar4 + -1;
      }
      strcpy(pcVar3,param_2);
    }
    else {
      while (0 < iVar4) {
        *param_1 = ' ';
        param_1 = param_1 + 1;
        iVar4 = iVar4 + -1;
      }
      *param_1 = cVar1;
      strcpy(param_1 + 1,param_2);
    }
  }
  else {
    pcVar3 = param_1;
    if (param_5 != 0) {
      pcVar3 = param_1 + 1;
      *param_1 = cVar1;
    }
    strcpy(pcVar3,param_2);
    pcVar3 = pcVar3 + sVar2;
    while (0 < iVar4) {
      *pcVar3 = ' ';
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + -1;
    }
    *pcVar3 = '\0';
  }
  return;
}

static undefined4 maccmp(short *param_1,short *param_2)
{
  int iVar1;
  
  iVar1 = 0;
  while( TRUE ) {
    if (2 < iVar1) {
      return 0;
    }
    if (*param_1 != *param_2) break;
    iVar1 = iVar1 + 1;
    param_2 = param_2 + 1;
    param_1 = param_1 + 1;
  }
  return 1;
}

static undefined4 no_need_inq(undefined4 param_1)
{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = get_targetip(param_1);
  if (iVar1 == 0) {
    uVar2 = 1;
  }
  else {
    //uVar2 = inq_arpcache(iVar1);
  }
  return uVar2;
}

static int pad_mem(undefined param_1,uint param_2,int param_3,uint param_4)
{
  if (param_4 < param_2) {
    //MI_CpuFill8(param_3,param_1,param_2 - param_4);
    //param_3 = param_3 + (param_2 - param_4);
  }
  return param_3;
}

static void parse_mss(int param_1,int param_2)
{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  byte *pbVar5;
  
  *(undefined2 *)(param_2 + 0x2e) = 0x218;
  iVar2 = ((int)(*(byte *)(param_1 + 0xc) & 0xf0) >> 2) + -0x14;
  pbVar4 = (byte *)(param_1 + 0x14);
  while( TRUE ) {
    pbVar5 = pbVar4;
    iVar3 = iVar2;
    if (iVar3 == 0) {
      return;
    }
    pbVar4 = pbVar5 + 1;
    bVar1 = *pbVar5;
    if (bVar1 == 0) break;
    iVar2 = iVar3 + -1;
    if (bVar1 != 1) {
      if (bVar1 == 2) {
        //*(ushort *)(param_2 + 0x2e) = CONCAT11(pbVar5[2],pbVar5[3]);
        iVar2 = iVar3 + -4;
        pbVar4 = pbVar5 + 4;
      }
      else {
        iVar2 = (iVar3 + -1) - (*pbVar4 - 1);
        pbVar4 = pbVar4 + (*pbVar4 - 1);
      }
    }
  }
  return;
}

static void process_icmp_reply(int param_1,int param_2,int param_3)
{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  uint uVar5;
  
  uVar1 = OS_DisableInterrupts();
  //iVar2 = OS_GetThreadList();
  do {
    if (iVar2 == 0) {
LAB_00013ab0:
      OS_RestoreInterrupts(uVar1);
      return;
    }
    //puVar3 = (uint *)OSi_GetSpecificData(iVar2,0);
    if ((((puVar3 != (uint *)0x0) && (*puVar3 != 0)) && (*(char *)(puVar3 + 2) == '\v')) &&
       ((((*puVar3 & 0xffff) == (uint)*(ushort *)(param_2 + 4) &&
         (*(short *)((int)puVar3 + 10) == *(short *)(param_2 + 6))) && (puVar3[0x11] == 0)))) {
      iVar4 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
      uVar5 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
      if (puVar3[7] == (iVar4 << 0x10 | uVar5)) {
        if (puVar3[0xf] < param_3 - 8U) {
          puVar3[0x11] = puVar3[0xf];
        }
        else {
          puVar3[0x11] = param_3 - 8U;
        }
        //MI_CpuCopy8(param_2 + 8,puVar3[0x10],puVar3[0x11]);
        if (puVar3[1] == 3) {
          puVar3[1] = 0;
          //OS_WakeupThreadDirect(*puVar3);
        }
        goto LAB_00013ab0;
      }
    }
    //iVar2 = OS_GetNextThread(iVar2);
  } while( TRUE );
}

static void put_in_buffer(undefined4 param_1,undefined4 param_2,char *param_3,int param_4,int param_5,
                  int param_6)
{
  uint uVar1;
  uchar *puVar2;
  uint uVar3;
  uint uVar4;
  
  //uVar3 = wlan_putpnt;
  //if ((((((wlan_buf != (uchar *)0x0) && (wlan_buflen != 0)) &&
  //      (uVar4 = param_4 + param_6, 7 < uVar4)) && ((uVar4 < 0x5e5 && (*param_3 == _15351[0])))) &&
  //    ((param_3[1] == _15351[1] && ((param_3[2] == _15351[2] && (param_3[6] == '\b')))))) &&
  //   ((param_3[7] == '\0' || (param_3[7] == '\x06')))) {
  //  uVar1 = uVar4 + 9 & 0xfffe;
  //  uVar3 = wlan_putpnt + uVar1;
  //  if ((wlan_putpnt < wlan_getpnt) && (wlan_getpnt <= uVar3)) {
  //    OSi_TWarning(_15259,0x269,_15366);
  //    uVar3 = wlan_putpnt;
  //  }
  //  else {
  //    if (uVar3 == wlan_buflen) {
  //      uVar3 = 0;
  //      if (wlan_getpnt == 0) {
  //        OSi_TWarning(_15259,0x271,_15366);
  //        return;
  //      }
  //    }
  //    else if ((wlan_buflen < uVar3) && (uVar3 = uVar1, wlan_getpnt <= uVar1)) {
  //      OSi_TWarning(_15259,0x279,_15366);
  //      return;
  //    }
  //    if (wlan_buflen < wlan_putpnt + uVar1) {
  //      if (1 < wlan_buflen - wlan_putpnt) {
  //        puVar2 = wlan_buf + wlan_putpnt;
  //        puVar2[0] = '\0';
  //        puVar2[1] = '\0';
  //      }
  //      wlan_putpnt = 0;
  //    }
  //    *(ushort *)(wlan_buf + wlan_putpnt) = (ushort)(uVar4 + 9) & 0xfffe;
  //    MI_CpuCopy8(param_2,wlan_buf + wlan_putpnt + 2,6);
  //    MI_CpuCopy8(param_1,wlan_buf + wlan_putpnt + 8,6);
  //    MI_CpuCopy8(param_3 + 6,wlan_buf + wlan_putpnt + 0xe,param_4 + -6);
  //    if ((param_5 != 0) && (param_6 != 0)) {
  //      MI_CpuCopy8(param_5,wlan_buf + param_4 + wlan_putpnt + 8,param_6);
  //    }
  //  }
  //}
  //wlan_putpnt = uVar3;
  return;
}

static undefined4 rawip(char *param_1,uint *param_2)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  char *local_20;
  undefined4 uStack_1c;
  
  uVar2 = 0;
  iVar3 = 0;
  //uStack_1c = param_4;
  while( TRUE ) {
    if (3 < iVar3) {
      *param_2 = uVar2;
      return 1;
    }
    uVar1 = strtol10(param_1,&local_20);
    if (param_1 == local_20) break;
    if (((0xff < uVar1) ||
        ((param_1 = local_20, iVar3 != 3 && (param_1 = local_20 + 1, *local_20 != '.')))) ||
       ((iVar3 == 3 && (*param_1 != '\0')))) {
      return 0;
    }
    uVar2 = uVar2 << 8 | uVar1;
    iVar3 = iVar3 + 1;
  }
  return 0;
}

static uchar * receive_packet(int *param_1)
{
  undefined4 uVar1;
  
  uVar1 = OS_DisableInterrupts();
  //while (wlan_getpnt == wlan_putpnt) {
  //  receiver_thread = (_OSThread *)OS_GetCurrentThread();
  //  OS_SleepThread(0);
  //  receiver_thread = (_OSThread *)0x0;
  //}
  //OS_RestoreInterrupts(uVar1);
  //while( TRUE ) {
  //  if (wlan_buflen - wlan_getpnt < 2) {
  //    wlan_getpnt = 0;
  //  }
  //  if (*(ushort *)(wlan_buf + wlan_getpnt) != 0) break;
  //  wlan_getpnt = 0;
  //}
  //*param_1 = *(ushort *)(wlan_buf + wlan_getpnt) - 2;
  //return wlan_buf + wlan_getpnt + 2;
  return NULL;
}

static void reg_arpcache(undefined4 param_1,unsigned long param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  if ((((param_2 != 0x7f000001) && (param_2 != CPSMyIp)) &&
      (iVar1 = ip_islocal(param_2), iVar1 != 0)) && (iVar1 = is_multicast(param_2), iVar1 == 0)) {
    uVar2 = CPSi_GetTick();
    for (uVar3 = 0; uVar3 < 8; uVar3 = uVar3 + 1) {
      if (param_2 == arpcache[uVar3].ip) {
        arpcache[uVar3].when = (unsigned short)uVar2;
        //MI_CpuCopy8(param_1,uVar3 * 0xc + 0x10084,6);
        return;
      }
    }
    if (param_3 != 0) {
      uVar3 = 0;
      uVar5 = 0;
      for (uVar4 = 0; (uVar6 = uVar5, uVar4 < 8 && (uVar6 = uVar4, arpcache[uVar4].ip != 0));
          uVar4 = uVar4 + 1) {
        if ((int)uVar3 < (int)(((uVar2 & 0xffff) - (uint)arpcache[uVar4].when) * 0x10000) >> 0x10) {
          uVar3 = (uVar2 & 0xffff) - (uint)arpcache[uVar4].when & 0xffff;
          uVar5 = uVar4;
        }
      }
      arpcache[uVar6].ip = param_2;
      //MI_CpuCopy8(param_1,uVar6 * 0xc + 0x10084,6);
      arpcache[uVar6].when = (unsigned short)uVar2;
    }
  }
  return;
}

static void reply_arp(int param_1)
{
  undefined2 uVar1;
  
  uVar1 = CPS_htons(2);
  //*(undefined2 *)(param_1 + 6) = uVar1;
  //MI_CpuCopy8(param_1 + 8,param_1 + 0x12,10);
  //MI_CpuCopy8(CPSMyMac,param_1 + 8,6);
  //uVar1 = CPS_htons(CPSMyIp >> 0x10);
  //*(undefined2 *)(param_1 + 0xe) = uVar1;
  //uVar1 = CPS_htons(CPSMyIp & 0xffff);
  //*(undefined2 *)(param_1 + 0x10) = uVar1;
  //MI_CpuCopy8(param_1 + 0x12,param_1 + -0xe,6);
  //MI_CpuCopy8(CPSMyMac,param_1 + -8,6);
  send_packet(param_1 + -0xe,0x2a,0,0);
  return;
}

static void reply_icmp(int param_1,undefined *param_2,undefined4 param_3)
{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  iVar2 = get_targetip(iVar2 << 0x10 | uVar3);
  if (iVar2 != 0) {
    //iVar4 = inq_arpcache(iVar2);
    if (iVar4 == 0) {
      //send_arprequest(iVar2);
    }
    else {
      *param_2 = 0;
      uVar1 = CPS_htons(0);
      *(undefined2 *)(param_2 + 2) = uVar1;
      //calc_checksum(param_2,param_3);
      //uVar1 = CPS_htons();
      *(undefined2 *)(param_2 + 2) = uVar1;
      iVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
      uVar3 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
      //send_ip(param_2,param_3,0,0,iVar2 << 0x10 | uVar3,1);
    }
  }
  return;
}

static void reset_network_vars(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  int iVar1;
  int *piVar2;
  
  //if (CPSMyIp != 0) {
  //  MI_CpuClear8(arpcache,0x60);
  //  for (iVar1 = OS_GetThreadList(); iVar1 != 0; iVar1 = OS_GetNextThread(iVar1)) {
  //    piVar2 = (int *)OSi_GetSpecificData(iVar1,0);
  //    if ((piVar2 != (int *)0x0) && (*piVar2 != 0)) {
  //      if ((*(char *)(piVar2 + 2) != '\n') && (*(char *)(piVar2 + 2) != '\v')) {
  //        *(undefined *)(piVar2 + 2) = 0;
  //      }
  //      if (piVar2[1] != 0) {
  //        piVar2[1] = 0;
  //        OS_WakeupThreadDirect(*piVar2);
  //      }
  //    }
  //  }
  //  for (iVar1 = 0; iVar1 < 8; iVar1 = iVar1 + 1) {
  //    if (fragtable[iVar1].frags != 0) {
  //      (*CPSiFree)(fragtable[iVar1].buf);
  //      fragtable[iVar1].frags = 0;
  //    }
  //  }
  //  CPSi_SslCleanup();
  //}
  return;
}

static int resolve_common(char *aName, uint param_2, ushort aIdent, undefined4 param_4, uint param_5)
{
  char cVar1;
  char *pcVar2;
  int curTick;
  //undefined2 *puVar4;
  u8 * responseBuf;
  uint uVar5;
  undefined *puVar6;
  //int iVar7;
  int status;

  undefined2 *puVar8;
  char * hostnamePtr;
  undefined2 * puVar10;
  char *pcVar11;
  int ret;
  uint local_74;
  char local_64;
  char hostname [47]; /* local_63 */
  undefined4 local_34;
  char *local_10;

  DnsQuery_t myQuery;
  DnsQuery_t* responseQuery;
  char * hostnameResponsePtr;
  
  local_34 = param_4;
  //local_70 = CPS_htons(aIdent);
  myQuery.identification = CPS_htons(aIdent);
  if (param_2 == 0x20) {
    //local_6e = CPS_htons(0x110);
    myQuery.flags = CPS_htons(0x110);
  }
  else {
    //local_6e = CPS_htons(0x100);
    myQuery.flags = CPS_htons(0x100);
  }
  //local_6c = CPS_htons(1);
  myQuery.numQuestions = CPS_htons(1);
  //local_6a = CPS_htons(0);
  myQuery.numAnswerRRs = CPS_htons(0);
  //local_68 = CPS_htons(0);
  myQuery.numAuthorityRRs = CPS_htons(0);
  //local_66 = CPS_htons(0);
  myQuery.numAdditionalRRs = CPS_htons(0);
  local_74 = 0;
  //pcVar2 = hostname;
  pcVar2 = &myQuery.hostname[1];
  //pcVar11 = &local_64;
  pcVar11 = myQuery.hostname;
  local_10 = aName;
  while( TRUE ) {
    hostnamePtr = pcVar2;
    cVar1 = *local_10;
    if (cVar1 == '\0') break;
    if (cVar1 == '.') {
      *pcVar11 = (char)local_74;
      local_74 = 0;
      pcVar2 = hostnamePtr + 1;
      pcVar11 = hostnamePtr;
      local_10 = local_10 + 1;
    } else {
      if (0x3b < (u64)hostnamePtr - /*(int)&local_70*/(u64)&myQuery) {
        return -1;
      }
      *hostnamePtr = cVar1;
      local_74 = local_74 + 1;
      pcVar2 = hostnamePtr + 1;
      local_10 = local_10 + 1;
    }
  }
  *pcVar11 = (char)local_74;
  *hostnamePtr = '\0';
  hostnamePtr[1] = (char)(param_2 >> 8);
  hostnamePtr[2] = (char)param_2;
  hostnamePtr[3] = '\0';
  hostnamePtr[4] = '\x01';
  //CPS_SocWrite((void*)&local_70,(u32)(pcVar9 + (5 - (int)&local_70)));
  CPS_SocWrite((void*)&myQuery, (u32)(hostnamePtr + (5 - (u64)&myQuery)));
  ret = 0;
  curTick = CPSi_GetTick();
  do {
    while( TRUE ) {
      //iVar7 = (*link_is_on)();
      status = link_is_on();
      if (((status == 0) || (ret != 0)) || (status = CPSi_GetTick(), 0xe < status - curTick)) {
        return ret;
      }
      status = CPS_SocGetLength();
      if (status != 0) break;
      //OS_YieldThread__();
    }
    //responseBuf = (undefined2 *)CPS_SocRead(&local_74);
    responseBuf = CPS_SocRead((u32*)&local_74);

    responseQuery = (DnsQuery_t *)responseBuf;

    //if ((0xc < local_74) && (uVar5 = CPS_htons(*responseBuf), aIdent == uVar5)) {
    uVar5 = CPS_htons(responseQuery->identification);


    if ((0xc < local_74) && (aIdent == uVar5)) {
      //if ((*(byte *)((u64)responseBuf + 3) & 0xf) == 3) {
      if (((responseQuery->flags >> 8) & 0xf) == 3) {
        ret = -1;
      //} else if ((*(byte *)((u64)responseBuf + 3) & 0xf) == 0) {
      } else if (((responseQuery->flags >> 8) & 0xf) == 0) {
        puVar10 = (undefined2 *)((u64)responseBuf + local_74);
        //puVar8 = (undefined2 *)(responseBuf + 6);
        hostnameResponsePtr = responseQuery->hostname;
        //uVar5 = (uint)CONCAT11(*(undefined *)((u16*)responseBuf + 2),*(undefined *)((u64)responseBuf + 5));
        //uVar5 = (uint)CONCAT11((u8)responseQuery->numQuestions, (u8)responseQuery->numAnswerRRs);
        //uVar5 = CPS_htons(responseQuery->numQuestions);
        uVar5 = CPS_htons(responseQuery->numAnswerRRs);
        while (uVar5 != 0) {
          void * ptr;
          //ptr = dns_skipname((u8*)puVar8);
          ptr = dns_skipname(hostnameResponsePtr);
          //puVar8 = (undefined2 *)(ptr + 4);
          hostnameResponsePtr = ptr + 4;
          uVar5 = uVar5 - 1;
        }

        //while (puVar8 < puVar10) {
        while (hostnameResponsePtr < puVar10) {
          //puVar6 = (undefined *)dns_skipname((u8*)puVar8);
          puVar6 = (undefined *)dns_skipname((u8*)hostnameResponsePtr);
          uVar5 = (uint)CONCAT11(puVar6[8],puVar6[9]);
          if (param_2 == CONCAT11(*puVar6,puVar6[1])) {
            if (param_2 == 0xc) {
              if (param_5 < uVar5) {
                ret = 2;
              } else {
                //MI_CpuCopy8(puVar6 + 10,param_4,uVar5);
                ret = 1;
              }
            } else {
          //    iVar12 = CONCAT22(CONCAT11(puVar6[uVar5 + 6],puVar6[uVar5 + 7]),
          //                      CONCAT11(puVar6[uVar5 + 8],puVar6[uVar5 + 9]));

            ret = CONCAT22(CONCAT11(puVar6[uVar5 + 6],puVar6[uVar5 + 7]),
                           CONCAT11(puVar6[uVar5 + 8],puVar6[uVar5 + 9]));
            ret = CPS_htonl(ret);
            }
            break;
          }
          //puVar8 = (undefined2 *)(puVar6 + uVar5 + 10);
          hostnameResponsePtr = (char*)(puVar6 + uVar5 + 10);
        }
      }
    }


    CPS_SocConsume(local_74);
  } while( TRUE );
}

//static undefined4 resolve_sub(undefined4 param_1,int param_2,undefined2 param_3)
static undefined4 resolve_sub(char * aName, CPSInAddr aDnsIP, undefined2 aIdent)
{
  undefined4 uVar1;

  #ifdef SDK_PORT
  //aDnsIP = 0x01010101;
  OSThread * thread = OS_GetCurrentThread();
  //puVar2 = (undefined4 *)OSi_GetSpecificData(uVar1,0);
  CPSSoc * mySoc = OSi_GetSpecificData(thread,0);
  //if(mySoc != NULL) {
  //  aDnsIP = 0xD42B3EB2; //178.62.43.212
  //} else {
  //  aDnsIP = 0;
  //}
  #endif
  
  if (aDnsIP == 0) {
    uVar1 = 0xffffffff;
  } else {
    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(0,53,aDnsIP);
    uVar1 = resolve_common(aName,1,aIdent,0,0);
    CPS_SocRelease();
  }
  return uVar1;
}

static void return_integer(undefined4 param_1,int param_2,int *param_3,int param_4,undefined4 param_5)
{
  int iVar1;
  undefined uVar2;
  undefined auStack_34 [12];
  int local_28;
  
  *param_3 = *param_3 + 4;
  iVar1 = *(int *)(*param_3 + -4);
  uVar2 = 0;
  if (param_4 != 0) {
    if (iVar1 < 0) {
      uVar2 = 0x2d;
      iVar1 = -iVar1;
    }
    else if (*(char *)(param_2 + 2) != '\0') {
      uVar2 = *(undefined *)(param_2 + 2);
    }
  }
  local_28 = param_4;
  tostring(auStack_34,iVar1,param_5);
  //justify_string(param_1,auStack_34,param_2,*(undefined *)(param_2 + 3),uVar2);
  return;
}

static CPSInAddr rev_resolve_sub(undefined4 param_1,int param_2,undefined2 param_3,undefined4 param_4,
               undefined4 param_5)
{
  CPSInAddr uVar1;
  
  if (param_2 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(0,0x35,param_2);
    //uVar1 = resolve_common(param_1,0xc,param_3,param_4,param_5);
    CPS_SocRelease();
  }
  return uVar1;
}

static void scavenger(void * arg)
{
  BOOL bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint local_24;
  
  scavenger_force_exit = 0;
  //MI_CpuClear8(&scavenger_soc,100);
  //scavenger_soc.rcvbuf.size = 0x180;
  //scavenger_soc.rcvbuf.data = scavenger_rcvbuf;
  //scavenger_soc.sndbuf.size = 0x180;
  //scavenger_soc.sndbuf.data = scavenger_sndbuf;
  //CPS_SocRegister(&scavenger_soc);
  iVar5 = 0;
  local_24 = 1;
  iVar6 = 1;
  CPSNoIpReason = 1;
  bVar1 = TRUE;
  while (OS_Sleep(1000), scavenger_force_exit == 0) {
    iVar2 = CPSi_GetTick();
    //iVar3 = (*link_is_on)();
    if (iVar3 == 0) {
      //reset_network_vars(1);
      iVar5 = 0;
      local_24 = 1;
      iVar6 = 1;
    }
    else {
      local_24 = local_24 - 1;
      if (local_24 == 0) {
        if ((/*mode &*/ 1) == 0) {
          // WARNING: Could not find normalized switch variable to match jumptable
          switch(iVar5) {
          case 0:
            if (bVar1) {
              CPSNoIpReason = 2;
              bVar1 = FALSE;
            }
            iVar5 = dhcp_discover_server();
            if ((iVar5 == 0) || (iVar5 = dhcp_request_server(&local_24,0), iVar5 == 0)) {
              set_fixed_ip();
              iVar5 = 3;
            }
            else {
              iVar5 = 1;
            }
            break;
          case 1:
            iVar3 = dhcp_request_server(&local_24,1);
            if ((iVar3 == 0) && (local_24 < 0x3c)) {
              iVar5 = 2;
            }
          }
        }
        else if (iVar5 == 0) {
          set_fixed_ip();
          iVar5 = 1;
        }
      }
    }
    for (iVar3 = 0; iVar3 < 8; iVar3 = iVar3 + 1) {
      if (arpcache && (arpcache[iVar3].ip != 0) &&
         (0x3bd < (int)((iVar2 - (uint)arpcache[iVar3].when) * 0x10000) >> 0x10)) {
        arpcache[iVar3].ip = 0;
      }
    }
    if ((CPSGatewayIp != 0) && (iVar6 = iVar6 + -1, iVar6 == 0)) {
      //send_arprequest(CPSGatewayIp);
      iVar6 = 0x69;
    }
    //for (iVar3 = OS_GetThreadList(); iVar3 != 0; iVar3 = OS_GetNextThread(iVar3)) {
    //  piVar4 = (int *)OSi_GetSpecificData(iVar3,0);
    //  if ((piVar4 != (int *)0x0) && (*piVar4 != 0)) {
    //    if ((*(char *)(piVar4 + 2) == '\x03') && (0x27 < iVar2 - piVar4[4])) {
    //      *(undefined *)(piVar4 + 2) = 1;
    //      *(undefined2 *)(piVar4 + 6) = *(undefined2 *)((int)piVar4 + 0x1a);
    //      piVar4[7] = piVar4[8];
    //    }
    //    else if ((*(char *)(piVar4 + 2) == '\x02') && (0x27 < iVar2 - piVar4[4])) {
    //      if (piVar4[1] == 1) {
    //        *(undefined *)(piVar4 + 2) = 0;
    //        piVar4[1] = 0;
    //        OS_WakeupThreadDirect(*piVar4);
    //      }
    //    }
    //    else if ((*(char *)(piVar4 + 2) != '\x04') && (piVar4[1] == 2)) {
    //      piVar4[1] = 0;
    //      OS_WakeupThreadDirect(*piVar4);
    //    }
    //  }
    //}
    for (iVar3 = 0; iVar3 < 8; iVar3 = iVar3 + 1) {
      if (fragtable && (fragtable[iVar3].frags != 0) && (0xef < (int)(iVar2 - fragtable[iVar3].when))) {
        //OSi_TWarning(_15259,0xb45,_16368);
        (*CPSiFree)(fragtable[iVar3].buf);
        fragtable[iVar3].frags = 0;
      }
    }
    CPSi_SslPeriodical(iVar2);
    //if (scavenger_callback != (_func_void *)0x0) {
    //  (*scavenger_callback)();
    //}
  }
  if (((/*mode &*/ 1) == 0) && (iVar5 != 3)) {
    dhcp_release_server();
  }
  CPS_SocUnRegister();
  return;
}

static void send_arprequest(CPSInAddr aIP)
{
  undefined auStack_38 [6];
  undefined auStack_32 [6];
  undefined2 local_2c;
  undefined local_29;
  undefined local_28;
  undefined2 local_26;
  undefined local_23;
  undefined auStack_22 [6];
  undefined2 local_1c;
  undefined2 local_1a;
  undefined2 local_12;
  undefined2 local_10;
  undefined4 uStack_c;
  
  MI_CpuClear8(auStack_38,0x2a);
  MI_CpuFill8(auStack_38,0xff,6);
  MI_CpuCopy8(CPSMyMac,auStack_32,6);
  local_2c = CPS_htons(0x806);
  local_29 = 1;
  local_28 = 8;
  local_26 = CPS_htons(0x604);
  local_23 = 1;
  MI_CpuCopy8(CPSMyMac,auStack_22,6);
  local_1c = CPS_htons(CPSMyIp >> 0x10);
  local_1a = CPS_htons(CPSMyIp & 0xffff);
  local_12 = CPS_htons(aIP >> 0x10);
  local_10 = CPS_htons(aIP & 0xffff);
  //send_packet(auStack_38,0x2a,0,0);
  return;
}

static void send_ether(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
               undefined2 param_6)
{
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 uVar5;
  
  puVar4 = (undefined *)(param_1 + -0xe);
  uVar5 = param_4;
  uVar1 = CPS_htons(param_6);
  *(undefined2 *)(param_1 + -2) = uVar1;
  iVar2 = is_multicast(param_5);
  if (iVar2 == 0) {
    iVar2 = get_targetip(param_5);
    if (iVar2 == 0) {
      return;
    }
    //iVar3 = inq_arpcache(iVar2);
    if (iVar3 == 0) {
      iVar3 = arprequest(iVar2);
    }
    if (iVar3 == 0) {
      return;
    }
    //MI_CpuCopy8(iVar3,puVar4,6);
  }
  else {
    *puVar4 = 1;
    *(undefined *)(param_1 + -0xd) = 0;
    *(undefined *)(param_1 + -0xc) = 0x5e;
    *(byte *)(param_1 + -0xb) = (byte)((uint)param_5 >> 0x10) & 0x7f;
    *(char *)(param_1 + -10) = (char)((uint)param_5 >> 8);
    *(char *)(param_1 + -9) = (char)param_5;
  }
  //MI_CpuCopy8(CPSMyMac,param_1 + -8,6);
  //send_packet(puVar4,param_2 + 0xe,param_3,param_4,uVar5);
  return;
}

static void send_ip(int param_1,uint param_2,int param_3,int param_4,uint param_5,undefined param_6)
{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  undefined4 local_8;
  
  *(undefined *)(param_1 + -0x14) = 0x45;
  *(undefined *)(param_1 + -0x13) = 0;
  //ipid = ipid + 1;
  //uVar1 = CPS_htons(ipid);
  *(undefined2 *)(param_1 + -0x10) = uVar1;
  *(undefined *)(param_1 + -0xc) = 0x80;
  *(undefined *)(param_1 + -0xb) = param_6;
  uVar1 = CPS_htons(CPSMyIp >> 0x10);
  *(undefined2 *)(param_1 + -8) = uVar1;
  uVar1 = CPS_htons(CPSMyIp & 0xffff);
  *(undefined2 *)(param_1 + -6) = uVar1;
  uVar1 = CPS_htons(param_5 >> 0x10);
  *(undefined2 *)(param_1 + -4) = uVar1;
  uVar1 = CPS_htons(param_5 & 0xffff);
  *(undefined2 *)(param_1 + -2) = uVar1;
  uVar2 = 0;
  iVar3 = param_1;
  local_8 = param_3;
  if (0x5c8 < param_2) {
    for (; 0x5c8 < param_2; param_2 = param_2 - 0x5c8) {
      send_ip_frag(param_1,0,iVar3,0x5c8,param_5,uVar2 | 0x2000);
      uVar2 = uVar2 + 0xb9 & 0xffff;
      iVar3 = iVar3 + 0x5c8;
    }
    if (param_2 != 0) {
      if (param_4 == 0) {
        send_ip_frag(param_1,0,iVar3,param_2,param_5,uVar2);
      }
      else {
        send_ip_frag(param_1,0,iVar3,param_2,param_5,uVar2 | 0x2000);
      }
      uVar2 = uVar2 + (param_2 >> 3) & 0xffff;
      param_2 = 0;
    }
  }
  while (0x5c8 < param_2 + param_4) {
    iVar3 = 0x5c8 - param_2;
    send_ip_frag(param_1,param_2,local_8,iVar3,param_5,uVar2 | 0x2000);
    local_8 = local_8 + iVar3;
    param_4 = param_4 - iVar3;
    uVar2 = uVar2 + 0xb9 & 0xffff;
    param_2 = 0;
  }
  if (param_2 + param_4 != 0) {
    send_ip_frag(param_1,param_2,local_8,param_4,param_5,uVar2);
  }
  return;
}

static void send_ip_frag(int param_1,int param_2,undefined4 param_3,int param_4,unsigned_long param_5,
                 undefined2 param_6)
{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar1 = CPS_htons(param_2 + 0x14 + param_4 & 0xffff);
  *(undefined2 *)(param_1 + -0x12) = uVar1;
  uVar1 = CPS_htons(param_6);
  *(undefined2 *)(param_1 + -0xe) = uVar1;
  uVar1 = CPS_htons(0);
  *(undefined2 *)(param_1 + -10) = uVar1;
  //calc_checksum(param_1 + -0x14,0x14);
  //uVar1 = CPS_htons();
  *(undefined2 *)(param_1 + -10) = uVar1;
  if ((param_5 != 0x7f000001) && (param_5 != CPSMyIp)) {
    send_ether(param_1 + -0x14,param_2 + 0x14,param_3,param_4,param_5,0x800);
  }
  if (((param_5 == 0x7f000001) || (param_5 == CPSMyIp)) ||
     (iVar2 = is_multicast(param_5), iVar2 != 0)) {
    //MI_CpuCopy8(_15351,param_1 + -0x1c,8);
    uVar3 = OS_DisableInterrupts();
    //put_in_buffer(CPSMyMac,CPSMyMac,param_1 + -0x1c,param_2 + 0x1c,param_3,param_4);
    OS_RestoreInterrupts(uVar3);
  }
  return;
}

static void send_packet(int param_1,int param_2,undefined4 param_3,undefined4 param_4)
{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = param_4;
  //MI_CpuCopy8(_15351,param_1 + 6,6);
  //iVar1 = WCM_SendDCFDataEx(param_1,param_1 + 6,param_2 + -6,param_3,param_4,uVar2);
  //wfailed = iVar1 < 0;
  return;
}

static void send_ping(undefined4 param_1,undefined4 param_2,int param_3)
{
  unsigned_short uVar1;
  undefined2 uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined2 *puVar5;
  
  iVar3 = *(int *)(param_3 + 0x4c);
  puVar5 = (undefined2 *)(iVar3 + 0x22);
  uVar2 = CPS_htons(0x800);
  *puVar5 = uVar2;
  //uVar2 = OS_GetCurrentThread();
  *(undefined2 *)(iVar3 + 0x26) = uVar2;
  *(undefined2 *)(iVar3 + 0x24) = 0;
  //*(unsigned_short *)(param_3 + 10) = pingseq;
  //uVar1 = pingseq + 1;
  //*(unsigned_short *)(iVar3 + 0x28) = pingseq;
  //pingseq = uVar1;
  uVar4 = calc_checksum_do(puVar5,8,0);
  //uVar2 = calc_checksum_do(param_1,param_2,uVar4);
  invert_checksum(uVar2);
  //uVar2 = CPS_htons();
  *(undefined2 *)(iVar3 + 0x24) = uVar2;
  //send_ip(puVar5,8,param_1,param_2,*(undefined4 *)(param_3 + 0x1c),1);
  return;
}

static void send_tcp(undefined4 param_1,int param_2,int param_3,byte param_4)
{
  undefined2 uVar1;
  //_OSThread *p_Var2;
  void * p_Var2;
  undefined4 uVar3;
  uchar *puVar4;
  uint uVar5;
  
  if (*(char *)(param_3 + 8) != '\0') {
    //p_Var2 = (_OSThread *)OS_GetCurrentThread();
    if (/*p_Var2 == &tcpip_thread*/ 0) {
    //  puVar4 = tmpbuf + 0x22;
    }
    else {
      puVar4 = (uchar *)(*(int *)(param_3 + 0x4c) + 0x22);
    }
    if ((param_4 & 2) == 0) {
      uVar5 = 0x14;
    }
    else {
      uVar5 = 0x18;
    }
    uVar1 = CPS_htons(CPSMyIp >> 0x10);
    *(undefined2 *)(puVar4 + -0xc) = uVar1;
    uVar1 = CPS_htons(CPSMyIp & 0xffff);
    *(undefined2 *)(puVar4 + -10) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x1c) >> 0x10);
    *(undefined2 *)(puVar4 + -8) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x1c) & 0xffff);
    *(undefined2 *)(puVar4 + -6) = uVar1;
    uVar1 = CPS_htons(6);
    *(undefined2 *)(puVar4 + -4) = uVar1;
    uVar1 = CPS_htons(uVar5 + param_2 & 0xffff);
    *(undefined2 *)(puVar4 + -2) = uVar1;
    uVar1 = CPS_htons(*(undefined2 *)(param_3 + 10));
    *(undefined2 *)puVar4 = uVar1;
    uVar1 = CPS_htons(*(undefined2 *)(param_3 + 0x18));
    *(undefined2 *)(puVar4 + 2) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x28) >> 0x10);
    *(undefined2 *)(puVar4 + 4) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x28) & 0xffff);
    *(undefined2 *)(puVar4 + 6) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x24) >> 0x10);
    *(undefined2 *)(puVar4 + 8) = uVar1;
    uVar1 = CPS_htons(*(uint *)(param_3 + 0x24) & 0xffff);
    *(undefined2 *)(puVar4 + 10) = uVar1;
    puVar4[0xc] = (uchar)((uVar5 >> 2) << 4);
    puVar4[0xd] = param_4;
    uVar1 = CPS_htons(*(int *)(param_3 + 0x3c) - *(int *)(param_3 + 0x44) & 0xffff);
    *(undefined2 *)(puVar4 + 0xe) = uVar1;
    uVar1 = CPS_htons(0);
    *(undefined2 *)(puVar4 + 0x10) = uVar1;
    puVar4[0x12] = '\0';
    puVar4[0x13] = '\0';
    if ((param_4 & 2) != 0) {
      //uVar1 = CPS_htons(mymss + 0x2040000 >> 0x10);
      *(undefined2 *)(puVar4 + 0x14) = uVar1;
      //uVar1 = CPS_htons(mymss);
      *(undefined2 *)(puVar4 + 0x16) = uVar1;
    }
    //uVar3 = calc_checksum_do(puVar4 + -0xc,uVar5 + 0xc,0);
    //uVar1 = calc_checksum_do(param_1,param_2,uVar3);
    invert_checksum(uVar1);
    //uVar1 = CPS_htons();
    *(undefined2 *)(puVar4 + 0x10) = uVar1;
    //send_ip(puVar4,uVar5,param_1,param_2,*(undefined4 *)(param_3 + 0x1c),6);
    *(int *)(param_3 + 0x28) = *(int *)(param_3 + 0x28) + param_2;
    if ((param_4 & 3) != 0) {
      *(int *)(param_3 + 0x28) = *(int *)(param_3 + 0x28) + 1;
    }
  }
  return;
}

//static void send_udp(undefined4 param_1,int param_2,int param_3)
static void send_udp(void * aBuf,int aLen,CPSSoc * aSoc)
{
  undefined2 uVar1;
  int iVar2;
  undefined4 uVar3;

  void * sndBuf; /*iVar2*/
  
  //iVar2 = *(int *)(aSoc + 0x4c);
  sndBuf = aSoc->sndbuf.data;
  uVar1 = CPS_htons(CPSMyIp >> 0x10);
  //*(undefined2 *)(iVar2 + 0x16) = uVar1;
  *(u16*)(sndBuf + 0x16) = uVar1;
  uVar1 = CPS_htons(CPSMyIp & 0xffff);
  //*(undefined2 *)(iVar2 + 0x18) = uVar1;
  *(u16*)(sndBuf + 0x18) = uVar1;
  //uVar1 = CPS_htons(*(uint *)(aSoc + 0x1c) >> 0x10);
  uVar1 = CPS_htons(aSoc->remote_ip >> 0x10);
  //*(undefined2 *)(iVar2 + 0x1a) = uVar1;
  *(u16*)(sndBuf + 0x1a) = uVar1;
  //uVar1 = CPS_htons(*(uint *)(aSoc + 0x1c) & 0xffff);
  uVar1 = CPS_htons(aSoc->remote_ip & 0xffff);
  //*(undefined2 *)(iVar2 + 0x1c) = uVar1;
  *(u16*)(sndBuf + 0x1c) = uVar1;
  uVar1 = CPS_htons(0x11);
  //*(undefined2 *)(iVar2 + 0x1e) = uVar1;
  *(u16*)(sndBuf + 0x1e) = uVar1;
  uVar1 = CPS_htons(aLen + 8U & 0xffff);
  //*(undefined2 *)(iVar2 + 0x26) = uVar1;
  *(u16*)(sndBuf + 0x26) = uVar1;
  //*(undefined2 *)(iVar2 + 0x20) = *(undefined2 *)(iVar2 + 0x26);
  *(u16*)(sndBuf + 0x20) = uVar1;
  //uVar1 = CPS_htons(*(undefined2 *)(aSoc + 0x18));
  uVar1 = CPS_htons(aSoc->remote_port);
  //*(undefined2 *)(iVar2 + 0x24) = uVar1;
  *(u16*)(sndBuf + 0x24) = uVar1;
  //uVar1 = CPS_htons(*(undefined2 *)(aSoc + 10));
  uVar1 = CPS_htons(aSoc->local_port);
  //*(undefined2 *)(iVar2 + 0x22) = uVar1;
  *(u16*)(sndBuf + 0x22) = uVar1;
  uVar1 = CPS_htons(0);
  //*(undefined2 *)(iVar2 + 0x28) = uVar1;
  *(u16*)(sndBuf + 0x28) = uVar1;
  //uVar3 = calc_checksum_do(iVar2 + 0x16,0x14,0);
  //uVar1 = calc_checksum_do(aBuf,aLen,uVar3);
  invert_checksum(uVar1);
  //uVar1 = CPS_htons();
  //*(undefined2 *)(iVar2 + 0x28) = uVar1;
  *(u16*)(sndBuf + 0x28) = uVar1;
  //send_ip((undefined2 *)(iVar2 + 0x22),8,aBuf,aLen,*(undefined4 *)(aSoc + 0x1c),0x11);
  #ifdef SDK_PORT
  //Send the data


  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(aSoc->remote_port_bound);
  #ifdef SDK_BUILD_WIN64
  server.sin_addr.S_un.S_addr = aSoc->remote_ip;
  int sendOk;

  sendOk = sendto(aSoc->WIN_socket, aBuf, aLen, 0, (struct sockaddr *)&server, sizeof(server) );
  if( sendOk == SOCKET_ERROR )
  {
    printf("network.c WinError: %d", WSAGetLastError());
  }
  #endif
  #ifdef SDK_BUILD_LINUX
  server.sin_addr.s_addr = aSoc->remote_ip;
  while(!s_SocThreadReady) {
    SDL_Delay(1);
  }
  sendto(aSoc->WIN_socket, aBuf, aLen, 0, (struct sockaddr *)&server, sizeof(server));
  #endif

  //int sz = sizeof(server);
//
  //int numBytes = recvfrom(aSoc->WIN_socket, aSoc->rcvbuf.data + aSoc->rcvbufp, aSoc->rcvbuf.size - aSoc->rcvbufp, 0, (struct sockaddr *)&server, &sz);
  #else
  send_ip((sndBuf + 0x22),8,aBuf,aLen,aSoc->remote_ip,0x11);
  #endif
  return;
}

static void set_fixed_ip(void)
{
  int iVar1;
  int iVar2;
  
  //=(*dhcp_callback)();
  dhcp_callback();
  if (CPSMyIp != 0) {
    //send_arprequest(CPSMyIp);
    OS_Sleep(100);
    //send_arprequest(CPSMyIp);
    iVar1 = CPSi_GetTick();
    while( TRUE ) {
      //iVar2 = (*link_is_on)();
      if (iVar2 == 0) {
        return;
      }
      iVar2 = CPSi_GetTick();
      if (0x16 < iVar2 - iVar1) {
        return;
      }
      //if (ip_conflict != '\0') break;
      OS_Sleep(100);
    }
    //reset_network_vars(4);
  }
  return;
}

#ifndef SDK_PORT
static void strlwr(byte *param_1)
{
  byte bVar1;
  
  while( TRUE ) {
    bVar1 = *param_1;
    if (bVar1 == 0) break;
    if (bVar1 - 0x41 < 0x1a) {
      *param_1 = bVar1 ^ 0x20;
    }
    param_1 = param_1 + 1;
  }
  return;
}
#endif

static int strtol10(byte *param_1,char **param_2)
{
  int iVar1;
  uint uVar2;
  
  *param_2 = param_1;
  iVar1 = 0;
  while (uVar2 = *param_1 - 0x30 & 0xff, uVar2 < 10) {
    iVar1 = uVar2 + iVar1 * 10;
    param_1 = param_1 + 1;
    *param_2 = param_1;
  }
  return iVar1;
}

static void tcpip(void * arg)
{
  int iVar1;
  int iVar2;
  undefined4 in_r3;
  uint local_10;
  undefined4 uStack_c;
  
  uStack_c = in_r3;
  do {
    //iVar1 = receive_packet(&local_10);
    if (0x22 < local_10) {
      iVar2 = CPS_htons(*(undefined2 *)(iVar1 + 0xc));
      if (iVar2 == 0x800) {
        //dispatch_ip(iVar1 + 0xe,local_10 - 0xe);
      }
      else if (iVar2 == 0x806) {
        //dispatch_arp(iVar1 + 0xe,local_10 - 0xe);
      }
    }
    throw_packet();
  } while( TRUE );
}

static void tcp_send_ack(undefined4 param_1,undefined2 param_2,undefined4 param_3,undefined4 param_4)
{
  //tcp_send_handshake(param_1,0x10,param_2,param_4,param_4);
  return;
}

static void tcp_send_finack(undefined4 param_1,undefined2 param_2,undefined4 param_3,undefined4 param_4)
{
  //tcp_send_handshake(param_1,0x11,param_2,param_4,param_4);
  return;
}

static void tcp_send_handshake(int param_1,undefined param_2,undefined2 param_3,undefined4 param_4)
{
  int iVar1;
  //_OSThread *p_Var2;
  void * p_Var2;
  
  iVar1 = no_need_inq(*(undefined4 *)(param_1 + 0x1c));
  if ((iVar1 == 0) && (/*p_Var2 = (_OSThread *)OS_GetCurrentThread(), p_Var2 == &tcpip_thread*/0)) {
    get_targetip(*(undefined4 *)(param_1 + 0x1c));
    //send_arprequest();
    return;
  }
  //send_tcp(0,0,param_1,param_2,param_3,param_4);
  return;
}

static void tcp_send_rst(int param_1,undefined2 *param_2,int param_3,undefined4 param_4)
{
  int iVar1;
  uint uVar2;
  
  //MI_CpuClear8(&tmpsoc,100);
  //tmpsoc.local_port = CPS_htons(param_2[1]);
  //tmpsoc.remote_port = CPS_htons(*param_2);
  iVar1 = CPS_htons(*(undefined2 *)(param_1 + 0xc));
  uVar2 = CPS_htons(*(undefined2 *)(param_1 + 0xe));
  //tmpsoc.remote_ip = iVar1 << 0x10 | uVar2;
  if ((*(byte *)((int)param_2 + 0xd) & 0x10) == 0) {
    //tmpsoc.seqno = 0;
    iVar1 = CPS_htons(param_2[2]);
    uVar2 = CPS_htons(param_2[3]);
    //tmpsoc.ackno = param_3 + (iVar1 << 0x10 | uVar2);
    if ((*(byte *)((int)param_2 + 0xd) & 3) != 0) {
      //tmpsoc.ackno = tmpsoc.ackno + 1;
    }
    //tcp_send_handshake(&tmpsoc,0x14,param_4);
  }
  else {
    iVar1 = CPS_htons(param_2[4]);
    uVar2 = CPS_htons(param_2[5]);
    //tmpsoc.seqno = iVar1 << 0x10 | uVar2;
    //tcp_send_handshake(&tmpsoc,4,param_4);
  }
  return;
}

u32 tcp_write_do(u8 * buf, u32 len, CPSSoc * aSoc, int param_4)
{
  uint unaff_r4;
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  if (param_4 == 0) {
    uVar1 = aSoc->remote_win;
  }
  else {
    uVar1 = 1;
  }
  iVar4 = aSoc->ackrcvd;
  iVar2 = iVar4 * 2 + 4;
  iVar5 = param_4;
  while( TRUE ) {
    if ((len == 0) || (aSoc->state != '\x04')) {
      return unaff_r4;
    }
    unaff_r4 = uVar1;
    if (aSoc->remote_mss < uVar1) {
      unaff_r4 = aSoc->remote_mss;
    }
    //if (mymss < unaff_r4) {
    //  unaff_r4 = (uint)mymss;
    //}
    if (param_4 == 0) {
      unaff_r4 = unaff_r4 & 0xfffffffe;
    }
    if (len < unaff_r4) {
      unaff_r4 = len;
    }
    iVar3 = iVar2 + (aSoc->ackrcvd - iVar4);
    iVar4 = aSoc->ackrcvd;
    iVar2 = iVar3 + -1;
    if (iVar3 == 0) {
      unaff_r4 = 0;
    }
    if (unaff_r4 == 0) break;
    uVar1 = uVar1 - unaff_r4;
    //send_tcp(buf,unaff_r4,aSoc,0x18,0,iVar5);
    OS_YieldThread();
    buf = buf + unaff_r4;
    len = len - unaff_r4;
  }
  return 0;
}

void tcp_write_do2(u8* buf, u32 len, u8* buf2, u32 len2, CPSSoc * aSoc, undefined4 param_6)
{
  int iVar1;
  int iVar2;
  
  iVar2 = len2;
  iVar1 = tcp_write_do(buf, len, aSoc, param_6/*, len2*/);
  if ((iVar1 != 0) && (len2 != 0)) {
    tcp_write_do(buf2, len2, aSoc, 0/*, iVar2*/);
  }
  return;
}

static void throw_packet(void)
{
  undefined4 uVar1;
  
  uVar1 = OS_DisableInterrupts();
  //wlan_getpnt = wlan_getpnt + *(ushort *)(wlan_buf + wlan_getpnt);
  //if (wlan_buflen <= wlan_getpnt) {
  //  wlan_getpnt = 0;
  //}
  OS_RestoreInterrupts(uVar1);
  return;
}

static void tostring(char *param_1,int param_2,undefined4 param_3)
{
  char cVar1;
  uint extraout_r1;
  char *pcVar2;
  
  pcVar2 = param_1;
  do {
    //_u32_div_f(param_2,param_3);
    if (extraout_r1 < 10) {
      *pcVar2 = (char)extraout_r1 + '0';
    }
    else {
      *pcVar2 = (char)extraout_r1 + '7';
    }
    pcVar2 = pcVar2 + 1;
    //param_2 = _u32_div_f(param_2,param_3);
  } while (param_2 != 0);
  *pcVar2 = '\0';
  for (; pcVar2 = pcVar2 + -1, param_1 < pcVar2; param_1 = param_1 + 1) {
    cVar1 = *param_1;
    *param_1 = *pcVar2;
    *pcVar2 = cVar1;
  }
  return;
}

static u8 * udp_read_raw(u32 *len,CPSSoc * aSoc)
{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = OS_DisableInterrupts();
  while (iVar2 = aSoc->rcvbufp, iVar2 == 0) {
    //*(undefined4 *)(aSoc + 4) = 3;
    aSoc->block_type = CPS_BLOCK_UDPREAD;
    OS_SleepThread(0);
  }
  OS_RestoreInterrupts(uVar1);
  *len = iVar2;
  //return *(undefined4 *)(aSoc + 0x40);
  return (u8 *)(aSoc->rcvbuf.data);
}

static undefined4 valid_IP(int param_1,int param_2)
{
  BOOL bVar1;
  BOOL bVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  bVar2 = FALSE;
  bVar1 = FALSE;
  if ((param_1 != 0) && (param_1 != -1)) {
    bVar1 = TRUE;
  }
  if ((bVar1) && (param_2 != 0)) {
    bVar2 = TRUE;
  }
  if ((bVar2) && (param_2 != -1)) {
    uVar3 = 1;
  }
  return uVar3;
}

/*---------------------------------------------------------------------------*
 *
 * CPS Public Procedures
 * 
 *---------------------------------------------------------------------------*/

int CPS_CalmDown(void)
{
  undefined4 uVar1;
  int iVar2;
  
  uVar1 = OS_DisableInterrupts();
  iVar2 = OS_IsThreadTerminated(&scavenger_thread);
  if ((iVar2 == 0) && (scavenger_force_exit == 0)) {
    scavenger_force_exit = 1;
    //OS_WakeupThreadDirect(&scavenger_thread);
  }

  #ifdef SDK_PORT
  //PCPORT_TODO: Remove me to ensure scavenger is properly closed
  iVar2 = 1;
  #endif
  OS_RestoreInterrupts(uVar1);
  return iVar2;
}

void CPS_Cleanup(void)
{
  CPS_CalmDown();
  #ifdef SDK_PORT
  SDL_LockMutex(s_SocketThreadStartupMutex);
  if(WIN_socThread != NULL) {
    //pthread_cancel(WIN_socPthread);
    pthread_t threadId = SDL_GetThreadID(WIN_socThread);
    //pthread_cancel(threadId);
    s_stopSocThread = 1;
    //pthread_join(WIN_socPthread, NULL);
    SDL_WaitThread(WIN_socThread, NULL);
    WIN_socThread = NULL;
  }
  SDL_UnlockMutex(s_SocketThreadStartupMutex);
  #endif
  //OS_JoinThread(&scavenger_thread);
  //OS_DestroyThread(&tcpip_thread);
  //receiver_thread = (_OSThread *)0x0;
  //reset_network_vars(0);
  //wlan_buf = (uchar *)0x0;
  //wlan_buflen = 0;
  return;
}

//void CPS_EncodeNbName(char *param_1,byte *param_2)
extern void CPS_EncodeNbName(u8 *d, u8 *s)
{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  char *pcVar4;
  
  for (iVar2 = 0; iVar2 < 0xf; iVar2 = iVar2 + 1) {
    if (*s == 0) {
      uVar1 = 0x20;
      pbVar3 = s;
    }
    else {
      pbVar3 = s + 1;
      uVar1 = (uint)*s;
    }
    if ((0x60 < uVar1) && (uVar1 < 0x7b)) {
      uVar1 = uVar1 & 0xffffffdf;
    }
    pcVar4 = d + 1;
    *d = (char)((int)uVar1 >> 4) + 'A';
    d = d + 2;
    *pcVar4 = ((byte)uVar1 & 0xf) + 0x41;
    s = pbVar3;
  }
  *d = 'A';
  d[1] = 'A';
  d[2] = '\0';
  return;
}

s32 CPS_GetProperSize(void)
{
  ushort uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  
  //uVar2 = OS_GetCurrentThread();
  //iVar3 = OSi_GetSpecificData(uVar2,0);
  if ((iVar3 == 0) || (*(char *)(iVar3 + 8) != '\x04')) {
    uVar4 = 0xffffffff;
  }
  else {
    if (*(ushort *)(iVar3 + 0x2e) < *(ushort *)(iVar3 + 0x2c)) {
      uVar1 = *(ushort *)(iVar3 + 0x2e);
    }
    else {
      uVar1 = *(ushort *)(iVar3 + 0x2c);
    }
    uVar4 = (uint)uVar1;
    //if (mymss < uVar4) {
    //  uVar4 = (uint)mymss;
    //}
    if (*(int *)(iVar3 + 0x48) + -0x36 < (int)uVar4) {
      uVar4 = *(int *)(iVar3 + 0x48) - 0x36;
    }
  }
  return uVar4;
}

u32 CPS_GetThreadPriority(void)
{
  return helper_threads_priority;
}

CPSInAddr CPS_NbResolve(const char * param_1)
{
  undefined2 uVar1;
  int iVar2;
  int local_34;
  undefined auStack_30 [36];
  undefined4 uStack_c;
  
  //uStack_c = param_4;
  //iVar2 = rawip(param_1,&local_34);
  if (iVar2 == 0) {
    CPS_EncodeNbName(auStack_30,param_1);
    CPS_SocUse();
    CPS_SocDatagramMode();
    CPS_SocBind(0x89,0x89,0xffffffff);
    uVar1 = MATH_Rand32(&CPSiRand32ctx,0x10000);
    local_34 = resolve_common(auStack_30,0x20,uVar1,0,0);
    CPS_SocRelease();
    if (local_34 == -1) {
      local_34 = 0;
    }
  }
  return local_34;
}

CPSInAddr CPS_Resolve(const char * aName)
{
  int iVar1;
  int iVar2;
  char local_20 [2];
  undefined2 randomNums[3];
  int local_18;
  undefined4 uStack_14;
  
  //uStack_14 = param_4;
  randomNums[0] = MATH_Rand32(&CPSiRand32ctx,0x10000);
  randomNums[1] = MATH_Rand32(&CPSiRand32ctx,0x10000);
  iVar1 = rawip(aName,&local_18);
  if (iVar1 == 0) {
    local_20[0] = '\x01';
    local_20[1] = 1;
    for (iVar1 = 0; iVar1 < 3; iVar1 = iVar1 + 1) {
      for (iVar2 = 0; iVar2 < 2; iVar2 = iVar2 + 1) {
        if (local_20[iVar2] != '\0') {
          local_18 = resolve_sub(aName,CPSDnsIp[iVar2],randomNums[iVar2]);
          if ((local_18 != 0) && (local_18 != -1)) goto LAB_00017a40;
          if (local_18 == -1) {
            local_20[iVar2] = '\0';
          }
        }
      }
    }
LAB_00017a40:
    if (local_18 == -1) {
      local_18 = 0;
    }
  }
  return local_18;
}


//undefined4 CPS_RevResolve(uint param_1,undefined *param_2,uint param_3)
int CPS_RevResolve(CPSInAddr param_1, char * param_2, u32 param_3)
{
  undefined4 uVar1;
  char *__dest;
  uint uVar2;
  int iVar3;
  uint __n;
  char local_5c [2];
  undefined2 local_5a [3];
  int local_54;
  undefined auStack_50 [32];
  
  local_5a[0] = MATH_Rand32(&CPSiRand32ctx,0x10000);
  local_5a[1] = MATH_Rand32(&CPSiRand32ctx,0x10000);
  local_5c[0] = '\x01';
  local_5c[1] = 1;
  //uVar1 = byte2a(auStack_50,param_1 & 0xff);
  //uVar1 = byte2a(uVar1,param_1 >> 8 & 0xff);
  //uVar1 = byte2a(uVar1,param_1 >> 0x10 & 0xff);
  //__dest = (char *)byte2a(uVar1,param_1 >> 0x18);
  //strcpy(__dest,_16637);
  for (local_54 = 0; local_54 < 3; local_54 = local_54 + 1) {
    for (iVar3 = 0; iVar3 < 2; iVar3 = iVar3 + 1) {
      if (local_5c[iVar3] != '\0') {
        //param_1 = rev_resolve_sub(auStack_50,CPSDnsIp[iVar3],local_5a[iVar3],param_2,param_3);
        if ((param_1 != 0) && (param_1 != 0xffffffff)) goto LAB_00017d1c;
        if (param_1 == 0xffffffff) {
          local_5c[iVar3] = '\0';
        }
      }
    }
  }
LAB_00017d1c:
  if ((param_1 == 0) || (param_1 == 0xffffffff)) {
    *param_2 = 0;
    uVar1 = 1;
  }
  else if (param_1 == 2) {
    *param_2 = 0;
    uVar1 = 0xffffffff;
  }
  else {
    iVar3 = 0;
    for (uVar2 = 0; uVar2 < param_3; uVar2 = uVar2 + __n + 1) {
      __n = (uint)(char)param_2[iVar3];
      if ((__n & 0xc0) == 0xc0) {
        //OSi_TWarning(_15259,0xdd3,_16638);
        *param_2 = 0;
        return 1;
      }
      if (__n == 0) {
        if (uVar2 != 0) {
          uVar2 = uVar2 - 1;
        }
        param_2[uVar2] = 0;
        return 0;
      }
      //memmove(param_2 + uVar2,param_2 + iVar3 + 1,__n);
      iVar3 = iVar3 + 1 + __n;
      param_2[uVar2 + __n] = 0x2e;
    }
    uVar1 = 0xffffffff;
  }
  return uVar1;
}

void CPS_SetScavengerCallback(void (*param_1)(void))
{
  scavenger_callback = param_1;
  return;
}

void CPS_SetThreadPriority(u32 param_1)
{
  helper_threads_priority = param_1;
  //OS_SetThreadPriority(&tcpip_thread,param_1);
  //OS_SetThreadPriority(&scavenger_thread,param_1);
  return;
}

void CPS_SetUdpCallback(int (*aCallback)(u8 *, u32, CPSSoc *))
{
  OSThread * myThread = OS_GetCurrentThread();
  int iVar2;
  CPSSoc * mySoc = OSi_GetSpecificData(myThread,0);
  
  if (mySoc != NULL) {
    //*(undefined4 *)(iVar2 + 0x38) = param_1;
    mySoc->udpread_callback = aCallback;
  }
  return;
}

//void CPS_SocBind(int param_1,undefined2 param_2,unsigned_long param_3)
void CPS_SocBind(u16 local_port, u16 remote_port, CPSInAddr remote_ip)
{
  undefined2 uVar1;
  undefined4 uVar2;
  int iVar3;
  OSThread * thread;
  CPSSoc * mySoc;
  
  //uVar2 = OS_GetCurrentThread();
  thread = OS_GetCurrentThread();
  //iVar3 = OSi_GetSpecificData(uVar2,0);
  mySoc = OSi_GetSpecificData(thread,0);
  //if (iVar3 != 0) {
  if(mySoc != 0) {
    if (remote_ip == 0x7f000001) { /* 127.0.0.1 */
      remote_ip = CPSMyIp;
    }
    #ifndef SDK_BUILD_ARM
    // Bail if the socket is already bound
    if(mySoc->remote_port_bound == remote_port && mySoc->remote_ip_bound == remote_ip 
      && (local_port != 0 && local_port == mySoc->local_port)) {
      return;
    }
    #endif
    //*(undefined2 *)(iVar3 + 0x1a) = remote_port;
    mySoc->remote_port_bound = remote_port;
    //*(undefined2 *)(iVar3 + 0x18) = *(undefined2 *)(iVar3 + 0x1a);
    mySoc->remote_port = mySoc->remote_port_bound;
    //*(unsigned_long *)(iVar3 + 0x20) = remote_ip;
    mySoc->remote_ip_bound = remote_ip;
    //*(undefined4 *)(iVar3 + 0x1c) = *(undefined4 *)(iVar3 + 0x20);
    mySoc->remote_ip = mySoc->remote_ip_bound;
    if (local_port == 0) {
      uVar1 = CPS_SocGetEport();
      //*(undefined2 *)(iVar3 + 10) = uVar1;
      mySoc->local_port = uVar1;
    }
    else {
      //*(short *)(iVar3 + 10) = (short)local_port;
      mySoc->local_port = local_port;
    }

    SDL_LockMutex(s_SocketThreadStartupMutex);
    if(WIN_socThread != NULL) {
      //pthread_cancel(WIN_socPthread);
      //pthread_cancel(SDL_GetThreadID(WIN_socThread));
      s_stopSocThread = 1;
      SDL_WaitThread(WIN_socThread, NULL);
      s_stopSocThread = 0;
      WIN_socThread = NULL;
    }

    struct sockaddr_in remote;
    #ifdef SDK_BUILD_WIN64
    remote.sin_addr.S_un.S_addr = ADDR_ANY;
    #endif
    #ifdef SDK_BUILD_LINUX
    remote.sin_addr.s_addr = INADDR_ANY;
    #endif
    remote.sin_family = AF_INET;
    if(local_port == 0) {
      remote.sin_port = htons(uVar1);
    } else {
      remote.sin_port = htons(local_port);
    }

    // Always close the socket when binding since CPS supports rebinding existing sockets 
    // and linux does not
    if(mySoc->WIN_socket != 0) {
      printf("Closing socket %d\n", mySoc->WIN_socket);
      #ifdef SDK_BUILD_WIN64
      closesocket(mySoc->WIN_socket);
      #endif
      #ifdef SDK_BUILD_LINUX
      close(mySoc->WIN_socket);
      #endif
      mySoc->WIN_socket = 0;
    }

    if(mySoc->state == 10) {
      // UDP
      #ifdef SDK_BUILD_WIN64
      mySoc->WIN_socket = socket(AF_INET, SOCK_DGRAM, 0);
      char setting = 1;
      setsockopt(mySoc->WIN_socket, SOL_SOCKET, SO_REUSEADDR, &setting, sizeof(int));
      #endif
      #ifdef SDK_BUILD_LINUX
      mySoc->WIN_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
      setsockopt(mySoc->WIN_socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
      #endif
    } else {
      // TCP
      #ifdef SDK_BUILD_WIN64
      mySoc->WIN_socket = socket(AF_INET, SOCK_STREAM, 0);
      #endif
      #ifdef SDK_BUILD_LINUX
      mySoc->WIN_socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
      #endif
    }

    int status;

    CreateSocketEvent(mySoc);
    #ifdef SDK_BUILD_WIN64
    status = WSAEventSelect(mySoc->WIN_socket, WIN_EventArray[WIN_EventTotal - 1], FD_READ | FD_ACCEPT | FD_CLOSE);
    if( status == SOCKET_ERROR ) {
      printf("WSAEventSelect Error: %d\n", WSAGetLastError());
    }
    #endif

    status = bind(mySoc->WIN_socket, (struct sockaddr *)&remote, sizeof( remote ));
    #ifdef SDK_BUILD_WIN64
    if( status == SOCKET_ERROR ) {
      printf("network.c WinError: %d\n", WSAGetLastError());
    }
    #endif
    #ifdef SDK_BUILD_LINUX
    if(status != 0) {
      printf("network.c Socket Error during bind() %d. RemotePort %d\n", errno, mySoc->remote_port);
    } else {
      printf("SOC: Socket %d bind. RemotePort %d\n", mySoc->WIN_socket, mySoc->remote_port);
    }
    #endif

    WIN_socThread = SDL_CreateThread(WIN_CPS_SocThreadFunc, "CPS_SocThreadFunc", NULL);
    SDL_UnlockMutex(s_SocketThreadStartupMutex);
  }
  return;
}

void CPS_SocConsume(u32 len)
{
  undefined4 uVar1;
  OSThread * curThread;
  int iVar2;
  
  //uVar1 = OS_GetCurrentThread();
  curThread = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  CPSSoc * mySoc = OSi_GetSpecificData(curThread,0);
  if (mySoc != 0) {
    if (mySoc->ssl == 0) {
      CPSi_SocConsumeRaw(len,mySoc);
    } else {
      CPSi_SslConsume(len,mySoc);
    }
  }
  return;
}

void CPS_SocDatagramMode(void)
{
  undefined4 uVar1;
  int iVar2;
  OSThread * thread;
  CPSSoc * mySoc;
  
  //uVar1 = OS_GetCurrentThread();
  thread = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  mySoc = OSi_GetSpecificData(thread,0);
  
  //if (iVar2 != 0) {
  if(mySoc != NULL){
    //*(undefined *)(iVar2 + 8) = 10;
    mySoc->state = 10;
    //*(undefined4 *)(iVar2 + 0x44) = 0;
    mySoc->rcvbufp = 0;

    //#ifdef SDK_BUILD_WIN64
    //mySoc->WIN_socket = socket(AF_INET, SOCK_DGRAM, 0);
    //#endif
    //#ifdef SDK_BUILD_LINUX
    //mySoc->WIN_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    //#endif
  }
  return;
}

void CPS_SocDup(OSThread * aThread)
{
  undefined4 uVar1;
  
  //uVar1 = OS_GetCurrentThread();
  OSThread * myThread = OS_GetCurrentThread();
  //uVar1 = OSi_GetSpecificData(uVar1,0);
  CPSSoc * mySoc = OSi_GetSpecificData(myThread,0);
  OSi_SetSpecificData(aThread,0,mySoc);
  return;
}

void CPS_SocFlush(void)
{
  undefined4 uVar1;
  int iVar2;
  
  OSThread * myThread;
  CPSSoc * mySoc;

  //uVar1 = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);

  myThread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(myThread, 0);


  if ((mySoc != NULL) && (mySoc->outbufp != 0)) {
    //CPSi_SocWrite2(*(undefined4 *)(iVar2 + 0x5c),*(undefined4 *)(iVar2 + 0x60),0,0);
    CPSi_SocWrite2(mySoc->outbuf.data, mySoc->outbufp, NULL, 0);
    //*(undefined4 *)(iVar2 + 0x60) = 0;
    mySoc->outbufp = 0;
  }
  return;
}

int CPS_SocGetChar(void)
{
  byte *pbVar1;
  uint uVar2;
  undefined4 in_r3;
  undefined4 uStack_10;
  
  uStack_10 = in_r3;
  //pbVar1 = (byte *)CPS_SocRead(&uStack_10);
  if (pbVar1 == (byte *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = (uint)*pbVar1;
    CPS_SocConsume(1);
  }
  return uVar2;
}

u16 CPS_SocGetEport(void)
{
  BOOL bVar1;
  int iVar2;
  int *piVar3;
  OSThread * thread;
  CPSSoc * mySoc;

  
  do {
    bVar1 = FALSE;
    eport = eport + 1;
    if (eport < 0x400) {
LAB_00015268:
      eport = 0x400;
    }
    else if (4999 < eport) goto LAB_00015268;
    
    //for (iVar2 = OS_GetThreadList(); iVar2 != 0; iVar2 = OS_GetNextThread(iVar2)) {
    for( thread = OS_GetThreadList(); thread != NULL; thread = OS_GetNextThread(thread)) {
      //piVar3 = (int *)OSi_GetSpecificData(iVar2,0);
      mySoc = OSi_GetSpecificData(thread,0);
    //  if (((piVar3 != (int *)0x0) && (*piVar3 != 0)) &&
      if(((mySoc != NULL) && (mySoc->thread != NULL)) &&
    //     (*(unsigned_short *)((int)piVar3 + 10) == eport)) {
           mySoc->local_port == eport) {
           bVar1 = TRUE;
           break;
         }
    }
    if (!bVar1) {
      return eport;
    }
  } while( TRUE );
}

s32 CPS_SocGetLength(void)
{
  OSThread * thread; /* uVar1 */
  CPSSoc * soc; /* iVar2 */
  int iVar3;
  
  thread = OS_GetCurrentThread();
  soc = OSi_GetSpecificData(thread,0);
  if (soc == NULL) {
    iVar3 = 0;
  } else if /*(*(char *)(soc + 9) == '\0')*/(soc->ssl == 0) {

    #ifdef SDK_PORT
    //Try to receive data from the socket
    //struct sockaddr_in server;
    //server.sin_family = AF_INET;
    //server.sin_port = htons(soc->remote_port);
    //server.sin_addr.S_un.S_addr = soc->remote_ip;
//
    //int sz = sizeof(server);
//
    //int numBytes = recvfrom(soc->WIN_socket, soc->rcvbuf.data + soc->rcvbufp, soc->rcvbuf.size - soc->rcvbufp, 0, (struct sockaddr *)&server, &sz);
    //if( numBytes == SOCKET_ERROR ) {
    //  if(WSAGetLastError() != WSAEWOULDBLOCK) {
    //    printf("network.c WinError: %d", WSAGetLastError());
    //  }
    //} else {
    //  soc->rcvbufp += numBytes;
    //}
    #endif
    //iVar3 = *(int *)(soc + 0x44);
    iVar3 = soc->rcvbufp;
    //if ((((iVar3 == 0) && (*(char *)(soc + 8) != '\x04')) && (*(char *)(soc + 8) != '\n')) &&
    //   (*(char *)(soc + 8) != '\v')) {
    if(((iVar3 == 0) && (soc->state != CPS_STT_ESTABLISHED)) && (soc->state != CPS_STT_DATAGRAM) && (soc->state != CPS_STT_PING)){
      iVar3 = -1;
    }
  } else {
    iVar3 = CPSi_SslGetLength(soc);
  }
  return iVar3;
}

u8 * CPS_SocGets(void)
{
  BOOL bVar1;
  undefined4 uVar2;
  int iVar3;
  char *pcVar4;
  undefined4 in_r3;
  undefined *puVar5;
  uint uVar6;
  int iVar7;
  char *pcVar8;
  uint uVar9;
  uint local_2c [2];
  undefined4 uStack_24;
  
  uStack_24 = in_r3;
  //uVar2 = OS_GetCurrentThread();
  //iVar3 = OSi_GetSpecificData(uVar2,0);
  if ((iVar3 == 0) || (*(int *)(iVar3 + 0x54) == 0)) {
LAB_00016394:
    uVar2 = 0;
  }
  else {
    CPS_SocFlush();
    puVar5 = *(undefined **)(iVar3 + 0x54);
    iVar7 = 0;
    bVar1 = FALSE;
    do {
     // pcVar4 = (char *)CPS_SocRead(local_2c);
      if (pcVar4 == (char *)0x0) goto LAB_00016394;
      pcVar8 = pcVar4;
      for (uVar6 = 0; uVar6 < local_2c[0]; uVar6 = uVar6 + 1) {
        if (*pcVar8 == '\r') {
          iVar7 = 1;
          break;
        }
        pcVar8 = pcVar8 + 1;
      }
      uVar9 = *(int *)(iVar3 + 0x50) - ((int)puVar5 - *(int *)(iVar3 + 0x54));
      if (uVar9 <= uVar6) {
        uVar6 = uVar9 - 1;
        iVar7 = 0;
        bVar1 = TRUE;
      }
      MI_CpuCopy8(pcVar4,puVar5,uVar6);
      CPS_SocConsume(uVar6 + iVar7);
      puVar5 = puVar5 + uVar6;
      if (bVar1) {
        *puVar5 = 0;
        //return *(undefined4 *)(iVar3 + 0x54);
        return NULL;
      }
    } while (iVar7 == 0);
    iVar7 = CPS_SocGetChar();
    if (iVar7 == -1) {
      uVar2 = 0;
    }
    else {
      *puVar5 = 0;
      uVar2 = *(undefined4 *)(iVar3 + 0x54);
    }
  }
  //return uVar2;
  return NULL;
}

void CPS_SocPingMode(void)
{
  OSThread * myThread;
  CPSSoc * mySoc;

  myThread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(myThread, 0);
  if (mySoc != NULL) {
    mySoc->state = CPS_STT_PING;
    mySoc->rcvbufp = 0;
  }
  return;
}

void CPS_SocPrintf(const char *format, ...)
{
  char cVar1;
  int *piVar2;
  char *pcVar3;
  char local_50 [8];
  int *local_48;
  char acStack_44 [32];
  undefined4 local_24;
  int local_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  local_48 = &local_c;
  //local_24 = param_4;
  //local_c = param_2;
  //uStack_8 = param_3;
  //uStack_4 = param_4;
  //while( TRUE ) {
  //  pcVar3 = param_1 + 1;
  //  cVar1 = *param_1;
  //  if (cVar1 == '\0') break;
  //  if (cVar1 == '%') {
  //    if (*pcVar3 == '%') {
  //      CPS_SocPutChar(0x25);
  //      param_1 = param_1 + 2;
  //    }
  //    else {
  //      param_1 = (char *)analyze_format(pcVar3,local_50);
  //      if (local_50[0] == 's') {
  //        piVar2 = local_48 + 1;
  //        pcVar3 = (char *)*local_48;
  //        local_48 = piVar2;
  //        if (pcVar3 == (char *)0x0) {
  //          pcVar3 = _16774;
  //        }
  //      }
  //      else {
  //        handle_arg(acStack_44,local_50,&local_48);
  //        pcVar3 = acStack_44;
  //      }
  //      CPS_SocPuts(pcVar3);
  //    }
  //  }
  //  else {
  //    CPS_SocPutChar((int)cVar1);
  //    param_1 = pcVar3;
  //  }
  //}
  return;
}

void CPS_SocPutChar(char param_1)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  //uVar1 = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  if ((iVar2 != 0) && (*(int *)(iVar2 + 0x5c) != 0)) {
    iVar3 = *(int *)(iVar2 + 0x60);
    *(int *)(iVar2 + 0x60) = *(int *)(iVar2 + 0x60) + 1;
    *(undefined *)(*(int *)(iVar2 + 0x5c) + iVar3) = param_1;
    if (*(int *)(iVar2 + 0x60) == *(int *)(iVar2 + 0x58)) {
      CPS_SocFlush();
    }
  }
  return;
}

void CPS_SocPuts(char *param_1)
{
  while( TRUE ) {
    if (*param_1 == 0) break;
    CPS_SocPutChar((int)*param_1);
    param_1 = param_1 + 1;
  }
  return;
}

u8 * CPS_SocRead(u32 *len)
{
  undefined4 uVar1;
  OSThread * thread;
  //int iVar2;
  CPSSoc * mySoc;

  u8 * ptr;
  
  thread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(thread,0);
  if (mySoc == NULL) {
    *len = 0;
    ptr = NULL;
  } else if ((mySoc->state == 10) || (mySoc->state == 11)) {
    ptr = udp_read_raw(len, mySoc);
  } else if (mySoc->ssl == 0) {
    ptr = CPSi_TcpReadRaw(len, mySoc);
  } else {
    ptr = CPSi_SslRead(len,mySoc);
  }
  return ptr;
  //return uVar1;
  //return NULL;
}

void CPS_SocRegister(CPSSoc * aSoc)
{
  undefined4 uVar1;
  OSThread * thread;
  
  //uVar1 = OS_GetCurrentThread();
  thread = OS_GetCurrentThread();
  //OSi_SetSpecificData(uVar1,0,aSoc);
  OSi_SetSpecificData(thread,0,aSoc);
  #ifdef SDK_PORT
  aSoc->WIN_socket = 0;
  //aSoc->WIN_socket = 0;
  aSoc->WIN_pthread = 0;
  #endif
  return;
}

void CPS_SocRelease(void)
{
  //undefined4 uVar1;
  OSThread * thread;
  //undefined4 *puVar2;
  CPSSoc * mySoc;
  
  //uVar1 = OS_GetCurrentThread();
  thread = OS_GetCurrentThread();
  //puVar2 = (undefined4 *)OSi_GetSpecificData(uVar1,0);
  mySoc = OSi_GetSpecificData(thread,0);



  if(mySoc != NULL) {
    SDL_LockMutex(s_SocketThreadStartupMutex);
    if(WIN_socThread != 0) {
      //pthread_cancel(SDL_GetThreadID(WIN_socThread));
      s_stopSocThread = 1;
      SDL_WaitThread(WIN_socThread, NULL);
      s_stopSocThread = 0;
      WIN_socThread = 0;
    }
    SDL_UnlockMutex(s_SocketThreadStartupMutex);

    #ifdef SDK_BUILD_WIN64
    SDL_LockMutex(s_SocketSharedMutex);
    WIN_EventArray[mySoc->WIN_eventArrayNum] = WIN_EventArray[WIN_EventTotal - 1];
    WIN_EventArray[WIN_EventTotal - 1] = NULL;

    WIN_EventTotal = WIN_EventTotal - 1;
    SDL_UnlockMutex(s_SocketSharedMutex);
    closesocket(mySoc->WIN_socket);
    #endif
    //TODO: We probably want to make the WIN_SocketArray threadsafe
  #ifndef SDK_BUILD_ARM
    mySoc->remote_port_bound = 0;
    mySoc->remote_ip_bound = 0;
  #endif
    #ifdef SDK_BUILD_LINUX
    SDL_LockMutex(s_SocketSharedMutex);
    for(int i=0; i < MAX_NUM_OPEN_SOCKETS; i++) {
      if(WIN_SocketArray[i] == mySoc) {
        WIN_SocketArray[i] = NULL;
        WIN_SocketTotal -= 1;
      }
    }
    SDL_UnlockMutex(s_SocketSharedMutex);
    close(mySoc->WIN_socket);
    printf("SOC: Socket %d unbind.\n", mySoc->WIN_socket);
    #endif


    mySoc->WIN_socket = 0;


    #ifdef SDK_BUILD_WIN64
    SDL_LockMutex(s_SocketThreadStartupMutex);
    if(WIN_EventTotal > 0) {
      WIN_socThread = SDL_CreateThread( WIN_CPS_SocThreadFunc, "CPS_SocThread", NULL );
    }
    SDL_UnlockMutex(s_SocketThreadStartupMutex);
    #endif
    #ifdef SDK_BUILD_LINUX
    SDL_LockMutex(s_SocketThreadStartupMutex);
    if(WIN_SocketTotal > 0 && WIN_socThread == NULL) {
      WIN_socThread = SDL_CreateThread( WIN_CPS_SocThreadFunc, "CPS_SocThread", NULL );
    }
    SDL_UnlockMutex(s_SocketThreadStartupMutex);
    #endif
  }

  //mySoc->WIN_socket = 0;

  if (mySoc != NULL) {
    //*puVar2 = 0;
  }
  return;
}

void CPS_SocUnRegister(void)
{
  undefined4 uVar1;
  
  //uVar1 = OS_GetCurrentThread();
  //OSi_SetSpecificData(uVar1,0,0);
  return;
}

void CPS_SocUse(void)
{
  undefined4 uVar1;
  undefined4 *puVar2;

  OSThread * thread;

  CPSSoc * mySoc;
  
  //uVar1 = OS_GetCurrentThread();
  thread = OS_GetCurrentThread();
  //puVar2 = (undefined4 *)OSi_GetSpecificData(uVar1,0);
  mySoc = OSi_GetSpecificData(thread,0);
  //if (puVar2 != (undefined4 *)0x0) {
  if( mySoc != NULL ) {
    //uVar1 = OS_GetCurrentThread();
    //*puVar2 = uVar1;
    mySoc->thread = thread;
    //*(undefined *)(puVar2 + 2) = 0;
    mySoc->state = 0;
    mySoc->ssl = 0;
    mySoc->local_port = 0;
    //puVar2[0x11] = 0;
    mySoc->rcvbufp = 0;
    //puVar2[0x18] = 0;
    mySoc->outbufp = 0;
    //puVar2[0xe] = 0;
    mySoc->udpread_callback = NULL;
  }
  return;
}

CPSInAddr CPS_SocWho(u16 *remote_port, CPSInAddr *local_ip)
{
  CPSInAddr addr;

  OSThread * myThread;
  CPSSoc * mySoc;
  
  myThread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(myThread, 0);
  if ((mySoc == NULL) || ((mySoc->state != CPS_STT_ESTABLISHED && (mySoc->state != CPS_STT_DATAGRAM)))) {
    addr = 0;
  } else {
    if (remote_port != NULL) {
      *remote_port = mySoc->remote_port;
    }
    if(local_ip != NULL) {
      *local_ip = mySoc->local_ip_real;
    }
    addr = mySoc->remote_ip;
  }
  return addr;
}

u32 CPS_SocWrite(u8 *buf, u32 len)
{
  //undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;

  OSThread * thread;
  CPSSoc * mySoc;
  
  thread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(thread,0);
  if (mySoc == NULL) {
    iVar4 = 0;
  } else if (/**(int *)(mySoc + 0x60)*/mySoc->outbufp == 0) {
    //iVar4 = CPSi_SocWrite2(param_1,param_2,0,0,param_4);
    iVar4 = CPSi_SocWrite2(buf, len, NULL, 0);
  } else {
    //uVar3 = CPSi_SocWrite2(*(undefined4 *)(mySoc + 0x5c),*(undefined4 *)(mySoc + 0x60),param_1,
    //                       param_2,param_4);
    uVar3 = CPSi_SocWrite2(mySoc->outbuf.data, mySoc->outbufp, buf, len);
    //if (uVar3 < *(uint *)(mySoc + 0x60)) {
    if( uVar3 < mySoc->outbufp ) {
      //memmove(*(void **)(mySoc + 0x5c),(void *)(*(int *)(mySoc + 0x5c) + uVar3),
      //        *(int *)(mySoc + 0x60) - uVar3);
      memmove(mySoc->outbuf.data, mySoc->outbuf.data + uVar3, mySoc->outbufp - uVar3);
      //*(int *)(mySoc + 0x60) = *(int *)(mySoc + 0x60) - uVar3;
      mySoc->outbufp = mySoc->outbufp - uVar3;
      iVar4 = 0;
    } else {
      //iVar4 = uVar3 - *(int *)(mySoc + 0x60);
      iVar4 = uVar3 - mySoc->outbufp;
      //*(undefined4 *)(mySoc + 0x60) = 0;
      mySoc->outbufp = 0;
    }
  }
  return iVar4;
}

void CPS_Startup(CPSConfig * aCpsConfig)
{
  short sVar1;
  u64 uVar2;

  #ifndef SDK_BUILD_ARM
  s_SocketSharedMutex = SDL_CreateMutex();
  s_SocketThreadStartupMutex = SDL_CreateMutex();
  #endif
  
  //OSi_ReferSymbol(id_string);
  if(aCpsConfig->random_seed == 0) {
    uVar2 = OS_GetTick();
    MATH_InitRand32(&CPSiRand32ctx,uVar2);
  } else {
    MATH_InitRand32(&CPSiRand32ctx, aCpsConfig->random_seed);
  }

  if(aCpsConfig->alloc == NULL || aCpsConfig->free == NULL) {
    OSi_TWarning("network.c",0x13d,"alloc/free must be given\n");
    CPSiAlloc = (void*)empty_func;
    CPSiFree = (void*)empty_func;
  } else {
    CPSiAlloc = aCpsConfig->alloc;
    CPSiFree = aCpsConfig->free;
  }

  mode = aCpsConfig->mode;
  if(aCpsConfig->mymss == 0) {
    mymss = 0x5b4;
  } else {
    mymss = aCpsConfig->mymss;
  }

  offered_myip = aCpsConfig->requested_ip;
  yield_wait = aCpsConfig->yield_wait;
  if (aCpsConfig->dhcp_callback == NULL) {
   dhcp_callback = (void*)empty_func;
  } else {
    //dhcp_callback = (_func_void *)param_1[3];
    dhcp_callback = aCpsConfig->dhcp_callback;
  }
  
  if (aCpsConfig->link_is_on == NULL) {
    link_is_on = default_link_is_on;
  } else {
    //link_is_on = (_func_int *)param_1[4];
    link_is_on = aCpsConfig->link_is_on;
  }

  wlan_buf = (u8*)aCpsConfig->lan_buf;
  wlan_buflen = aCpsConfig->lan_buflen;
  wlan_getpnt = 0;
  wlan_putpnt = 0;
  if( wlan_buf == NULL || wlan_buflen == 0 ) {
    OSi_TWarning("network.c",0x157,"Ring buffer must be given\n");
  }
  sVar1 = MATH_Rand32(&CPSiRand32ctx,0xf88);
  eport = sVar1 + 0x400;
  OS_GetMacAddress(CPSMyMac);
  ip_conflict = 0;

  #ifndef SDK_BUILD_ARM
  // Setup CPSMyIp

  #ifdef SDK_BUILD_LINUX
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in *sa;
  char *addr;

  getifaddrs (&ifap);
  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr && ifa->ifa_addr->sa_family==AF_INET) {
          sa = (struct sockaddr_in *) ifa->ifa_addr;
          //addr = inet_ntoa(sa->sin_addr);
          printf("Interface: %s\tAddress: %d\n", ifa->ifa_name, sa->sin_addr);
          if(strcmp(ifa->ifa_name, "lo") != 0) {
            CPSMyIp = CPS_htonl(sa->sin_addr.s_addr);
            break;
          }
      }
  }

  freeifaddrs(ifap);
  #endif
  #if SDK_BUILD_WIN64

  HOSTENT *hp=NULL;
  struct sockaddr_in source;
  char hostname[128];

  gethostname(hostname, 128);
  hp = gethostbyname(hostname);

  if(hp == NULL)
  {
    printf("Local gethostbyname failed: %d\n", WSAGetLastError());
  }

  memcpy(&(source.sin_addr),hp->h_addr,hp->h_length);
  source.sin_family = hp->h_addrtype;

  printf("Local IP Address %s\n", inet_ntoa(source.sin_addr));
  CPSMyIp = CPS_htonl(source.sin_addr.s_addr);
  #endif
  #endif


  #ifdef SDK_PORT
  //OS_CreateThread(&tcpip_thread, tcpip, 0,win_tcpip_thread_stack, 0x800, helper_threads_priority);
  //OS_CreateThread(&scavenger_thread, scavenger, 0,win_scavenger_thread_stack, 0x800, helper_threads_priority);
  #else
  //OS_CreateThread(&tcpip_thread,tcpip,0,reset_network_vars,0x800,helper_threads_priority);
  OS_CreateThread(&tcpip_thread, tcpip, 0,reset_network_vars, 0x800, helper_threads_priority);
  //OS_CreateThread(&scavenger_thread,scavenger,0,tcpip_stack,0x800,helper_threads_priority);
  OS_CreateThread(&scavenger_thread, scavenger, 0,tcpip_stack, 0x800, helper_threads_priority);
  OS_WakeupThreadDirect(&tcpip_thread);
  OS_WakeupThreadDirect(&scavenger_thread);
  #endif

  return;
}

void CPS_TcpAck(void)
{
  undefined4 uVar1;
  int iVar2;
  
  //uVar1 = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  if (iVar2 != 0) {
    //tcp_send_ack(iVar2,0x1c);
  }
  return;
}

void CPS_TcpClose(void)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;

  OSThread * myThread;
  CPSSoc * mySoc;
  
  //uVar1 = OS_GetCurrentThread();
  myThread = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  mySoc = OSi_GetSpecificData(myThread, 0);


  if (mySoc != 0) {
    if (/**(char *)(iVar2 + 9) != '\0'*/mySoc->ssl) {
      //CPSi_SslClose(mySoc);
    }
    iVar3 = CPSi_GetTick();
    //while ((iVar4 = (*link_is_on)(), iVar4 != 0 && (*(char *)(iVar2 + 8) != '\0'))) {
    //  iVar4 = CPSi_GetTick();
    //  if (0x26 < iVar4 - iVar3) break;
    //  //OS_YieldThread__();
    //}
    //*(undefined *)(iVar2 + 8) = 0;
    mySoc->state = 0;
    
#ifdef SDK_BUILD_WIN64
    if(closesocket(mySoc->WIN_socket) == SOCKET_ERROR) {
      printf("CPS_TcpClose WinError: %d\n", WSAGetLastError());
    }
#endif
  }
  return;
}

u32 CPS_TcpConnect(void)
{
  OSThread * myThread;
  CPSSoc * mySoc;
  u32 ret;
  
  myThread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(myThread, 0);
  if (mySoc == 0) {
    ret = 1;
  } else if (mySoc->ssl == 0) {
    ret = CPSi_TcpConnectRaw(mySoc);
  } else {
    ret = CPSi_SslConnect(mySoc);
  }
  return ret;
}

void CPS_TcpListen(void)
{
  OSThread * myThread;
  CPSSoc * mySoc;
  
  myThread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(myThread, 0);
  if (mySoc != 0) {
    if (mySoc->ssl == 0) {
      CPSi_TcpListenRaw(mySoc);
    } else {
      CPSi_SslListen(mySoc);
    }
  }
  return;
}

void CPS_TcpShutdown(void)
{
  //undefined4 uVar1;
  OSThread * myThread;
  //int iVar2;
  CPSSoc * mySoc;
  
  //uVar1 = OS_GetCurrentThread();
  myThread = OS_GetCurrentThread();
  //iVar2 = OSi_GetSpecificData(uVar1,0);
  mySoc = OSi_GetSpecificData(myThread, 0);
  if (mySoc != 0) {
    if (mySoc->ssl != 0) {
      CPSi_SslShutdown(mySoc);
    }
    CPSi_TcpShutdownRaw(mySoc);
  }
  return;
}

/*---------------------------------------------------------------------------*
 *
 * CPS Shared Internal Procedures
 * 
 *---------------------------------------------------------------------------*/

void CPSi_RecvCallbackFunc
               ()
{
  int iVar1;
  
  //put_in_buffer(param_1,param_2,param_3,param_4,0,0,param_4);
  //if ((receiver_thread != (_OSThread *)0x0) &&
  //   (iVar1 = OS_IsThreadTerminated(receiver_thread), iVar1 == 0)) {
  //  OS_WakeupThreadDirect(receiver_thread);
  //}
  return;
}

void CPSi_SocConsumeRaw(u32 len, CPSSoc *soc)
{
  BOOL bVar1;
  undefined4 uVar2;
  size_t __n;
  uchar *__dest;
  
  uVar2 = OS_DisableInterrupts();
  bVar1 = FALSE;
  if ((soc->rcvbufp == (soc->rcvbuf).size) && (len != 0)) {
    bVar1 = TRUE;
  }
  if (len < soc->rcvbufp) {
    __dest = (soc->rcvbuf).data;
    __n = soc->rcvbufp - len;
    soc->rcvbufp = __n;
    memmove(__dest,__dest + len,__n);
  }
  else {
    soc->rcvbufp = 0;
  }
  OS_RestoreInterrupts(uVar2);
  if (((soc->state != 10) && (soc->state != 11)) && ((soc->rcvbufp == 0 || (bVar1)))) {
    //tcp_send_ack(soc,0x1b);
  }
  return;
}

u32 CPSi_SocWrite2(u8 *buf, u32 len, u8 *buf2, u32 len2)
{
  OSThread * thread;
  CPSSoc * mySoc;
  undefined4 uVar1;
  int iVar2;
  
  thread = OS_GetCurrentThread();
  mySoc = OSi_GetSpecificData(thread,0);
  if (mySoc != NULL) {
    if (/**(char *)(mySoc + 8) == '\n'*/mySoc->state == CPS_STT_DATAGRAM) {
      if (len != 0) {
        send_udp(buf,len,mySoc);
      }
      if (len2 != 0) {
        send_udp(buf2,len2,mySoc);
      }
      len = len + len2;
    } else if (/**(char *)(mySoc + 8) == '\v'*/mySoc->state == CPS_STT_PING) {
      if (len != 0) {
        //send_ping(buf,len,mySoc);
      }
      if (len2 != 0) {
        //send_ping(buf2,len2,mySoc);
      }
      len = len + len2;
    } else if (mySoc->ssl == 0) {
      len = CPSi_TcpWrite2Raw(buf, len, buf2, len2, mySoc);
    } else {
      len = CPSi_SslWrite2(buf, len, buf2, len2, mySoc);
    }
    //if (wfailed == '\0') {
    //  return len;
    //}
  }
  return len;
}

u32 CPSi_TcpConnectRaw(CPSSoc *soc)
{
#if (defined(SDK_BUILD_WIN64) || defined(SDK_BUILD_LINUX))
  struct sockaddr_in theSockaddr;

  theSockaddr.sin_family = AF_INET;
  theSockaddr.sin_addr.s_addr = soc->remote_ip;
  theSockaddr.sin_port = htons(soc->remote_port);

  u8 loop = TRUE;

  #ifdef SDK_BUILD_WIN64
  FD_SET WriteSet;
  #endif
  #ifdef SDK_BUILD_LINUX
  fd_set WriteSet;
  #endif
  int peerNameLen = sizeof(theSockaddr);

  while(TRUE) {
    FD_ZERO(&WriteSet);

    FD_SET(soc->WIN_socket, &WriteSet);

    #ifdef SDK_BUILD_WIN64
    if(connect(soc->WIN_socket, (SOCKADDR*)&theSockaddr, sizeof(theSockaddr)) == SOCKET_ERROR && WSAGetLastError() != 10035) {
      printf("CPSi_TcpConnectRaw WinError %d\n", WSAGetLastError());
    }

    if(select(0, NULL, &WriteSet, &WriteSet, NULL) == SOCKET_ERROR) {
      printf("CPSi_TcpConnectRaw select WinError %d\n", WSAGetLastError());
    }
    #endif
    #ifdef SDK_BUILD_LINUX
    int connectStatus = connect(soc->WIN_socket, (struct sockaddr *)&theSockaddr, sizeof(theSockaddr));
    if(connectStatus != 0 && errno != EINPROGRESS) {
      printf("CPSi_TcpConnectRaw socket error: %d\n", errno);
    }

    int selectStatus = select(soc->WIN_socket+1, NULL, &WriteSet, &WriteSet, NULL);
    if(selectStatus < 0) {
      printf("CPSi_TcpConnectRaw socket error: %d\n", errno);
    }
    #endif

    if(
      #ifdef SDK_BUILD_WIN64
      getpeername(soc->WIN_socket, (SOCKADDR*)&theSockaddr, &peerNameLen) == SOCKET_ERROR
      #endif
      #ifdef SDK_BUILD_LINUX
      getpeername(soc->WIN_socket, (struct sockaddr *)&theSockaddr, &peerNameLen) != 0
      #endif
      ) {
      // Connection failed, retry
      #ifdef SDK_BUILD_WIN64
      Sleep(1);
      #endif
    } else {
      // Connection success
      soc->state = CPS_STT_ESTABLISHED;

      //printf("End of CPSi_TcpConnectRaw\n");
      break;
    }
  }

#else
  //undefined4 uVar1;
  //undefined4 uVar2;
  //uint uVar3;
  //
  //uVar1 = get_seqno();
  //uVar3 = 0;
  //while( TRUE ) {
  //  if (2 < uVar3) {
  //    return 1;
  //  }
  //  *(undefined4 *)(param_1 + 0x28) = uVar1;
  //  *(undefined *)(param_1 + 8) = 2;
  //  uVar2 = CPSi_GetTick();
  //  *(undefined4 *)(param_1 + 0x10) = uVar2;
  //  tcp_send_handshake(param_1,2,0x18);
  //  uVar2 = OS_DisableInterrupts();
  //  if ((*(char *)(param_1 + 8) == '\x02') && (CPSMyIp != 0)) {
  //    *(undefined4 *)(param_1 + 4) = 1;
  //    OS_SleepThread(0);
  //  }
  //  OS_RestoreInterrupts(uVar2);
  //  if (*(char *)(param_1 + 8) == '\x04') break;
  //  //if (CPSMyIp == 0) {
  //  //  return 1;
  //  //}
  //  uVar3 = uVar3 + 1;
  //}
  #endif
  return 0;
}


void CPSi_TcpListenRaw(CPSSoc *soc)
{
  undefined4 uVar1;
  
  //uVar1 = get_seqno();
  //*(undefined4 *)(param_1 + 0x28) = uVar1;
  //*(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0x28);
  //*(undefined *)(param_1 + 8) = 1;
  //uVar1 = OS_DisableInterrupts();
  //*(undefined4 *)(param_1 + 4) = 1;
  //OS_SleepThread(0);
  //OS_RestoreInterrupts(uVar1);
  return;
}

u8 *CPSi_TcpReadRaw(u32 *len, CPSSoc *soc)
{
  undefined4 uVar1;
  u8 * retPtr;


  if(soc->rcvbufp == 0 && soc->state == CPS_STT_ESTABLISHED) {
    uVar1 = OS_DisableInterrupts();
    while(soc->rcvbufp == 0 && soc->state == CPS_STT_ESTABLISHED) {
      soc->block_type = CPS_BLOCK_TCPREAD;
      OS_SleepThread(0);
    }
    OS_RestoreInterrupts(uVar1);

  } else {
    OS_YieldThread();
  }
  *len = soc->rcvbufp;
  if(*len == 0) {
    retPtr = NULL;
  } else {
    retPtr = soc->rcvbuf.data;
  }
  return retPtr;
}

void CPSi_TcpShutdownRaw(CPSSoc *soc)
{
  //OS_YieldThread();
  //if ((*(char *)(soc + 8) == '\x04') || (*(char *)(soc + 8) == '\x03')) {
  //  tcp_send_finack(soc,0x19);
  //  *(undefined *)(soc + 8) = 7;
  //}
  //else if (*(char *)(soc + 8) != '\0') {
  //  tcp_send_ack(soc,0x1a);
  //}
  return;
}

u32 CPSi_TcpWrite2Raw(u8 *buf, u32 len, u8 *buf2, u32 len2, CPSSoc *soc)
{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int local_10;
  int local_8;
  int local_4;
  
  *(undefined4 *)(soc + 0x34) = 0;
  iVar6 = 0;
  iVar5 = 0;
  iVar8 = len2;
  iVar1 = CPSi_GetTick();
  //local_10 = buf;
  //local_8 = buf2;
  local_4 = len2;
#if (defined(SDK_BUILD_WIN64) || defined(SDK_BUILD_LINUX))
//TODO: Use more of the actual logic. For now on simulator platforms we just wrap OS sockets
  //PCPORT_TODO: Send the data

  struct sockaddr_in server;
  server.sin_family = AF_INET;
  server.sin_port = htons(soc->remote_port);
  #ifdef SDK_BUILD_WIN64
  server.sin_addr.S_un.S_addr = soc->remote_ip;
  #endif
  #ifdef SDK_BUILD_LINUX
  server.sin_addr.s_addr = soc->remote_ip;
  #endif
  int sendOk;
  int retries = 0;
  while(TRUE){
    sendOk = sendto(soc->WIN_socket, buf, len, 0, (struct sockaddr *)&server, sizeof(server) );
    if( 
      #ifdef SDK_BUILD_WIN64
      sendOk == SOCKET_ERROR
      #endif
      #ifdef SDK_BUILD_LINUX
      sendOk < 0
      #endif
     )
    {
      #ifdef SDK_BUILD_WIN64
      int error = WSAGetLastError();
      if(error == 10057) {
        // Socket not connected. try to connect and send again
        printf("CPSi_TcpWrite2Raw WinError: %d. Trying to reconnect.", WSAGetLastError());
        if(retries < 5) {
          if(
            connect(soc->WIN_socket, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR && WSAGetLastError() != 10035
            ) {
            printf("CPSi_TcpConnectRaw WinError %d\n", WSAGetLastError());
            retries++;
          }
        } else {
          return 0;
        }
      } else {
        printf("CPSi_TcpWrite2Raw WinError: %d", WSAGetLastError());
      }
      #endif
      #ifdef SDK_BUILD_LINUX
      //TODO Linux support for reconnecting.
      printf("CPSi_TcpWrite2Raw error %d. Trying to reconnect.\n", errno);
      if(retries < 5) {
        if(connect(soc->WIN_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
          retries++;
        }
      } else {
        return 0;
      }
      #endif
    }else {
      break;
    }
  }

  return len;
#else
  do {
    //iVar3 = (*link_is_on)();
    iVar3 = link_is_on();
    if ((((iVar3 == 0) || (len == 0)) || (soc->state != '\x04')) ||
       (iVar3 = CPSi_GetTick(), 0x9e < iVar3 - iVar1)) {
      return iVar6;
    }
    iVar7 = *(int *)(soc + 0x28);
    //tcp_write_do2(local_10,len,local_8,local_4,soc,iVar5,iVar1,iVar8);
    tcp_write_do2(buf, len, buf2, len2, soc, iVar5);
    iVar3 = CPSi_GetTick();
    while( TRUE ) {
      //OS_YieldThread__();
      //iVar2 = (*link_is_on)();
      iVar2 = link_is_on();
      if ((iVar2 == 0) || (*(char *)(soc + 8) != '\x04')) break;
      if (*(int *)(soc + 0x28) == *(int *)(soc + 0x30)) break;
      iVar2 = CPSi_GetTick();
      if ((0xe < iVar2 - iVar3) || ((iVar5 != 0 && (*(short *)(soc + 0x2c) != 0)))) break;
    }
    uVar4 = *(int *)(soc + 0x30) - iVar7;
    if ((uint)(*(int *)(soc + 0x28) - iVar7) < uVar4) {
      //OSi_TWarning(_15259,0x981,_16202,uVar4,*(int *)(soc + 0x28) - iVar7);
      uVar4 = 0;
    }
    iVar6 = iVar6 + uVar4;
    if (uVar4 != 0) {
      iVar1 = CPSi_GetTick();
    }
    *(undefined4 *)(soc + 0x28) = *(undefined4 *)(soc + 0x30);
    if (((*(char *)(soc + 8) == '\x04') && (*(short *)(soc + 0x2c) == 0)) && (uVar4 == 0)) {
      if (iVar5 == 0) {
        iVar3 = CPSi_GetTick();
        //while (iVar7 = (*link_is_on)(), iVar7 != 0) {
          //iVar7 = CPSi_GetTick();
          //if ((0xe < iVar7 - iVar3) || (OS_YieldThread__(), *(short *)(soc + 0x2c) != 0)) break;
        //}
        if (*(short *)(soc + 0x2c) == 0) {
          iVar5 = 1;
        }
      }
    }
    else {
      iVar5 = 0;
    }
    if (uVar4 < len) {
      local_10 = local_10 + uVar4;
      len = len - uVar4;
    }
    else {
      local_10 = local_8 + (uVar4 - len);
      len = local_4 - (uVar4 - len);
      local_8 = 0;
      local_4 = 0;
    }
  } while( TRUE );
#endif
}