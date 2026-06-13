#include <nitro.h>
#include <nitroWiFi.h>
#include <nitroWiFi/decomp/decomp_defs_nitrowifi.h>

static u32 ssl_handshake_priority;
static CPSSslSession session[4];
static char pool[20];
static BOOL pool_initialized = FALSE;
static u16 pairlist[2] = {0x04, 0x05}; // NitroWifi supports SSL_RSA_WITH_RC4_128_MD5, SSL_RSA_WITH_RC4_128_SHA
static char * object[6] = {"\xFF\xFF\xFF",
                           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01", //An algorithm ID
                           "\x55\x08\x01\x01",
                           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04",
                           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05",
                           "\x55\x04\x03"};

static void add1_be8(u8 * aBuf);
static uint auth_cert(CPSSslConnection *aConn);
static void cache_session(CPSSslConnection *aConn,CPSInAddr aIpAddr,u16 aPort);
static undefined4 cert_item(CPSSslConnection *aConn, u8 **aBuf, int param_3, int param_4, int param_5);
static uint cert_item_len(u8 ** aBuf);
static int chars_till_end(char *param_1);
static void client_hello(CPSSslConnection * aConn, undefined *param_2);
static void client_hello_v2(CPSSslConnection * aConn, undefined *param_2);
static undefined4 compare_fqdn(char *param_1, char *param_2);
static void create_key_block(CPSSslConnection * aConn);
static void create_master_secret(CPSSslConnection *aConn);
static void create_ms_sub(u8 *aResultBuf,char *param_2,CPSSslConnection *aConn);
static int date2sec(void);
static int decrypt(CPSSslConnection *aConn, uchar *aBuf, int aLen);
static void decrypt_premaster_secret(CPSSslConnection *aConn, u8 *aBuf, CPSPrivateKey *aKey);
static undefined4 enter_computebound(void);
static void exit_computebound(uint param_1);
static void find_session_from_id(CPSSslConnection * aConn);
static void find_session_from_IP(CPSSslConnection *aConn, CPSInAddr aIpAddr, u16 aPort);
static void finished_md5(CPSSslConnection *aConn, u8 *aBuf, uint param_3);
static void finished_sha1(CPSSslConnection *aConn, u8 *aBuf, uint param_3);
static CPSCaInfo * get_rootCA(CPSSslConnection *aConn,char *aIssuer);
static undefined4 has_method(byte *param_1, int param_2, int param_3, ushort param_4);
static int make_ciphertext(CPSSslConnection *aConn,u8 *aBuf);
static void make_dn(char *param_1, char *param_2, int param_3);
static int make_plaintext(CPSSslConnection *aConn, u8 *aBuf);
static undefined4 mustget_change_cipher_spec_and_finished(CPSSoc * aSoc);
static int parse2digits(byte *param_1);
static u32 parse_time(u8 *param_1, int param_2);
static uchar parse_record(CPSSoc *aSoc);
static void parse_record_in_buf(CPSSslConnection *aConn, uchar *aBuf, CPSSoc *aSoc);
static void purge_session(CPSSslConnection * aConn);
static void rcv_certificate(CPSSslConnection *aConn, u8 *aBuf);
static void rcv_client_key_exchange(CPSSslConnection *aConn, u8 *aBuf);
static void rcv_finished(CPSSslConnection *aConn, u8 *aBuf);
static void rcv_server_hello(CPSSslConnection * aConn, u8 * aBuf);
static u16 select_method(u8 * param_1, int param_2, int param_3);
static void send_change_cipher_spec_and_finished(CPSSoc *aSoc);
static void send_client_hello(CPSSoc *aSoc);
static void send_client_key_exchange(CPSSoc * aSoc);
static uchar send_server_hello(CPSSoc *aSoc);
static void set_random(u8 *aBuf, int aLen);
static undefined4 ssl_connect_try(CPSSoc *aSoc);
static undefined4 ssl_listen_try(CPSSoc *aSoc);
static u32 tcp_read_raw_nbytes(u8 *aBuf, u32 aLen, CPSSoc *aSoc);
static void try_fill_record(CPSSoc *aSoc);
static void update_digest(CPSSslConnection *aConn,u8 *param_2, int param_3);
static undefined4 validate_signature(CPSSslConnection *aConn, CPSCaInfo *aCaInfo);
static BOOL version_ok(char param_1);



u32 CPS_GetSslHandshakePriority(void)
{
  return ssl_handshake_priority;
}


void CPS_SetMyCert(CPSCertificate *aCert, CPSPrivateKey *aKey)
{
  OSThread *myThread;
  CPSSoc *mySoc;
  CPSSslConnection *myConn;
  
  myThread = OS_GetCurrentThread();
  mySoc = (CPSSoc *)OSi_GetSpecificData(myThread,0);
  if ((mySoc != (CPSSoc *)0x0) &&
     (myConn = (CPSSslConnection *)mySoc->con, myConn != NULL)) {
    myConn->my_key = aKey;
    myConn->my_certificate = aCert;
  }
  return;
}


void CPS_SetRootCa(CPSCaInfo **aCaInfo, int aCaBuiltins)
{
  OSThread *myThead;
  CPSSoc *mySoc;
  CPSSslConnection *myConn;
  
  myThead = OS_GetCurrentThread();
  mySoc = (CPSSoc *)OSi_GetSpecificData(myThead,0);
  if ((mySoc != NULL) &&
     (myConn = (CPSSslConnection *)mySoc->con, myConn != NULL))
  {
    myConn->ca_info = aCaInfo;
    myConn->ca_builtins = aCaBuiltins;
  }
  return;
}


void CPS_SetSsl(int aUseSsl)
{
  OSThread *myThread;
  CPSSoc *mySoc;
  
  //OSi_ReferSymbol(id_string);
  myThread = OS_GetCurrentThread();
  mySoc = (CPSSoc *)OSi_GetSpecificData(myThread,0);
  if (mySoc != NULL) {
    mySoc->ssl = (uchar)aUseSsl;
  }
  return;
}


void CPS_SetSslHandshakePriority(u32 aPriority)
{
  ssl_handshake_priority = aPriority;
  return;
}


void CPS_SslAddRandomSeed(void * param_1, u32 param_2)
{
  undefined4 uVar1;
  CPSSha1Ctx CStack_78;
  
  CPSi_sha1_init(&CStack_78);
  uVar1 = OS_DisableInterrupts();
  CPSi_sha1_calc(&CStack_78,pool,0x14);
  CPSi_sha1_calc(&CStack_78,param_1,param_2);
  CPSi_sha1_result(&CStack_78,pool);
  OS_RestoreInterrupts(uVar1);
  pool_initialized = TRUE;
  return;
}








void CPSi_SslCleanup()
{
  MI_CpuClear8(session, sizeof(session));
  return;
}


void CPSi_SslClose(CPSSoc * aSoc)
{
  int iVar1;
  
  iVar1 = *(int *)(aSoc + 0xc);
  *(undefined *)(iVar1 + 0x455) = 0;
  if (*(int *)(iVar1 + 0x824) != 0) {
    //(*CPSiFree)(*(undefined4 *)(iVar1 + 0x824));
  }
  *(undefined4 *)(iVar1 + 0x824) = 0;
  return;
}


u32 CPSi_SslConnect(CPSSoc *aSoc)
{
  int iVar1;
  u32 uVar2;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  if ((aSoc->state == '\x04') || (iVar1 = CPSi_TcpConnectRaw(aSoc), iVar1 == 0)) {
    myConn->state = '\0';
    myConn->rcv_mac = (uchar *)0x0;
    myConn->server = '\0';
    CPSi_sha1_init(&myConn->sha1_hash);
    CPSi_md5_init(&myConn->md5_hash);
    uVar2 = ssl_connect_try(aSoc);
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}


void CPSi_SslConsume(u32 len,CPSSoc *aSoc)
{
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  if (len < (uint)(myConn->inbuf_len - myConn->inbuf_pnt)) {
    myConn->inbuf_pnt = myConn->inbuf_pnt + len;
  } else {
    if (myConn->inbuf != NULL) {
      (*CPSiFree)(myConn->inbuf);
    }
    myConn->inbuf = (uchar *)0x0;
  }
  return;
}


s32 CPSi_SslGetLength(CPSSoc *aSoc)
{
  int iVar1;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  if ((myConn->inbuf == NULL) || (myConn->inbuf_decrypted == 0)) {
    try_fill_record(aSoc);
  }
  if ((myConn->inbuf == NULL) || (myConn->inbuf_decrypted == 0)) {
    if ((myConn->inbuf == NULL) && ((aSoc->state != 4 || (myConn->state == 9)))) {
      iVar1 = -1;
    } else {
      iVar1 = 0;
    }
  } else {
    iVar1 = myConn->inbuf_len - myConn->inbuf_pnt;
  }
  return iVar1;
}


void CPSi_SslListen(CPSSoc *aSoc)
{
  int iVar1;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  while( TRUE ) {
    CPSi_TcpListenRaw(aSoc);
    myConn->state = '\0';
    myConn->rcv_mac = (uchar *)0x0;
    myConn->server = '\x01';
    CPSi_sha1_init(&myConn->sha1_hash);
    CPSi_md5_init(&myConn->md5_hash);
    iVar1 = ssl_listen_try(aSoc);
    if (iVar1 == 0) break;
    CPSi_TcpShutdownRaw(aSoc);
    aSoc->remote_port = aSoc->remote_port_bound;
    aSoc->remote_ip = aSoc->remote_ip_bound;
  }
  myConn->state = '\b';
  return;
}


void CPSi_SslPeriodical(u32 now)
{
  undefined4 uVar1;
  OSThread *theThread;
  CPSSoc *theSoc;
  int iVar2;
  
  uVar1 = OS_DisableInterrupts();
  for (iVar2 = 0; iVar2 < 4; iVar2 = iVar2 + 1) {
    if ((session[iVar2].valid != '\0') && (0x3bd < (int)(now - session[iVar2].when))) {
      session[iVar2].valid = '\0';
    }
  }
  OS_RestoreInterrupts(uVar1);
  for (theThread = OS_GetThreadList(); theThread != NULL;
      theThread = OS_GetNextThread(theThread)) {
    theSoc = (CPSSoc *)OSi_GetSpecificData(theThread,0);
    if ((((theSoc != (CPSSoc *)0x0) && (theSoc->thread != NULL)) &&
        (theSoc->ssl != '\0')) &&
       (((theSoc->state == '\x04' && (*(byte *)((int)theSoc->con + 0x455) < 8)) &&
        ((0xef < (int)(now - theSoc->when) && (theSoc->block_type == 2)))))) {
      theSoc->state = '\0';
      theSoc->block_type = 0;
      OS_WakeupThreadDirect(theSoc->thread);
    }
  }
  return;
}


u8 * CPSi_SslRead(u32 *aLen, CPSSoc *aSoc)
{
  uchar uVar1;
  int iVar2;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  if ((myConn->inbuf != NULL) && (myConn->inbuf_decrypted == 0)) {
    iVar2 = tcp_read_raw_nbytes(myConn->inbuf + myConn->inbuf_pnt,
                                myConn->inbuf_len - myConn->inbuf_pnt,aSoc);
    if (iVar2 != 0) {
      (*CPSiFree)(myConn->inbuf);
      myConn->inbuf = NULL;
      *aLen = 0;
      return NULL;
    }
    parse_record_in_buf(myConn, myConn->inbuf, aSoc);
    if (myConn->inbuf_decrypted == 0) {
      myConn->inbuf = NULL;
    }
  }
  do {
    if (myConn->inbuf != NULL) {
      *aLen = myConn->inbuf_len - myConn->inbuf_pnt;
      return myConn->inbuf + myConn->inbuf_pnt;
    }
    uVar1 = parse_record(aSoc);
  } while (uVar1 != 9);
  *aLen = 0;
  return NULL;
}


void CPSi_SslShutdown(CPSSoc *aSoc)
{
  undefined4 uVar1;
  CPSSslConnection *myConn;
  u8 local_2c [32];
  
  myConn = (CPSSslConnection *)aSoc->con;
  if (myConn->state == 8) {
    local_2c[0] = 21;
    local_2c[1] = 3;
    local_2c[2] = 0;
    local_2c[3] = 0;
    local_2c[4] = 2;
    local_2c[5] = 1;
    local_2c[6] = 0;
    uVar1 = make_ciphertext(myConn,local_2c);
    CPSi_TcpWrite2Raw(local_2c, uVar1, 0, 0, aSoc);
  }
  myConn->state = 0;
  return;
}


u32 CPSi_SslWrite2(u8 *aBuf,u32 aLen,u8 *aBuf2,u32 aLen2,CPSSoc *aSoc)
{
  CPSSslConnection *myConn;
  u8 *tmp;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  u8 *local_10;
  u8 *local_8;
  
  myConn = (CPSSslConnection *)aSoc->con;
  uVar4 = aLen + aLen2;
  iVar5 = 0;
  local_10 = aBuf;
  local_8 = aBuf2;
  while( TRUE ) {
    uVar3 = uVar4;
    if (0xb4f < (int)uVar4) {
      uVar3 = 0xb4f;
    }
    tmp = (u8 *)(*CPSiAlloc)(uVar3 + 0x19);
    if (tmp == NULL) {
      OSi_TWarning("ssl.c", 0xa2d, "Failed to allcoate tmp\n");
      return iVar5;
    }
    uVar1 = aLen;
    if (uVar3 <= aLen) {
      uVar1 = uVar3;
    }
    MI_CpuCopy8(local_10,tmp + 5,uVar1);
    local_10 = local_10 + uVar1;
    aLen = aLen - uVar1;
    MI_CpuCopy8(local_8,tmp + uVar1 + 5,uVar3 - uVar1);
    local_8 = local_8 + (uVar3 - uVar1);
    *tmp = '\x17'; //Record Content Type (Application Data)
    tmp[1] = '\x03'; //Protocol Version SSLv3
    tmp[2] = '\0';
    tmp[3] = (u8)(uVar3 >> 8); //Length
    tmp[4] = (u8)uVar3;
    uVar1 = make_ciphertext(myConn,tmp);
    uVar2 = CPSi_TcpWrite2Raw(tmp,uVar1,0,0,aSoc);
    if (uVar2 < uVar1) {
      uVar3 = 0;
    }
    (*CPSiFree)(tmp);
    uVar4 = uVar4 - uVar3;
    iVar5 = iVar5 + uVar3;
    if (uVar4 == 0) break;
    if (uVar3 == 0) {
      return iVar5;
    }
  }
  return iVar5;
}









void add1_be8(u8 * aBuf)
{
  u8 uVar1;
  int iVar2;
  
  iVar2 = 8;
  while( TRUE ) {
    if (iVar2 == 0) {
      return;
    }
    aBuf = aBuf + -1;
    uVar1 = *aBuf;
    *aBuf = uVar1 + '\x01';
    if ((u8)(uVar1 + '\x01') != '\0') break;
    iVar2 = iVar2 + -1;
  }
  return;
}


uint auth_cert(CPSSslConnection *aConn)
{
  CPSCaInfo *myCaInfo;
  uint uVar1;
  CPSMd5Ctx *myMd5Ctx;
  CPSSha1Ctx *mySha1Ctx;
  uint uVar2;
  
  if (aConn->date_ok == FALSE) {
    uVar2 = 0x8000;
  } else {
    uVar2 = 0;
  }

  if (aConn->pub_algorithm == -1) {
    uVar2 = uVar2 | 4;
  } else {
    if (aConn->sig_algorithm == 3) {
      myMd5Ctx = &aConn->md5_hash_tmp;
      CPSi_md5_init(myMd5Ctx);
      CPSi_md5_calc(myMd5Ctx, aConn->hash_start, (int)aConn->hash_end - (int)aConn->hash_start);
      CPSi_md5_result(myMd5Ctx, aConn->hash_val);
      aConn->hash_len = 0x10;
    } else {
      if (aConn->sig_algorithm != 4) {
        return uVar2 | 3;
      }
      mySha1Ctx = &aConn->sha1_hash_tmp;
      CPSi_sha1_init(mySha1Ctx);
      CPSi_sha1_calc(mySha1Ctx, aConn->hash_start, (int)((u64)aConn->hash_end - (u64)aConn->hash_start));
      CPSi_sha1_result(mySha1Ctx,aConn->hash_val);
      aConn->hash_len = 0x14;
    }
    myCaInfo = get_rootCA(aConn,aConn->issuer);
    if (myCaInfo == (CPSCaInfo *)0x0) {
      uVar2 = uVar2 | 1;
    } else {
      uVar1 = validate_signature(aConn, myCaInfo);
      uVar2 = uVar2 | uVar1;
    }
  }
  return uVar2;
}


void cache_session(CPSSslConnection *aConn,CPSInAddr aIpAddr,u16 aPort)
{
  undefined4 uVar1;
  unsigned long uVar2;
  CPSSslSession *pCVar3;
  CPSSslSession *pCVar4;
  int iVar5;
  uint uVar6;
  
  uVar1 = OS_DisableInterrupts();
  uVar2 = CPSi_GetTick();
  uVar6 = 0;
  pCVar3 = session;
  for (iVar5 = 0; pCVar4 = pCVar3, iVar5 < 4; iVar5 = iVar5 + 1) {
    pCVar4 = session + iVar5;
    if ((((session[iVar5].valid != '\0') && (aIpAddr != 0)) && (aIpAddr == session[iVar5].ip)) &&
       ((aPort != 0 && (aPort == session[iVar5].port)))) break;
    if (uVar6 != 0xffffffff) {
      if (session[iVar5].valid == '\0') {
        uVar6 = 0xffffffff;
        pCVar3 = pCVar4;
      }
      else if (uVar6 < uVar2 - session[iVar5].when) {
        uVar6 = uVar2 - session[iVar5].when;
        pCVar3 = pCVar4;
      }
    }
  }
  MI_CpuCopy8(&aConn->common1, pCVar4, 0x20);
  MI_CpuCopy8(aConn, pCVar4->master_secret ,0x30);
  pCVar4->when = uVar2;
  pCVar4->valid = TRUE;
  pCVar4->ip = aIpAddr;
  pCVar4->port = aPort;
  OS_RestoreInterrupts(uVar1);
  return;
}


undefined4 cert_item(CPSSslConnection *aConn, u8 **aBuf, int param_3, int param_4, int param_5)
{
  byte currentCertByte;
  byte *curCertPtr;

  unsigned long uVar2;
  size_t __n;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  byte *pbVar7;
  int local_38;
  
  curCertPtr = *aBuf + 1;
  currentCertByte = **aBuf;
  uVar2 = cert_item_len(&curCertPtr);
  if (((int)uVar2 < 0) || (2000 < (int)uVar2)) {
    // Bail out if the cert item has a length greater than 2000 bytes
    return 1;
  }
  switch(currentCertByte & 0x1f) {
  case 0:
    break;
  case 1:
    break;
  case 2:
    if (aConn->seen_pub_algorithm) {
      if (param_4 == 0) {
        for (; *curCertPtr == 0; curCertPtr = curCertPtr + 1) {
          uVar2 = uVar2 - 1;
        }
        if (param_5 == 0) {
          if ((int)uVar2 < 257) {
            MI_CpuCopy8(curCertPtr, aConn->modulus, uVar2);
            aConn->modulus_len = uVar2;
          } else {
            OSi_TWarning("ssl.c", 503, "RSA key modulus too long (%d)\n",uVar2);
          }
        } else if (param_5 == 2) {
          (aConn->midca_info).modulus_len = uVar2;
          (aConn->midca_info).modulus = curCertPtr;
        }
      }
      else if (param_4 == 1) {
        for (; *curCertPtr == 0; curCertPtr = curCertPtr + 1) {
          uVar2 = uVar2 - 1;
        }
        if (param_5 == 0) {
          if ((int)uVar2 < 9) {
            MI_CpuCopy8(curCertPtr,aConn->exponent,uVar2);
            aConn->exponent_len = uVar2;
          } else {
            OSi_TWarning("ssl.c", 525, "RSA key exponent too long (%d)\n",uVar2);
          }
        } else if (param_5 == 2) {
          (aConn->midca_info).exponent_len = uVar2;
          (aConn->midca_info).exponent = curCertPtr;
        }
      }
    }
    curCertPtr = curCertPtr + uVar2;
    goto LAB_00010f78;
  case 3:
    if ((param_3 == 1) && (param_5 != 2)) {
      aConn->signature = curCertPtr + 1;
      aConn->signature_len = uVar2 - 1;
    }
    if (aConn->seen_pub_algorithm == '\0') {
      curCertPtr = curCertPtr + uVar2;
    }
    else {
      curCertPtr = curCertPtr + 1;
      iVar5 = cert_item(aConn,&curCertPtr,param_3,0,param_5);
      if (iVar5 != 0) {
        return 1;
      }
      aConn->seen_pub_algorithm = '\0';
    }
    goto LAB_00010f78;
  case 4:
    break;
  case 5:
    break;
  case 6:
    iVar5 = 0;
LAB_00010d28:
    if (iVar5 < 6) {
      __n = strlen((char *)object[iVar5]);
      iVar3 = memcmp(curCertPtr, object[iVar5], __n);
      if (iVar3 != 0) goto LAB_00010d24;
      switch(iVar5) {
      case 0:
        goto switchD_00010cc8_caseD_6;
      case 1:
        break;
      case 2:
        break;
      case 3:
        goto LAB_00010d00;
      case 4:
LAB_00010d00:
        if (param_5 != 2) {
          aConn->sig_algorithm = iVar5;
        }
        goto switchD_00010cc8_caseD_6;
      case 5:
        if (param_5 != 2) {
          aConn->seen_attr = (uchar)iVar5;
        }
      default:
        goto switchD_00010cc8_caseD_6;
      }
      if (param_5 == 0) {
        aConn->pub_algorithm = iVar5;
      }
      aConn->seen_pub_algorithm = (uchar)iVar5;
    }
switchD_00010cc8_caseD_6:
    curCertPtr = curCertPtr + uVar2;
    goto LAB_00010f78;
  case 7:
    break;
  case 8:
    break;
  case 9:
    break;
  case 10:
    break;
  case 0xb:
    break;
  case 0xc:
    goto LAB_00010d40;
  case 0xd:
    break;
  case 0xe:
    break;
  case 0xf:
    break;
  case 0x10:
    if (((param_3 == 0) && (param_4 == 0)) && (param_5 != 2)) {
      aConn->hash_start = curCertPtr;
    }
    pbVar7 = curCertPtr + uVar2;
    local_38 = 0;
    while (curCertPtr < pbVar7) {
      iVar5 = cert_item(aConn, &curCertPtr, param_3 + 1, local_38, param_5);
      local_38 = local_38 + 1;
      if (iVar5 != 0) {
        return 1;
      }
    }
    if (((param_3 == 1) && (param_4 == 0)) && (param_5 != 2)) {
      aConn->hash_end = curCertPtr;
    }
    goto LAB_00010f78;
  case 0x11:
    pbVar7 = curCertPtr + uVar2;
    while (curCertPtr < pbVar7) {
      iVar5 = cert_item(aConn,&curCertPtr,param_3 + 1,0,param_5);
      if (iVar5 != 0) {
        return 1;
      }
    }
    goto LAB_00010f78;
  case 0x12:
    break;
  case 0x13:
    goto LAB_00010d40;
  case 0x14:
    goto LAB_00010d40;
  case 0x15:
    break;
  case 0x16:
LAB_00010d40:
    if (param_5 != 2) {
      if (aConn->seen_validity == '\0') {
        make_dn(aConn->issuer, curCertPtr,uVar2);
      } else {
        make_dn(aConn->subject, curCertPtr,uVar2);
        if ((aConn->seen_attr == '\x05') && ((int)uVar2 < 0x50)) {
          MI_CpuCopy8(curCertPtr, aConn->cn, uVar2);
          aConn->cn[uVar2] = '\0';
        }
      }
    }
    aConn->seen_attr = '\0';
    curCertPtr = curCertPtr + uVar2;
    goto LAB_00010f78;
  case 0x17:
    goto LAB_00010dc0;
  case 0x18:
LAB_00010dc0:
    if (param_5 != 2) {
      uVar4 = parse_time(curCertPtr, currentCertByte & 0x1f);
      if (param_4 == 0) {
        if (uVar4 <= aConn->cur_date) {
          aConn->date_ok = '\x01';
        }
      } else if (uVar4 < aConn->cur_date) {
        aConn->date_ok = '\0';
#ifdef SDK_PORT
        OS_Printf("Warning: Certificate expired. Allowing it through anyways.\n");
        aConn->date_ok = 1;
#endif
      }
    }
    curCertPtr = curCertPtr + uVar2;
    aConn->seen_validity = '\x01';
    goto LAB_00010f78;
  }
  if (currentCertByte == 160 /*0xa0*/) {
    pbVar7 = curCertPtr + uVar2;
    do {
      if (pbVar7 <= curCertPtr) goto LAB_00010f78;
      iVar5 = cert_item(aConn, &curCertPtr, param_3 + 1, 0, param_5);
    } while (iVar5 == 0);
    uVar6 = 1;
  } else {
    curCertPtr = curCertPtr + uVar2;
LAB_00010f78:
    *aBuf = curCertPtr;
    uVar6 = 0;
  }
  return uVar6;
LAB_00010d24:
  iVar5 = iVar5 + 1;
  goto LAB_00010d28;
}


uint cert_item_len(u8 ** aBuf)
{
  byte curCertByte;
  uint uVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *aBuf + 1;
  curCertByte = **aBuf;
  uVar2 = (uint)curCertByte;
  if ((curCertByte & 0x80) != 0) {
    uVar3 = uVar2 & 0x7f;
    uVar2 = 0;
    while (uVar3 != 0) {
      if ((uVar2 & 0xff000000) != 0) {
        return 0xffffffff;
      }
      uVar2 = uVar2 * 0x100 + (uint)*pbVar4;
      uVar3 = uVar3 - 1;
      pbVar4 = pbVar4 + 1;
    }
  }
  *aBuf = pbVar4;
  return uVar2;
}


int chars_till_end(char *param_1)
{
  char *pcVar1;
  
  for (pcVar1 = param_1; (*pcVar1 != '.' && (*pcVar1 != '\0')); pcVar1 = pcVar1 + 1) {
  }
  return (int)pcVar1 - (int)param_1;
}


void client_hello(CPSSslConnection * aConn, undefined *param_2)
{
  byte bVar1;
  unsigned short uVar2;
  int iVar3;
  byte *pbVar4;
  
  iVar3 = version_ok(*param_2);
  if (iVar3 != 0) {
    MI_CpuCopy8(param_2 + 2, aConn->client_random, 0x20);
    bVar1 = param_2[0x22];
    if (bVar1 == 0x20) {
      MI_CpuCopy8(param_2 + 0x23, &aConn->common1, 0x20);
      find_session_from_id(aConn);
    }
    else {
      aConn->session_cached = FALSE;
    }
    pbVar4 = param_2 + 0x23 + bVar1;
    uVar2 = select_method(pbVar4 + 2,((uint)*pbVar4 * 0x100 + (uint)pbVar4[1]) / 2,2);
    aConn->method = uVar2;
    if (uVar2 != 0) {
      aConn->state = '\x01';
    }
  }
  return;
}


void client_hello_v2(CPSSslConnection * aConn, undefined *param_2)
{
  byte bVar1;
  byte bVar2;
  unsigned short uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  
  iVar4 = version_ok(*param_2);
  if (iVar4 != 0) {
    iVar4 = (uint)(byte)param_2[2] * 0x100 + (uint)(byte)param_2[3];
    //uVar5 = _s32_div_f(iVar4,3);
    uVar3 = select_method(param_2 + 8,uVar5,3);
    if (uVar3 != 0) {
      aConn->method = uVar3;
      bVar1 = param_2[4];
      bVar2 = param_2[5];
      uVar6 = (uint)(byte)param_2[6] * 0x100 + (uint)(byte)param_2[7];
      aConn->session_cached = FALSE;
      if (uVar6 < 32) {
        MI_CpuClear8(aConn->client_random, 0x20 - uVar6);
        MI_CpuCopy8(param_2 + iVar4 + 8 + (uint)bVar1 * 0x100 + (uint)bVar2,
                    &aConn->client_random[32 - uVar6], uVar6);
      } else {
        MI_CpuCopy8(param_2 + iVar4 + 8 + (uint)bVar1 * 0x100 + (uint)bVar2,aConn->client_random,
                    32);
      }
      aConn->state = 1;
    }
  }
  return;
}


undefined4 compare_fqdn(char *param_1,char *param_2)
{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  
  while( TRUE ) {
    while( TRUE ) {
      pcVar4 = param_2 + 1;
      cVar1 = *param_1;
      if (cVar1 != *param_2) break;
      param_1 = param_1 + 1;
      param_2 = pcVar4;
      if (cVar1 == '\0') {
        return 0;
      }
    }
    if (*param_2 != '*') {
      return 1;
    }
    iVar2 = chars_till_end(param_1);
    iVar3 = chars_till_end(pcVar4);
    if (iVar2 < iVar3) break;
    param_1 = param_1 + (iVar2 - iVar3);
    param_2 = pcVar4;
  }
  return 1;
}


void create_key_block(CPSSslConnection * aConn)
{
  CPSSha1Ctx *mySha1Ctx;
  CPSMd5Ctx *myMd5Ctx;
  int unaff_r6;
  int iVar1;
  int unaff_r8;
  int iVar2;
  int unaff_r10;
  char local_40 [4];
  int local_3c;
  undefined auStack_38 [24];
  
  if (aConn->method == 4) {
    unaff_r6 = 0x10;
    unaff_r8 = 0x10;
    unaff_r10 = 0;
  } else if (aConn->method == 5) {
    unaff_r6 = 0x14;
    unaff_r8 = 0x10;
    unaff_r10 = 0;
  }
  
  local_3c = (unaff_r10 + unaff_r6 + unaff_r8) * 2;
  for (iVar1 = 0; iVar1 * 0x10 < local_3c; iVar1 = iVar1 + 1) {
    mySha1Ctx = &aConn->sha1_hash_tmp;
    CPSi_sha1_init(mySha1Ctx);
    local_40[0] = (char)iVar1 + 'A';
    for (iVar2 = 0; iVar2 < iVar1 + 1; iVar2 = iVar2 + 1) {
      CPSi_sha1_calc(mySha1Ctx,local_40,1);
    }
    CPSi_sha1_calc(mySha1Ctx,aConn,0x30);
    CPSi_sha1_calc(mySha1Ctx,aConn->server_random,0x20);
    CPSi_sha1_calc(mySha1Ctx,aConn->client_random,0x20);
    CPSi_sha1_result(mySha1Ctx,auStack_38);
    myMd5Ctx = &aConn->md5_hash_tmp;
    CPSi_md5_init(myMd5Ctx);
    CPSi_md5_calc(myMd5Ctx,aConn,0x30);
    CPSi_md5_calc(myMd5Ctx,auStack_38,0x14);
    CPSi_md5_result(myMd5Ctx,aConn->server_random + iVar1 * 0x10 + 0x20);
  }

  if (aConn->server == '\0') {
    aConn->send_mac = (uchar *)&aConn->common1;
    aConn->send_key = aConn->send_mac + unaff_r6 * 2;
    aConn->rcv_mac = aConn->server_random + unaff_r6 + 0x20;
    aConn->rcv_key = aConn->rcv_mac + unaff_r8 + unaff_r6;
  } else {
    aConn->rcv_mac = (uchar *)&aConn->common1;
    aConn->rcv_key = aConn->rcv_mac + unaff_r6 * 2;
    aConn->send_mac = aConn->server_random + unaff_r6 + 0x20;
    aConn->send_key = aConn->send_mac + unaff_r8 + unaff_r6;
  }

  CPSi_rc4_init(&aConn->rcv_cipher.rc4_ctx, aConn->rcv_key,0x10);
  CPSi_rc4_init(&aConn->send_cipher.rc4_ctx, aConn->send_key,0x10);
  return;
}


void create_master_secret(CPSSslConnection *aConn)
{
  //See section 6.1 of RFC6101

  u8 myMasterSecret[48];
  
  create_ms_sub(myMasterSecret, "A", aConn);
  create_ms_sub(&myMasterSecret[16], "BB", aConn);
  create_ms_sub(&myMasterSecret[32], "CCC", aConn);
  MI_CpuCopy8(myMasterSecret, aConn->master_secret, 48);
  return;
}


void create_ms_sub(u8 *aResultBuf,char *param_2,CPSSslConnection *aConn)
{
  size_t sVar1;
  CPSSha1Ctx *mySha1Ctx;
  CPSMd5Ctx *myMd5Ctx;
  u8 shaHash[24];
  
  mySha1Ctx = &aConn->sha1_hash_tmp;
  CPSi_sha1_init(mySha1Ctx);
  sVar1 = strlen(param_2);
  CPSi_sha1_calc(mySha1Ctx,param_2,sVar1);
  CPSi_sha1_calc(mySha1Ctx,aConn->master_secret,0x30);
  CPSi_sha1_calc(mySha1Ctx,aConn->client_random,0x40);
  CPSi_sha1_result(mySha1Ctx, shaHash);
  myMd5Ctx = &aConn->md5_hash_tmp;
  CPSi_md5_init(myMd5Ctx);
  CPSi_md5_calc(myMd5Ctx, aConn->master_secret, 0x30);
  CPSi_md5_calc(myMd5Ctx, shaHash, 0x14);
  CPSi_md5_result(myMd5Ctx, aResultBuf);
  return;
}


int date2sec(void)
{
  int seconds;
  RTCDate theDate;
  RTCTime theTime;
  
  RTC_GetDate(&theDate);
  RTC_GetTime(&theTime);
  seconds = RTC_ConvertDateTimeToSecond(&theDate, &theTime);
  // 0x386d4380 = 1/1/2000 in epoch
  return seconds + 0x386d4380;
}


int decrypt(CPSSslConnection *aConn, uchar *aBuf, int aLen)
{
  CPSi_rc4_crypt(&(aConn->rcv_cipher).rc4_ctx,aBuf,aLen);
  return aLen;
}


void decrypt_premaster_secret(CPSSslConnection *aConn, u8 *aBuf, CPSPrivateKey *aKey)
{
  u16 *tmp_var;
  u16 *puVar1;
  u16 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  u16 *puVar6;
  u16 *puVar7;
  u16 *puVar8;
  u16 *puVar9;
  
  if ((aKey != (CPSPrivateKey *)0x0) && (aKey->modulus_len != 0)) {
    iVar5 = (aKey->modulus_len * 2) / 2 + 1;
    tmp_var = (u16 *)(*CPSiAlloc)(iVar5 * 0x14);
    if (tmp_var == (u16 *)0x0) {
      OSi_TWarning("ssl.c", 0x420, "Failed to allcoate tmp_var\n");
    }
    else {
      puVar6 = tmp_var + iVar5;
      puVar7 = puVar6 + iVar5;
      puVar1 = puVar7 + iVar5;
      puVar2 = puVar1 + iVar5;
      puVar9 = puVar2 + iVar5;
      puVar8 = puVar9 + iVar5;
      CPSi_big_from_char(tmp_var,aBuf,aKey->modulus_len,iVar5);
      CPSi_big_from_char(puVar6,aKey->exponent1,aKey->exponent1_len,iVar5);
      CPSi_big_from_char(puVar9,aKey->prime1,aKey->prime1_len,iVar5);
      uVar3 = enter_computebound();
      CPSi_big_montpower(puVar1,tmp_var,puVar6,iVar5,puVar9);
      CPSi_big_from_char(puVar6,aKey->exponent2,aKey->exponent2_len,iVar5);
      CPSi_big_from_char(puVar9,aKey->prime2,aKey->prime2_len,iVar5);
      CPSi_big_montpower(puVar2,tmp_var,puVar6,iVar5,puVar9);
      exit_computebound(uVar3);
      CPSi_big_sub(tmp_var,puVar1,puVar2,iVar5);
      CPSi_big_from_char(puVar6,aKey->coefficient,aKey->coefficient_len,iVar5);
      CPSi_big_mult(puVar7,tmp_var,puVar6,iVar5);
      CPSi_big_from_char(puVar6,aKey->prime2,aKey->prime2_len,iVar5);
      CPSi_big_mult(tmp_var,puVar7,puVar6,iVar5);
      CPSi_big_add(puVar7,tmp_var,puVar2,iVar5);
      CPSi_big_from_char(puVar6,aKey->modulus,aKey->modulus_len,iVar5);
      iVar4 = CPSi_big_sign(puVar7,iVar5);
      if (iVar4 < 0) {
        CPSi_big_negate(puVar7,iVar5);
        CPSi_big_div(0,puVar7,puVar6,puVar8,iVar5,puVar8 + iVar5);
        CPSi_big_sub(puVar8,puVar6,puVar8,iVar5);
      }
      else {
        CPSi_big_div(0,puVar7,puVar6,puVar8,iVar5,puVar8 + iVar5);
      }
      CPSi_char_from_big(aConn->master_secret,puVar8,0x30,iVar5);
      (*CPSiFree)(tmp_var);
    }
  }
  return;
}


undefined4 enter_computebound(void)
{
  OSThread *pOVar1;
  undefined4 uVar2;
  
  if (ssl_handshake_priority < 0x20) {
    pOVar1 = OS_GetCurrentThread();
    uVar2 = OS_GetThreadPriority(pOVar1);
    OS_SetThreadPriority(pOVar1,ssl_handshake_priority);
  }
  else {
    uVar2 = 0xffffffff;
  }
  return uVar2;
}


void exit_computebound(uint param_1)
{
  OSThread *pOVar1;
  
  if (param_1 < 0x20) {
    pOVar1 = OS_GetCurrentThread();
    OS_SetThreadPriority(pOVar1,param_1);
  }
  return;
}


void find_session_from_id(CPSSslConnection * aConn)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = OS_DisableInterrupts();
  aConn->session_cached = '\0';
  iVar3 = 0;
  do {
    if (3 < iVar3) {
LAB_0001028c:
      OS_RestoreInterrupts(uVar1);
      return;
    }
    if ((((session[iVar3].valid != '\0') && (session[iVar3].ip == 0)) && (session[iVar3].port == 0))
       && (iVar2 = memcmp(session + iVar3,&aConn->common1,0x20), iVar2 == 0)) {
      //MI_CpuCopy8(iVar3 * 0x5c + 0x10028,aConn,0x30);
      aConn->session_cached = '\x01';
      goto LAB_0001028c;
    }
    iVar3 = iVar3 + 1;
  } while( TRUE );
}


void find_session_from_IP(CPSSslConnection *aConn,CPSInAddr aIpAddr,u16 aPort)
{
  undefined4 uVar1;
  unsigned_long uVar2;
  int iVar3;
  
  uVar1 = OS_DisableInterrupts();
  #ifdef SDK_PORT
  //PCPORT_TODO: Fix session resuming
  return;
  #endif
  aConn->session_cached = '\0';
  iVar3 = 0;
  do {
    if (3 < iVar3) {
LAB_00010340:
      OS_RestoreInterrupts(uVar1);
      return;
    }
    if (((session[iVar3].valid != '\0') && (session[iVar3].ip == aIpAddr)) &&
       (session[iVar3].port == aPort)) {
      MI_CpuCopy8(session + iVar3,&aConn->common1,0x20);
      //MI_CpuCopy8(iVar3 * 0x5c + 0x10028,aConn,0x30);
      uVar2 = CPSi_GetTick();
      session[iVar3].when = uVar2;
      aConn->session_cached = '\x01';
      goto LAB_00010340;
    }
    iVar3 = iVar3 + 1;
  } while( TRUE );
}


void finished_md5(CPSSslConnection *aConn, u8 *aBuf, uint param_3)
{
  CPSMd5Ctx *aMd5Ctx;
  undefined auStack_50 [48];
  
  aMd5Ctx = &aConn->md5_hash;
  if (aConn->server == param_3) {
    CPSi_md5_calc(aMd5Ctx, "CLNT", 4);
  } else {
    CPSi_md5_calc(aMd5Ctx, "SRVR", 4);
  }
  CPSi_md5_calc(aMd5Ctx,aConn,0x30);
  MI_CpuFill8(auStack_50,0x36,0x30);
  CPSi_md5_calc(aMd5Ctx,auStack_50,0x30);
  CPSi_md5_result(aMd5Ctx,aBuf);
  CPSi_md5_init(aMd5Ctx);
  CPSi_md5_calc(aMd5Ctx,aConn,0x30);
  MI_CpuFill8(auStack_50,0x5c,0x30);
  CPSi_md5_calc(aMd5Ctx,auStack_50,0x30);
  CPSi_md5_calc(aMd5Ctx,aBuf,0x10);
  CPSi_md5_result(aMd5Ctx,aBuf);
  return;
}


void finished_sha1(CPSSslConnection *aConn,u8 *aBuf,uint param_3)
{
  CPSSha1Ctx *aSha1Ctx;
  undefined auStack_48 [40];
  
  aSha1Ctx = &aConn->sha1_hash;
  if (aConn->server == param_3) {
    CPSi_sha1_calc(aSha1Ctx, "CLNT",4);
  }
  else {
    CPSi_sha1_calc(aSha1Ctx, "SRVR",4);
  }
  CPSi_sha1_calc(aSha1Ctx,aConn,0x30);
  MI_CpuFill8(auStack_48,0x36,0x28);
  CPSi_sha1_calc(aSha1Ctx,auStack_48,0x28);
  CPSi_sha1_result(aSha1Ctx,aBuf);
  CPSi_sha1_init(aSha1Ctx);
  CPSi_sha1_calc(aSha1Ctx,aConn,0x30);
  MI_CpuFill8(auStack_48,0x5c,0x28);
  CPSi_sha1_calc(aSha1Ctx,auStack_48,0x28);
  CPSi_sha1_calc(aSha1Ctx,aBuf,0x14);
  CPSi_sha1_result(aSha1Ctx,aBuf);
  return;
}


CPSCaInfo * get_rootCA(CPSSslConnection *aConn,char *aIssuer)
{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  while( TRUE ) {
    if (aConn->ca_builtins <= iVar2) {
      return NULL;
    }
    iVar1 = strcmp(aConn->ca_info[iVar2]->dn,aIssuer);
    if (iVar1 == 0) break;
    iVar2 = iVar2 + 1;
  }
  return aConn->ca_info[iVar2];
}


undefined4 has_method(byte *param_1, int param_2, int param_3, ushort param_4)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = 0;
  while( TRUE ) {
    if (param_2 <= iVar2) {
      return 0;
    }
    uVar1 = (uint)*param_1 * 0x100 + (uint)param_1[1];
    if (param_3 == 3) {
      uVar1 = uVar1 * 0x100 + (uint)param_1[2];
    }
    if (uVar1 == param_4) break;
    param_1 = param_1 + param_3;
    iVar2 = iVar2 + 1;
  }
  return 1;
}


int make_ciphertext(CPSSslConnection *aConn, u8 *aBuf)
{
  CPSMd5Ctx *aMd5Ctx;
  CPSSha1Ctx *aSha1Ctx;
  int aLen;
  u8 *puVar1;
  undefined auStack_48 [48];
  
  aLen = (uint)aBuf[3] * 0x100 + (uint)aBuf[4];
  puVar1 = aBuf + aLen + 5; //Pointer to the MAC. directly at the end of the message fragment
  if (aConn->method == 4) {
    aMd5Ctx = &aConn->md5_hash_tmp;
    CPSi_md5_init(aMd5Ctx);
    CPSi_md5_calc(aMd5Ctx,aConn->send_mac,0x10);
    MI_CpuFill8(auStack_48,0x36,0x30);
    CPSi_md5_calc(aMd5Ctx,auStack_48,0x30);
    CPSi_md5_calc(aMd5Ctx,aConn->send_seq,8);
    CPSi_md5_calc(aMd5Ctx,aBuf,1);
    CPSi_md5_calc(aMd5Ctx,aBuf + 3,aLen + 2);
    CPSi_md5_result(aMd5Ctx,puVar1);
    CPSi_md5_init(aMd5Ctx);
    CPSi_md5_calc(aMd5Ctx,aConn->send_mac,0x10);
    MI_CpuFill8(auStack_48,0x5c,0x30);
    CPSi_md5_calc(aMd5Ctx,auStack_48,0x30);
    CPSi_md5_calc(aMd5Ctx,puVar1,0x10);
    CPSi_md5_result(aMd5Ctx,puVar1);
    aLen = aLen + 0x10;
  } else if (aConn->method == 5) {
    aSha1Ctx = &aConn->sha1_hash_tmp;
    CPSi_sha1_init(aSha1Ctx);
    CPSi_sha1_calc(aSha1Ctx,aConn->send_mac,0x14); //mac_write_secret
    MI_CpuFill8(auStack_48,0x36,0x28); //pad_1 RFC6101
    CPSi_sha1_calc(aSha1Ctx,auStack_48,0x28);
    CPSi_sha1_calc(aSha1Ctx,aConn->send_seq,8); //seq_num
    CPSi_sha1_calc(aSha1Ctx,aBuf,1); //SSLType
    CPSi_sha1_calc(aSha1Ctx,aBuf + 3,aLen + 2); //Length + Fragment //NOTE: Investigate sending a large amount of data through SHA1.
    CPSi_sha1_result(aSha1Ctx,puVar1);
    CPSi_sha1_init(aSha1Ctx);
    CPSi_sha1_calc(aSha1Ctx,aConn->send_mac,0x14); //mac_write_Secret
    MI_CpuFill8(auStack_48,0x5c,0x28); //pad_2 RFC6101
    CPSi_sha1_calc(aSha1Ctx,auStack_48,0x28);
    CPSi_sha1_calc(aSha1Ctx,puVar1,0x14); //The hash calculated above
    CPSi_sha1_result(aSha1Ctx,puVar1);
    aLen = aLen + 0x14;
  }
  aBuf[3] = (u8)((uint)aLen >> 8);
  aBuf[4] = (u8)aLen;
  CPSi_rc4_crypt(&(aConn->send_cipher).rc4_ctx,aBuf + 5,aLen);
  //add1_be8((u8 *)&aConn->rcv_mac);
  add1_be8(((u8*)&aConn->send_seq) + 8);
  return aLen + 5;
}


void make_dn(char *param_1, char *param_2, int param_3)
{
  char *pcVar1;
  char *pcVar2;
  
  pcVar1 = param_1;
  if (*param_1 != '\0') {
    do {
      pcVar2 = pcVar1;
      pcVar1 = pcVar2 + 1;
    } while (*pcVar1 != '\0');
    if (0xfe < (int)pcVar1 - (int)param_1) {
      return;
    }
    *pcVar1 = ',';
    pcVar1 = pcVar2 + 3;
    pcVar2[2] = ' ';
  }
  for (; (param_3 != 0 && ((int)pcVar1 - (int)param_1 < 0xff)); pcVar1 = pcVar1 + 1) {
    *pcVar1 = *param_2;
    param_3 = param_3 + -1;
    param_2 = param_2 + 1;
  }
  *pcVar1 = '\0';
  return;
}


int make_plaintext(CPSSslConnection *aConn, u8 *aBuf)
{
  int iVar1;
  int iVar2;
  CPSMd5Ctx *myMd5Ctx;
  CPSSha1Ctx *mySha1Ctx;
  size_t unaff_r8;
  undefined auStack_60 [48];
  undefined auStack_30 [24];
  
  iVar1 = decrypt(aConn, aBuf + 5, (uint)aBuf[3] * 0x100 + (uint)aBuf[4]);
  if (aConn->method == 4) {
    iVar2 = iVar1 + -0x10;
    aBuf[3] = (u8)((uint)iVar2 >> 8);
    aBuf[4] = (u8)iVar2;
    myMd5Ctx = &aConn->md5_hash_tmp;
    CPSi_md5_init(myMd5Ctx);
    CPSi_md5_calc(myMd5Ctx,aConn->rcv_mac,0x10);
    MI_CpuFill8(auStack_60,0x36,0x30);
    CPSi_md5_calc(myMd5Ctx,auStack_60,0x30);
    CPSi_md5_calc(myMd5Ctx,aConn->rcv_seq,8);
    CPSi_md5_calc(myMd5Ctx,aBuf,1);
    CPSi_md5_calc(myMd5Ctx,aBuf + 3,iVar1 + -0xe);
    CPSi_md5_result(myMd5Ctx,auStack_30);
    CPSi_md5_init(myMd5Ctx);
    CPSi_md5_calc(myMd5Ctx,aConn->rcv_mac,0x10);
    MI_CpuFill8(auStack_60,0x5c,0x30);
    CPSi_md5_calc(myMd5Ctx,auStack_60,0x30);
    CPSi_md5_calc(myMd5Ctx,auStack_30,0x10);
    CPSi_md5_result(myMd5Ctx,auStack_30);
    unaff_r8 = 0x10;
    iVar1 = iVar2;
  } else if (aConn->method == 5) {
    iVar2 = iVar1 + -0x14;
    aBuf[3] = (u8)((uint)iVar2 >> 8);
    aBuf[4] = (u8)iVar2;
    mySha1Ctx = &aConn->sha1_hash_tmp;
    CPSi_sha1_init(mySha1Ctx);
    CPSi_sha1_calc(mySha1Ctx,aConn->rcv_mac,0x14);
    MI_CpuFill8(auStack_60,0x36,0x28);
    CPSi_sha1_calc(mySha1Ctx,auStack_60,0x28);
    CPSi_sha1_calc(mySha1Ctx,aConn->rcv_seq,8);
    CPSi_sha1_calc(mySha1Ctx,aBuf,1);
    CPSi_sha1_calc(mySha1Ctx,aBuf + 3,iVar1 + -0x12);
    CPSi_sha1_result(mySha1Ctx,auStack_30);
    CPSi_sha1_init(mySha1Ctx);
    CPSi_sha1_calc(mySha1Ctx,aConn->rcv_mac,0x14);
    MI_CpuFill8(auStack_60,0x5c,0x28);
    CPSi_sha1_calc(mySha1Ctx,auStack_60,0x28);
    CPSi_sha1_calc(mySha1Ctx,auStack_30,0x14);
    CPSi_sha1_result(mySha1Ctx,auStack_30);
    unaff_r8 = 0x14;
    iVar1 = iVar2;
  }
  iVar2 = memcmp(aBuf + iVar1 + 5,auStack_30,unaff_r8);
  if (iVar2 != 0) {
    OSi_TWarning("ssl.c", 1505, "mac mismatch\n");
    aConn->state = CPS_SSL_STATE_FAILURE;
  }
  add1_be8((u8*)&aConn->sha1_hash);
  return iVar1 + 5;
}


undefined4 mustget_change_cipher_spec_and_finished(CPSSoc * aSoc)
{
  uchar uVar1;
  undefined4 uVar2;
  
  uVar1 = parse_record(aSoc);
  if (uVar1 == '\a') {
    uVar1 = parse_record(aSoc);
    if (uVar1 == '\x06') {
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}


int parse2digits(byte *param_1)
{
  return (uint)param_1[1] + (uint)*param_1 * 10 + -0x210;
}


u32 parse_time(u8 *param_1, int param_2)
{
  uint uVar1;
  int month;
  int day;
  int year;
  u8 *puVar5;
  
  uVar1 = parse2digits(param_1);
  puVar5 = param_1 + 2;
  if (param_2 == 0x17) {
    if (uVar1 < 0x32) {
      year = uVar1 + 2000;
    } else {
      year = uVar1 + 0x76c;
    }
  } else {
    year = parse2digits(puVar5);
    year = uVar1 * 100 + year;
    puVar5 = param_1 + 4;
  }
  month = parse2digits(puVar5);
  day = parse2digits(puVar5 + 2);
  return (year * 0x10000) + (month * 0x100) + day;
}


uchar parse_record(CPSSoc *aSoc)
{
  u8 *puVar1;
  int iVar2;
  uint in_r3;
  CPSSslConnection *myConn;
  u32 local_18;
  
  myConn = (CPSSslConnection *)aSoc->con;
  local_18 = in_r3;
  do {
    puVar1 = CPSi_TcpReadRaw(&local_18,aSoc);
    if (local_18 == 0) {
      myConn->state = CPS_SSL_STATE_FAILURE;
      return '\t';
    }
  } while (local_18 < 5);
  if (*puVar1 == 0x80) {
    if ((myConn->server == 0) || (myConn->state != 0)) {
      myConn->state = CPS_SSL_STATE_FAILURE;
    }
    else {
      local_18 = (uint)puVar1[1];
      CPSi_SocConsumeRaw(2, aSoc);
      puVar1 = (u8 *)(*CPSiAlloc)(local_18);
      if (puVar1 == NULL) {
        OSi_TWarning("ssl.c", 0x710, "Failed to allcoate buf\n");
        myConn->state = CPS_SSL_STATE_FAILURE;
        return CPS_SSL_STATE_FAILURE;
      }
      iVar2 = tcp_read_raw_nbytes(puVar1,local_18,aSoc);
      if ((iVar2 == 0) && (*puVar1 == '\x01')) {
        client_hello_v2(myConn,puVar1 + 1);
      }
      else {
        myConn->state = CPS_SSL_STATE_FAILURE;
      }
      update_digest(myConn,puVar1,local_18);
      (*CPSiFree)(puVar1);
    }
  } else {
    local_18 = (uint)puVar1[3] * 0x100 + (uint)puVar1[4] + 5;
    if (0x4805 < local_18) {
      OSi_TWarning("ssl.c", 0x728, "Packet length > 2^14\n");
      myConn->state = CPS_SSL_STATE_FAILURE;
      return CPS_SSL_STATE_FAILURE;
    }
    puVar1 = (u8 *)(*CPSiAlloc)(local_18);
    if (puVar1 == NULL) {
      OSi_TWarning("ssl.c", 0x730, "Failed to allcoate buf\n");
      myConn->state = CPS_SSL_STATE_FAILURE;
      return CPS_SSL_STATE_FAILURE;
    }
    iVar2 = tcp_read_raw_nbytes(puVar1,local_18,aSoc);
    if (iVar2 != 0) {
      (*CPSiFree)(puVar1);
      myConn->state = CPS_SSL_STATE_FAILURE;
      return CPS_SSL_STATE_FAILURE;
    }
    parse_record_in_buf(myConn,puVar1,aSoc);
  }
  return myConn->state;
}


void parse_record_in_buf(CPSSslConnection *aConn, uchar *aBuf, CPSSoc *aSoc)
{
  u8 contentType;
  byte bVar2;
  byte *pbVar3;
  byte *buf;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  if (aConn->state == 9) {
    (*CPSiFree)(aBuf);
  } else {
    contentType = *aBuf;
    uVar4 = (uint)aBuf[3] * 0x100 + (uint)aBuf[4] + 5;
    if (((((aConn->state == 7) || (aConn->state == 8)) && (contentType != 21)) ||
        ((contentType == 21 && (7 < uVar4)))) &&
       (uVar4 = make_plaintext(aConn, aBuf), aConn->state == 9)) {
      (*CPSiFree)(aBuf);
    } else {
      pbVar3 = aBuf + 5;
      iVar5 = uVar4 - 5;
      switch(contentType) {
      case 20: /* Change Cipher Spec */
        if (aConn->rcv_mac == (uchar *)0x0) {
          aConn->state = CPS_SSL_STATE_FAILURE;
        } else {
          MI_CpuClear8(aConn->rcv_seq, 8);
          aConn->state = 7;
        }
        break;
      case 21: /* Alert */
        if (*pbVar3 == 2) {
          /* Fatal Alert Level */
          aConn->state = CPS_SSL_STATE_FAILURE;
        }
        break;
      case 22: /* Handshake */
        do {
          bVar2 = *pbVar3;
          iVar6 = (uint)pbVar3[3] + (uint)pbVar3[1] * 0x10000 + (uint)pbVar3[2] * 0x100;
          buf = pbVar3 + 4;
          if (bVar2 < 0xc) {
            if (bVar2 < 0xb) {
              if ((2 < bVar2) || (bVar2 == 0)) goto switchD_00012a24_caseD_8;
              if (bVar2 == 1) {
                if ((aConn->server != 0) && (aConn->state == 0)) {
                  client_hello(aConn,buf);
                }
              } else {
                if (bVar2 != 2) goto switchD_00012a24_caseD_8;
                rcv_server_hello(aConn,buf);
              }
            } else {
              rcv_certificate(aConn,buf);
              aConn->seen_validity = 0;
            }
            goto LAB_00012adc;
          }
          switch(bVar2) {
          case 0xd:
            aConn->seen_validity = 1;
            goto LAB_00012adc;
          case 0xe:
            aConn->state = '\x04';
            goto LAB_00012adc;
          case 0xf:
            break;
          case 0x10:
            rcv_client_key_exchange(aConn,buf);
            goto LAB_00012adc;
          case 0x11:
            break;
          case 0x12:
            break;
          case 0x13:
            break;
          case 0x14:
            rcv_finished(aConn,buf);
            goto LAB_00012adc;
          }
switchD_00012a24_caseD_8:
          aConn->state = CPS_SSL_STATE_FAILURE;
LAB_00012adc:
          update_digest(aConn,pbVar3,iVar6 + 4);
          pbVar3 = buf + iVar6;
          iVar5 = iVar5 - (iVar6 + 4);
        } while ((iVar5 != 0) && (aConn->state != CPS_SSL_STATE_FAILURE));
        break;
      case 23: /* Application Data */
        aConn->inbuf = aBuf;
        aConn->inbuf_pnt = 5;
        aConn->inbuf_len = uVar4;
        aConn->inbuf_decrypted = 1;
        return;
      default:
        aConn->state = CPS_SSL_STATE_FAILURE;
      }
      (*CPSiFree)(aBuf);
    }
  }
  return;
}


void purge_session(CPSSslConnection * aConn)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = OS_DisableInterrupts();
  iVar3 = 0;
  do {
    if (3 < iVar3) {
LAB_00010500:
      OS_RestoreInterrupts(uVar1);
      return;
    }
    if ((session[iVar3].valid != '\0') &&
       (iVar2 = memcmp(session + iVar3,&aConn->common1,0x20), iVar2 == 0)) {
      session[iVar3].valid = '\0';
      goto LAB_00010500;
    }
    iVar3 = iVar3 + 1;
  } while( TRUE );
}


void rcv_certificate(CPSSslConnection *aConn, u8 *aBuf)
{
  uint no_name;
  uint uVar1;
  int iVar2;
  int no_name1;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  byte *local_44;
  RTCDate theDate;
  byte *local_c [3];
  
  iVar2 = (uint)aBuf[2] + ((uint)*aBuf * 0x100 + (uint)aBuf[1]) * 0x100; //Size of the certificates handshake item
  local_c[0] = aBuf + 3;
  aConn->pub_algorithm = -1;
  RTC_GetDate(&theDate);
  aConn->cur_date = theDate.day + ((theDate.year + 2000) * 0x10000) + (theDate.month * 0x100);
  aConn->subject[0] = '\0';
  aConn->exponent_len = 0;
  aConn->modulus_len = aConn->exponent_len;
  uVar5 = 0;
  no_name1 = 0;
  while( TRUE ) {
    iVar4 = (uint)local_c[0][2] + ((uint)*local_c[0] * 0x100 + (uint)local_c[0][1]) * 0x100; //Size of the certificate
    local_c[0] = local_c[0] + 3;
    iVar2 = iVar2 - (iVar4 + 3);
    aConn->sig_algorithm = -1;
    aConn->seen_pub_algorithm = '\0';
    aConn->seen_validity = '\0';
    aConn->date_ok = '\0';
    aConn->subject[0] = '\0';
    aConn->issuer[0] = '\0';
    aConn->cn[0] = '\0';
    aConn->cert = local_c[0];
    aConn->certlen = iVar4;
    iVar4 = cert_item(aConn,local_c,0,0,uVar5);
    if (((iVar4 != 0) || (aConn->modulus_len < 0x33)) || (aConn->exponent_len == 0)) {
      aConn->state = CPS_SSL_STATE_FAILURE;
      return;
    }
    no_name = auth_cert(aConn);
    if (((no_name1 == 0) && (aConn->server_name != (char *)0x0)) &&
       (iVar4 = compare_fqdn(aConn->server_name, aConn->cn), iVar4 != 0)) {
      no_name = no_name | 0x4000;
    }
    uVar3 = no_name & 0xff;
    if ((uVar3 == 1) && (iVar2 != 0)) {
      local_44 = local_c[0] + 3;
      aConn->seen_pub_algorithm = '\0';
      iVar4 = cert_item(aConn,&local_44,0,0,2);
      if (iVar4 != 0) {
        aConn->state = CPS_SSL_STATE_FAILURE;
        return;
      }
      uVar1 = validate_signature(aConn, &aConn->midca_info);
      no_name = no_name & 0xffffff00 | uVar1;
    }
    if (aConn->auth_callback != NULL) {
      no_name = (*aConn->auth_callback)(no_name,aConn,no_name1);
    }
    no_name1 = no_name1 + 1;
    if (((uVar3 == 0) || (no_name != 0)) || (iVar2 == 0)) break;
    uVar5 = 1;
  }
  if (no_name == 0) {
    aConn->state = 3;
    return;
  }
  aConn->state = CPS_SSL_STATE_FAILURE;
  return;
}


void rcv_client_key_exchange(CPSSslConnection *aConn, u8 *aBuf)
{
  decrypt_premaster_secret(aConn, aBuf, aConn->my_key);
  create_master_secret(aConn);
  cache_session(aConn,0,0);
  create_key_block(aConn);
  aConn->state = 5;
  return;
}


void rcv_finished(CPSSslConnection *aConn, u8 *aBuf)
{
  int iVar1;
  undefined auStack_20 [20];
  
  MI_CpuCopy8(&aConn->md5_hash,&aConn->md5_hash_tmp,0x58);
  finished_md5(aConn,auStack_20,1);
  MI_CpuCopy8(&aConn->md5_hash_tmp,&aConn->md5_hash,0x58);
  iVar1 = memcmp(aBuf,auStack_20,0x10);
  if (iVar1 == 0) {
    MI_CpuCopy8(&aConn->sha1_hash,&aConn->sha1_hash_tmp,0x5c);
    finished_sha1(aConn,auStack_20,1);
    MI_CpuCopy8(&aConn->sha1_hash_tmp,&aConn->sha1_hash,0x5c);
    iVar1 = memcmp(aBuf + 0x10,auStack_20,0x14);
    if (iVar1 == 0) {
      aConn->state = '\x06';
    } else {
      OSi_TWarning("ssl.c", 0x553, "sha1 mismatch\n");
      aConn->state = CPS_SSL_STATE_FAILURE;
    }
  } else {
    OSi_TWarning("ssl.c", 0x546, "md5 mismatch\n");
    aConn->state = CPS_SSL_STATE_FAILURE;
  }
  return;
}


void rcv_server_hello(CPSSslConnection * aConn, u8 * aBuf)
{
  int iVar1;
  u8 *__s2;
  uint uVar2;
  
  MI_CpuCopy8(aBuf + 2,aConn->server_random,0x20);
  __s2 = aBuf + 0x23;
  uVar2 = (uint)aBuf[0x22];
  if (((aConn->session_cached == '\0') || (uVar2 != 0x20)) ||
     (iVar1 = memcmp(&aConn->common1,__s2,0x20), iVar1 != 0)) {
    if (aConn->session_cached != '\0') {
      purge_session(aConn);
    }
    if (uVar2 == 0) {
      aConn->session_cached = '\0';
    }
    else {
      MI_CpuCopy8(__s2,&aConn->common1,0x20);
      aConn->session_cached = '\x01';
    }
    aConn->reuse_session = '\0';
  }
  else {
    aConn->reuse_session = '\x01';
  }
  aConn->method = (ushort)__s2[uVar2] * 0x100 + (ushort)(__s2 + uVar2)[1];
  aConn->state = '\x02';
  return;
}


u16 select_method(u8 * param_1, int param_2, int param_3)
{
  int iVar1;
  uint uVar2;
  
  uVar2 = 0;
  while( TRUE ) {
    if (1 < uVar2) {
      return 0;
    }
    iVar1 = has_method(param_1,param_2,param_3,pairlist[uVar2]);
    if (iVar1 != 0) break;
    uVar2 = uVar2 + 1;
  }
  return pairlist[uVar2];
}


void send_change_cipher_spec_and_finished(CPSSoc *aSoc)
{
  undefined *buf;
  int iVar1;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  buf = (undefined *)(*CPSiAlloc)(0x83);
  if (buf == (undefined *)0x0) {
    //OSi_TWarning(@14013,0x802,@14261);
    myConn->state = CPS_SSL_STATE_FAILURE;
  } else {
    // Record
    *buf = 0x14; // Change Cipher Spec record type
    buf[1] = 3;  // SSLv3
    buf[2] = 0;  // .0
    buf[3] = 0;  // Length
    buf[4] = 1;  // Length (1 byte total)
    buf[5] = 1;  // The actual change cipher spec message
    MI_CpuClear8(myConn->send_seq,8); // Reset the sequence number
    // Record
    buf[6] = 0x16; //Handshake Record type
    buf[7] = 3; // SSLv3
    buf[8] = 0; // .0
    buf[9] = 0; // Length
    buf[10] = 0x28; // Length 
    buf[0xb] = 0x14;
    buf[0xc] = 0;
    buf[0xd] = 0;
    buf[0xe] = 0x24;
    MI_CpuCopy8(&myConn->md5_hash,&myConn->md5_hash_tmp,0x58);
    finished_md5(myConn,buf + 0xf,0); // Commenting out this line results in a HandShake failure!
    MI_CpuCopy8(&myConn->md5_hash_tmp,&myConn->md5_hash,0x58);
    MI_CpuCopy8(&myConn->sha1_hash,&myConn->sha1_hash_tmp,0x5c);
    finished_sha1(myConn,buf + 0x1f,0);
    MI_CpuCopy8(&myConn->sha1_hash_tmp,&myConn->sha1_hash,0x5c);
    update_digest(myConn,buf + 0xb,0x28);
    iVar1 = make_ciphertext(myConn,buf + 6); // Encrypt the Handshake record
    CPSi_TcpWrite2Raw(buf,iVar1 + 6,0,0,aSoc);
    (*CPSiFree)(buf);
  }
  return;
}


void send_client_hello(CPSSoc *aSoc)
{
  undefined *buf;
  undefined4 uVar1;
  undefined *puVar2;
  undefined *puVar3;
  CPSSslConnection *myConn;
  uint uVar4;
  undefined *puVar5;
  
  myConn = (CPSSslConnection *)aSoc->con;
  buf = (undefined *)(*CPSiAlloc)(0x98);
  if (buf == (undefined *)0x0) {
    OSi_TWarning("ssl.c", 2112, "Failed to allcoate buf\n");
    myConn->state = CPS_SSL_STATE_FAILURE;
  } else {
    buf[9] = 3; //Client version
    buf[10] = 0;
    uVar1 = date2sec();
    myConn->client_random[0] = (uchar)((uint)uVar1 >> 0x18);
    myConn->client_random[1] = (uchar)((uint)uVar1 >> 0x10);
    myConn->client_random[2] = (uchar)((uint)uVar1 >> 8);
    myConn->client_random[3] = (uchar)uVar1;
    set_random(myConn->client_random + 4, 0x1c);
    MI_CpuCopy8(myConn->client_random, buf + 0xb, 0x20);
    find_session_from_IP(myConn, aSoc->remote_ip, aSoc->remote_port);
    if (myConn->session_cached == '\0') {
      puVar2 = buf + 0x2c;
      buf[0x2b] = 0;
    } else {
      buf[0x2b] = 0x20;
      MI_CpuCopy8(&myConn->common1, buf + 0x2c, 0x20);
      puVar2 = buf + 0x4c;
    }
    *puVar2 = 0;
    puVar2[1] = 4; //Cipher suites length ??
    for (uVar4 = 0; puVar3 = puVar2 + 2, uVar4 < 2; uVar4 = uVar4 + 1) {
      *puVar3 = (char)(pairlist[uVar4] >> 8);
      puVar2[3] = (char)pairlist[uVar4];
      puVar2 = puVar3;
    }
    *puVar3 = 1;
    puVar2[3] = 0;
    #ifdef SDK_PORT
    u32 temp = (u64)puVar2 + (-1 - (u64)buf);
    #else
    puVar3 = puVar2 + (-1 - (int)buf);
    #endif
    buf[0] = 0x16; //Handshake record
    buf[1] = 3; //Protocol major version
    buf[2] = 0; //Protocol minor version
    #ifdef SDK_PORT
    buf[3] = (char)((uint)temp >> 8); //Handshake message size
    buf[4] = (char)temp;
    #else
    buf[3] = (char)((uint)puVar3 >> 8);
    buf[4] = (char)puVar3;
    #endif
    #ifdef SDK_PORT
    puVar5 = puVar2 + (-5 - (u64)buf);
    #else
    puVar5 = puVar2 + (-5 - (int)buf);
    #endif
    buf[5] = 1; //Client hello handshake message type
    buf[6] = (char)((uint)puVar5 >> 0x10); //Size of client hello message
    buf[7] = (char)((uint)puVar5 >> 8);
    buf[8] = (char)puVar5;
    CPSi_TcpWrite2Raw(buf, ((u64)puVar2 + (4 - (u64)buf)), 0, 0, aSoc);
    #ifdef SDK_PORT
    update_digest(myConn, buf + 5, temp);
    #else
    update_digest(myConn, buf + 5, *puVar3);
    #endif
    (*CPSiFree)(buf);
  }
  return;
}


void send_client_key_exchange(CPSSoc * aSoc)
{
  u8 *tmp;
  u16 *tmp_var;
  u16 *puVar2;
  u16 *puVar3;
  undefined4 uVar4;
  u8 *buf;
  undefined *puVar6;
  undefined *puVar7;
  CPSSslConnection *aConn;
  uint uVar8;
  int iVar9;
  
  aConn = (CPSSslConnection *)aSoc->con;
  if (aConn->seen_validity != '\0') {
    CPSi_TcpWrite2Raw("\x15\x03",7,0,0,aSoc);
  }

  //RFC6101 5.6.7.1 RSA Encrypted Premaster Secret Message
  aConn->master_secret[0] = '\x03'; //SSLv3
  aConn->master_secret[1] = '\0';
  set_random(aConn->master_secret + 2,0x2e); // 46 Random bytes
  uVar8 = aConn->modulus_len;
  iVar9 = (int)(uVar8 * 2) / 2;
  tmp = (u8 *)(*CPSiAlloc)(uVar8);
  if (tmp == NULL) {
    OSi_TWarning("ssl.c", 0x899, "Failed to allcoate tmp\n");
    aConn->state = CPS_SSL_STATE_FAILURE;
  } else {
    *tmp = 0;
    tmp[1] = 2;
    set_random(tmp + 2,uVar8 - 0x33);
    tmp[uVar8 - 0x31] = 0;
    MI_CpuCopy8(aConn, tmp + (uVar8 - 0x30), 0x30);
    tmp_var = (u16 *)(*CPSiAlloc)(iVar9 << 3);
    if (tmp_var == NULL) {
      OSi_TWarning("ssl.c", 0x8a9, "Failed to allcoate tmp_var\n");
      (*CPSiFree)(tmp);
      aConn->state = CPS_SSL_STATE_FAILURE;
    } else {
      puVar2 = tmp_var + iVar9;
      puVar3 = puVar2 + iVar9;
      CPSi_big_from_char(puVar2,tmp,uVar8,iVar9);
      CPSi_big_from_char(puVar3,aConn->exponent,aConn->exponent_len,iVar9);
      CPSi_big_from_char(puVar3 + iVar9,aConn->modulus,uVar8,iVar9);
      uVar4 = enter_computebound();
      CPSi_big_power(tmp_var,puVar2,puVar3,iVar9,puVar3 + iVar9);
      exit_computebound(uVar4);
      buf = (u8 *)(*CPSiAlloc)(uVar8 + 0x49);
      if (buf == NULL) {
        OSi_TWarning("ssl.c", 0x8c0, "Failed to allcoate buf\n");
        (*CPSiFree)(tmp);
        (*CPSiFree)(tmp_var);
        aConn->state = CPS_SSL_STATE_FAILURE;
      } else {
        *buf = 22; // Handshake
        buf[1] = 3;
        buf[2] = 0;
        buf[3] = (char)(uVar8 + 4 >> 8);
        buf[4] = (char)uVar8 + '\x04';
        buf[5] = 0x10;
        buf[6] = (char)(uVar8 >> 0x10);
        buf[7] = (char)(uVar8 >> 8);
        buf[8] = (char)uVar8;
        puVar6 = buf + 9;
        if ((uVar8 & 1) != 0) {
          puVar6 = buf + 10;
          buf[9] = (char)tmp_var[(int)uVar8 / 2];
        }
        iVar9 = (int)uVar8 / 2;
        while (iVar9 = iVar9 + -1, -1 < iVar9) {
          puVar7 = puVar6 + 1;
          *puVar6 = (char)(tmp_var[iVar9] >> 8);
          puVar6 = puVar6 + 2;
          *puVar7 = (char)tmp_var[iVar9];
        }
        CPSi_TcpWrite2Raw(buf, uVar8 + 9, 0, 0, aSoc);
        update_digest(aConn, buf + 5, uVar8 + 4);  // If this line is commented out we will get a Handshake Failure (which is different from the Encrypted alert)
        (*CPSiFree)(buf);
        (*CPSiFree)(tmp_var);
        (*CPSiFree)(tmp);
      }
    }
  }
  return;
}


uchar send_server_hello(CPSSoc *aSoc)
{
  char cVar1;
  uchar uVar2;
  undefined4 curTime;
  undefined *buf;
  undefined *puVar3;
  undefined *puVar4;
  CPSSslConnection *myConn;
  int myCertLen;
  CPSCertificate *myCert;
  //
  //myConn = (CPSSslConnection *)aSoc->con;
  //myCert = myConn->my_certificate;
  //if (myCert == (CPSCertificate *)0x0) {
  //  myCertLen = 0;
  //} else {
  //  myCertLen = myCert->certificate_len;
  //}
  //curTime = date2sec();
  //myConn->server_random[0] = (uchar)((uint)curTime >> 0x18);
  //myConn->server_random[1] = (uchar)((uint)curTime >> 0x10);
  //myConn->server_random[2] = (uchar)((uint)curTime >> 8);
  //myConn->server_random[3] = (uchar)curTime;
  //set_random(myConn->server_random + 4,0x1c);
  //buf = (undefined *)(*CPSiAlloc)(myCertLen + 0x9d);
  //if (buf == (undefined *)0x0) {
  //  OSi_TWarning(_14013,0x7a2,_14261);
  //  myConn->state = CPS_SSL_STATE_FAILURE;
  //  uVar2 = '\x01';
  //} else {
  //  buf[5] = 2;
  //  buf[6] = 0;
  //  buf[7] = 0;
  //  buf[8] = 0x46;
  //  buf[9] = 3;
  //  buf[10] = 0;
  //  MI_CpuCopy8(myConn->server_random,buf + 0xb,0x20);
  //  buf[0x2b] = 0x20;
  //  if (myConn->session_cached == '\0') {
  //    set_random(buf + 0x2c,0x1c);
  //    buf[0x48] = (char)(cnt >> 0x18);
  //    buf[0x49] = (char)(cnt >> 0x10);
  //    buf[0x4a] = (char)(cnt >> 8);
  //    buf[0x4b] = (char)cnt;
  //    MI_CpuCopy8(buf + 0x2c,&myConn->common1,0x20);
  //    cnt = cnt + 1;
  //    myConn->reuse_session = '\0';
  //  } else {
  //    MI_CpuCopy8(&myConn->common1,buf + 0x2c,0x20);
  //    myConn->reuse_session = '\x01';
  //  }
  //  buf[0x4c] = (char)(myConn->method >> 8);
  //  buf[0x4d] = (char)myConn->method;
  //  puVar3 = buf + 0x4f;
  //  buf[0x4e] = 0;
  //  if (myConn->reuse_session == '\0') {
  //    if (myCertLen != 0) {
  //      *puVar3 = 0xb;
  //      buf[0x50] = (char)((uint)(myCertLen + 6) >> 0x10);
  //      buf[0x51] = (char)((uint)(myCertLen + 6) >> 8);
  //      cVar1 = (char)myCertLen;
  //      buf[0x52] = cVar1 + '\x06';
  //      buf[0x53] = (char)((uint)(myCertLen + 3) >> 0x10);
  //      buf[0x54] = (char)((uint)(myCertLen + 3) >> 8);
  //      buf[0x55] = cVar1 + '\x03';
  //      buf[0x56] = (char)((uint)myCertLen >> 0x10);
  //      buf[0x57] = (char)((uint)myCertLen >> 8);
  //      buf[0x58] = cVar1;
  //      MI_CpuCopy8(myCert->certificate,buf + 0x59,myCertLen);
  //      puVar3 = buf + 0x59 + myCertLen;
  //    }
  //    *puVar3 = 0xe;
  //    puVar3[1] = 0;
  //    puVar4 = puVar3 + 3;
  //    puVar3[2] = 0;
  //    puVar3 = puVar3 + 4;
  //    *puVar4 = 0;
  //  }
  //  myCertLen = ((int)puVar3 - (int)buf) + -5;
  //  *buf = 0x16;
  //  buf[1] = 3;
  //  buf[2] = 0;
  //  buf[3] = (char)((uint)myCertLen >> 8);
  //  buf[4] = (char)myCertLen;
  //  update_digest(myConn,buf + 5,myCertLen);
  //  CPSi_TcpWrite2Raw(buf,(int)puVar3 - (int)buf,0,0,aSoc);
  //  //(*CPSiFree)(buf);
  //  uVar2 = myConn->reuse_session;
  //}
  return uVar2;
}


void set_random(u8 *aBuf, int aLen)
{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 local_a0;
  byte local_9c [20];
  CPSSha1Ctx mySha1Ctx;
  
  if (pool_initialized == '\0') {
    local_a0 = MATH_Rand32(&CPSiRand32ctx,0);
    CPS_SslAddRandomSeed(&local_a0,4);
  }
  iVar2 = 0x14;
  iVar4 = 0;
  while (iVar4 < aLen) {
    if (iVar2 == 0x14) {
      CPSi_sha1_init(&mySha1Ctx);
      uVar1 = OS_DisableInterrupts();
      CPSi_sha1_calc(&mySha1Ctx,pool,0x14);
      //CPSi_sha1_result_prng(&mySha1Ctx,local_9c); // Not Implemented!!!
      CPSi_sha1_result(&mySha1Ctx,local_9c);
      uVar5 = 1;
      for (iVar2 = 0x13; -1 < iVar2; iVar2 = iVar2 + -1) {
        local_a0 = uVar5 + (uint)pool[iVar2] + (uint)local_9c[iVar2];
        pool[iVar2] = (uchar)local_a0;
        uVar5 = local_a0 >> 8;
      }
      OS_RestoreInterrupts(uVar1);
      iVar2 = 0;
    }
    iVar3 = iVar4;
    if (local_9c[iVar2] != 0) {
      iVar3 = iVar4 + 1;
      aBuf[iVar4] = local_9c[iVar2];
    }
    iVar2 = iVar2 + 1;
    iVar4 = iVar3;
  }
  return;
}


undefined4 ssl_connect_try(CPSSoc *aSoc)
{
  uchar uVar1;
  int iVar2;
  CPSSslConnection *myConn;
  
  myConn = (CPSSslConnection *)aSoc->con;
  send_client_hello(aSoc);
  do {
    uVar1 = parse_record(aSoc);
    if (uVar1 == 9) {
      return 1;
    }
  } while ((uVar1 != '\x04') && (myConn->reuse_session == FALSE));

  if (myConn->reuse_session == FALSE) {
    send_client_key_exchange(aSoc);
    create_master_secret(myConn);
    if (myConn->session_cached != '\0') {
      cache_session(myConn, aSoc->remote_ip, aSoc->remote_port);
    }
    create_key_block(myConn);
    send_change_cipher_spec_and_finished(aSoc);
    iVar2 = mustget_change_cipher_spec_and_finished(aSoc);
    if (iVar2 != 0) {
      return 1;
    }
  } else {
    create_key_block(myConn);
    iVar2 = mustget_change_cipher_spec_and_finished(aSoc);
    if (iVar2 != 0) {
      return 1;
    }
    send_change_cipher_spec_and_finished(aSoc);
  }
  myConn->state = '\b';
  return 0;
}


undefined4 ssl_listen_try(CPSSoc *aSoc)
{
  //uchar uVar1;
  //int iVar2;
  //
  //uVar1 = parse_record(aSoc);
  //if (uVar1 != '\x01') {
  //  return 1;
  //}
  //iVar2 = send_server_hello(aSoc);
  //if (iVar2 == 0) {
  //  uVar1 = parse_record(aSoc);
  //  if (uVar1 != '\x05') {
  //    return 1;
  //  }
  //  iVar2 = mustget_change_cipher_spec_and_finished(aSoc);
  //  if (iVar2 != 0) {
  //    return 1;
  //  }
  //  send_change_cipher_spec_and_finished(aSoc);
  //}
  //else {
  //  create_key_block(aSoc->con);
  //  send_change_cipher_spec_and_finished(aSoc);
  //  iVar2 = mustget_change_cipher_spec_and_finished(aSoc);
  //  if (iVar2 != 0) {
  //    return 1;
  //  }
  //}
  return 0;
}


u32 tcp_read_raw_nbytes(u8 *aBuf, u32 aLen, CPSSoc *aSoc)
{
  u8 *puVar1;
  uint in_r3;
  u32 local_18;
  
  local_18 = in_r3;
  do {
    puVar1 = CPSi_TcpReadRaw(&local_18,aSoc);
    if (local_18 == 0) {
      return 0xffffffff;
    }
    if (aLen < local_18) {
      local_18 = aLen;
    }
    MI_CpuCopy8(puVar1,aBuf,local_18);
    CPSi_SocConsumeRaw(local_18,aSoc);
    aBuf = aBuf + local_18;
    aLen = aLen - local_18;
  } while (0 < (int)aLen);
  return 0;
}


void try_fill_record(CPSSoc *aSoc)
{
  u8 *puVar1;
  uchar *buf;
  CPSSoc *aSoc_00;
  u32 in_r3;
  CPSSslConnection *myConn;
  BOOL bVar2;
  u32 local_18;
  
  myConn = (CPSSslConnection *)aSoc->con;
  if (myConn->inbuf == (uchar *)0x0) {
    if (aSoc->rcvbufp < 5) {
      return;
    }
    puVar1 = CPSi_TcpReadRaw(&local_18,aSoc);
    local_18 = (uint)puVar1[3] * 0x100 + (uint)puVar1[4] + 5;
    if (0x4805 < local_18) {
      OSi_TWarning("ssl.c", 0x9db, "Packet length > 2^14\n");
      myConn->state = CPS_SSL_STATE_FAILURE;
      return;
    }
    buf = (uchar *)(*CPSiAlloc)(local_18);
    myConn->inbuf = buf;
    if (myConn->inbuf == NULL) {
      OSi_TWarning("ssl.c", 0x9e3, "Failed to allocate buf\n");
      myConn->state = CPS_SSL_STATE_FAILURE;
      return;
    }
    myConn->inbuf_len = local_18;
    myConn->inbuf_pnt = 0;
    myConn->inbuf_decrypted = 0;
  } else {
    local_18 = in_r3;
    if (aSoc->rcvbufp == 0) {
      return;
    }
  }
  puVar1 = CPSi_TcpReadRaw(&local_18,aSoc);
  bVar2 = local_18 < (uint)(myConn->inbuf_len - myConn->inbuf_pnt);
  if (!bVar2) {
    local_18 = myConn->inbuf_len - myConn->inbuf_pnt;
  }
  aSoc_00 = (CPSSoc *)local_18; //TODO: this is probably wrong
  MI_CpuCopy8(puVar1, myConn->inbuf + myConn->inbuf_pnt, local_18);

  CPSi_SocConsumeRaw(local_18, aSoc);
  if (bVar2) {
    myConn->inbuf_pnt = myConn->inbuf_pnt + local_18;
  } else {
    parse_record_in_buf(myConn, myConn->inbuf, aSoc);
    if (myConn->inbuf_decrypted == 0) {
      myConn->inbuf = NULL;
    }
  }
  return;
}


void update_digest(CPSSslConnection *aConn,u8 *param_2, int param_3)
{
  CPSi_sha1_calc(&aConn->sha1_hash,param_2,param_3);
  CPSi_md5_calc(&aConn->md5_hash,param_2,param_3);
  return;
}


undefined4 validate_signature(CPSSslConnection *aConn, CPSCaInfo *aCaInfo)
{
  u16 *tmp_var;
  u16 *puVar2;
  undefined4 uVar3;
  int iVar4;
  u16 *puVar5;
  undefined4 ret;

#ifdef SDK_PORT
  //TODO: REMOVE ME!!!
  //return 0;
#endif
  
  // Ensure we have a signature, signature length, exponent, exponent len
  // modulus, and modulus len
  if ((((aConn->signature == NULL) || (aConn->signature_len == 0)) ||
      (aCaInfo->exponent == NULL)) ||
     (((aCaInfo->exponent_len == 0 || (aCaInfo->modulus == NULL)) ||
      (aCaInfo->modulus_len == 0)))) {
    // One of the above was invalid
    ret = 2;
  } else {
    // Has signature, exponent, and modulus
    iVar4 = (aCaInfo->modulus_len * 2) / 2;
    tmp_var = (u16 *)(*CPSiAlloc)(iVar4 << 3);
    if (tmp_var == NULL) {
      OSi_TWarning("ssl.c", 677, "Failed to allcoate tmp_var\n");
      ret = 2;
    } else {
      puVar5 = tmp_var + iVar4;
      puVar2 = puVar5 + iVar4;
      CPSi_big_from_char(puVar5, aConn->signature, aConn->signature_len, iVar4);
      CPSi_big_from_char(puVar2, aCaInfo->exponent, aCaInfo->exponent_len, iVar4);
      CPSi_big_from_char(puVar2 + iVar4, aCaInfo->modulus, aCaInfo->modulus_len, iVar4);
      uVar3 = enter_computebound();
      CPSi_big_power(tmp_var, puVar5, puVar2, iVar4, puVar2 + iVar4);
      exit_computebound(uVar3);
      CPSi_char_from_big((u8 *)puVar5,tmp_var,aCaInfo->modulus_len,iVar4);
      ret = 0;


      // What the hell are we doing here
      if ((*(char *)puVar5 == '\0') && (*(char *)((u8*)puVar5 + 1) == '\x01')) {

        for (iVar4 = 2; (iVar4 < aCaInfo->modulus_len && (*(char *)((u8*)puVar5 + iVar4) == -1)); iVar4++) {
        }
        if ((((aCaInfo->modulus_len <= iVar4 + 1) || (*(char *)((u8*)puVar5 + iVar4) != '\0')) ||
            (*(char *)((u8*)puVar5 + iVar4 + 1) != '0')) ||
           (iVar4 = memcmp(aConn->hash_val,
                           (void *)((u8*)puVar5 + (aCaInfo->modulus_len - aConn->hash_len)),
                           aConn->hash_len), iVar4 != 0)) {
          // something didnt verify right
          ret = 2;
        }
      } else {
        //something didnt verify right
        ret = 2;
      }
      (*CPSiFree)(tmp_var);
    }
  }
  return ret;
}


BOOL version_ok(char param_1)
{
  return param_1 == '\x03';
}