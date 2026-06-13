#ifndef DECOMP_DEFS_NITROWIFI_H
#define DECOMP_DEFS_NITROWIFI_H

#define CONCAT11(x,y) ( ((u16)x) << 8 ) | (u8)y

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned long long    qword;
typedef int    sdword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined7;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef unsigned short unsigned_short;
typedef unsigned long long unsigned_long_long;
typedef unsigned long unsigned_long;

typedef uchar WBTCommandCounter;

typedef int BOOL;

typedef struct FORMAT FORMAT, *PFORMAT;

struct FORMAT {
  uchar type;
  uchar leftjustify;
  uchar sign;
  uchar padding;
  unsigned long width;
};

typedef struct {
  u16 identification;
  u16 flags;
  u16 numQuestions;
  u16 numAnswerRRs;
  u16 numAuthorityRRs;
  u16 numAdditionalRRs;
  char hostname[48];
} DnsQuery_t;


enum {
  CPS_SSL_STATE_0,
  CPS_SSL_STATE_1,
  CPS_SSL_STATE_2,
  CPS_SSL_STATE_3,
  CPS_SSL_STATE_4,
  CPS_SSL_STATE_5,
  CPS_SSL_STATE_6,
  CPS_SSL_STATE_7,
  CPS_SSL_STATE_8,
  CPS_SSL_STATE_FAILURE,
};

extern s32     WCM_SendDCFDataEx(const u8* dstAddr, const u8* header, s32 headerLen,
                          const u8* body, s32 bodyLen);

static inline u32 CONCAT22(u16 left, u16 right)
{
  u32 result = 0;
  result |= (((u32)left) << 16);
  result |= right;
  return result;
}

static inline u64 CONCAT24(u16 left, u32 right)
{
  u64 result = 0;
  result |= (((u64)left) << 32);
  result |= right;
  return result;
}


static inline u64 CONCAT44(u32 left, u32 right)
{
  u64 result = 0;
  result |= (((u64)left) << 32) & 0xffffffff00000000;
  result |= right;
  return result;
}

static inline int CARRY4(u32 p1, u32 p2)
{
  u64 tmp = p1 + p2;
  return tmp > 4294967295;
}

//biginteger.c Procedures
void CPSi_big_add_part(u16 *param_1, uint param_2, int param_3, int param_4);
void CPSi_big_add_small(u16 *param_1, u16 *param_2, u16 param_3, int param_4);
undefined4 CPSi_big_compare(u16 *param_1, u16 *param_2, int param_3);
void CPSi_big_modinv(u16 *param_1,u16 * param_2,u16 *param_3,int param_4,u16 *param_5);
void CPSi_big_montmult(u16 *param_1, u16 *param_2, u16 *param_3, int param_4, int param_5, u16 *param_6,
                       u16 *param_7, u16 *param_8, u16 *param_9);
void CPSi_big_mult_small(u16 *param_1, u16 *param_2, uint param_3, int param_4);
void CPSi_big_sqr(u16 *param_1, u16 *param_2, int param_3);
void CPSi_big_sub_small(u16 *param_1, u16 *param_2, u16 param_3, int param_4);

#endif