#include <nitro.h>
#include <nitroWiFi.h>
#include <nitroWiFi/decomp/decomp_defs_nitrowifi.h>

static int count_digits(u16 *param_1, int param_2);
static u64 get48bits_1(u16 *param_1);
static u64 get48bits_2(u16 *param_1);
static u64 get48bits_3(u16 *param_1);
static u64 get64bits(u16 *param_1);


void CPSi_big_add(u16 *param_1, u16 *param_2, u16 *param_3, int param_4)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = count_digits(param_2,param_4);
  iVar2 = count_digits(param_3,param_4);
  if (iVar1 < iVar2) {
    iVar1 = iVar2;
  }
  if (iVar1 != param_4) {
    iVar1 = iVar1 + 1;
  }
  uVar3 = 0;
  for (iVar2 = 0; iVar2 < iVar1; iVar2 = iVar2 + 1) {
    uVar3 = uVar3 + (uint)param_2[iVar2] + (uint)param_3[iVar2];
    param_1[iVar2] = (u16)(uVar3 * 0x10000 >> 0x10);
    uVar3 = uVar3 >> 0x10;
  }
  if ((param_1 != param_2) && (param_1 != param_3)) {
    MI_CpuClear8(param_1 + iVar2,(param_4 - iVar2) * 2);
  }
  return;
}


void CPSi_big_add_part(u16 *param_1, uint param_2, int param_3, int param_4)
{
  ushort uVar1;
  
  for (; (param_2 != 0 && (param_3 < param_4)); param_3 = param_3 + 1) {
    uVar1 = param_1[param_3];
    param_1[param_3] = (u16)((param_2 + uVar1) * 0x10000 >> 0x10);
    param_2 = param_2 + uVar1 >> 0x10;
  }
  return;
}


void CPSi_big_add_small(u16 *param_1, u16 *param_2, u16 param_3, int param_4)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = (uint)param_3;
  for (iVar3 = 0; iVar3 < param_4; iVar3 = iVar3 + 1) {
    uVar1 = param_2[iVar3];
    param_1[iVar3] = (u16)((uVar2 + uVar1) * 0x10000 >> 0x10);
    uVar2 = uVar2 + uVar1 >> 0x10;
    if (uVar2 == 0) break;
  }
  if (param_1 != param_2) {
    while (iVar3 = iVar3 + 1, iVar3 < param_4) {
      param_1[iVar3] = param_2[iVar3];
    }
  }
  return;
}


undefined4 CPSi_big_compare(u16 *param_1, u16 *param_2, int param_3)
{
  while( TRUE ) {
    param_3 = param_3 + -1;
    if (param_3 < 0) {
      return 0;
    }
    if (param_2[param_3] < param_1[param_3]) break;
    if (param_1[param_3] < param_2[param_3]) {
      return 0xffffffff;
    }
  }
  return 1;
}


void CPSi_big_div(u16 *aQuotient, u16 *aDividend, u16 *aDivisor, u16 *aRemainder, int aLen, u16 *aWksp)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  u16 *__src;
  u16 *puVar4;
  int iVar5;
  undefined8 uVar6;
  u64 uVar7;
  undefined4 local_40;
  undefined4 local_3c;
  
  __src = aWksp + aLen;
  puVar4 = __src + aLen;
  MI_CpuClear8(__src, aLen << 2);
  iVar1 = count_digits(aDividend, aLen);
  iVar2 = count_digits(aDivisor, aLen);

  if ((0 < iVar1) && (0 < iVar2)) {
    iVar5 = iVar2 + (aLen - iVar1) + -1;
    if (iVar5 < aLen) {
      MI_CpuCopy8(aDividend, __src + iVar5,iVar1 << 1);
      if (iVar2 < 3) {
        if (iVar2 < 2) {
          uVar6 = get48bits_1(aDivisor + iVar2 + -1);
        } else {
          uVar6 = get48bits_2(aDivisor + iVar2 + -1);
        }
      } else {
        uVar6 = get48bits_3(aDivisor + iVar2 + -1);
      }

      while( TRUE ) {
        local_3c = (undefined4)((ulonglong)uVar6 >> 0x20);
        local_40 = (undefined4)uVar6;
        if (aLen <= iVar5) break;
        memmove(__src + 1,__src,(aLen * 2 + -1) * 2);
        uVar7 = get64bits(puVar4 + iVar2);
#ifdef SDK_PORT
        //uVar3 = uVar7 / (((u64)local_3c << 32) | (u64) local_40);

        uVar3 = uVar7 / uVar6;
#else
        uVar3 = _ll_udiv((int)uVar7, (int)(uVar7 >> 0x20), local_40, local_3c);
#endif

        if (0xffff < uVar3) {
          uVar3 = 0xffff;
        }

        while( TRUE ) {
          CPSi_big_mult_small(aWksp, aDivisor, uVar3 & 0xffff, aLen);
          iVar1 = CPSi_big_compare(puVar4, aWksp, aLen);
          if (-1 < iVar1) break;
          uVar3 = uVar3 - 1;
        }

        CPSi_big_sub(puVar4, puVar4, aWksp, aLen);
        *__src = (u16)uVar3;
        iVar5 = iVar5 + 1;
      }
    } else {
      MI_CpuCopy8(aDividend, puVar4, aLen << 1);
    }
  }

  if (aQuotient != (u16 *)0x0) {
    MI_CpuCopy8(__src, aQuotient, aLen << 1);
  }

  if (aRemainder != NULL) {
    MI_CpuCopy8(puVar4, aRemainder, aLen << 1);
  }

  return;
}


void CPSi_big_from_char(u16 *param_1,u8 *param_2,int param_3,int param_4)
{
  byte *pbVar1;
  
  MI_CpuClear8(param_1,param_4 << 1);
  pbVar1 = param_2 + param_3 + -1;
  for (; 1 < param_3; param_3 = param_3 + -2) {
    *param_1 = (ushort)*pbVar1 + (ushort)pbVar1[-1] * 0x100;
    pbVar1 = pbVar1 + -2;
    param_1 = param_1 + 1;
  }
  if (0 < param_3) {
    *param_1 = (ushort)*pbVar1;
  }
  return;
}


void CPSi_big_modinv(u16 *param_1,u16 * param_2,u16 *param_3,int param_4,u16 *param_5)
{
  int iVar1;
  u16 *puVar2;
  u16 *puVar3;
  u16 *puVar4;
  u16 *puVar5;
  u16 *puVar6;
  
  puVar6 = param_5 + param_4;
  puVar5 = puVar6 + param_4;
  puVar3 = puVar5 + param_4;
  puVar4 = puVar3 + param_4;
  puVar2 = puVar4 + param_4;
  MI_CpuCopy8(param_2,param_5,param_4 << 1);
  MI_CpuCopy8(param_3,puVar5,param_4 << 1);
  *puVar3 = 1;
  while (iVar1 = CPSi_big_sign(param_5,param_4), 0 < iVar1) {
    CPSi_big_div(puVar6,puVar5,param_5,puVar2,param_4,puVar2 + param_4);
    MI_CpuCopy8(param_5,puVar5,param_4 << 1);
    MI_CpuCopy8(puVar2,param_5,param_4 << 1);
    CPSi_big_mult(puVar2,puVar6,puVar3,param_4);
    CPSi_big_sub(puVar2,puVar4,puVar2,param_4);
    MI_CpuCopy8(puVar3,puVar4,param_4 << 1);
    MI_CpuCopy8(puVar2,puVar3,param_4 << 1);
  }
  CPSi_big_add(puVar4,puVar4,param_3,param_4);
  CPSi_big_div((u16 *)0x0,puVar4,param_3,param_1,param_4,puVar2 + param_4);
  return;
}


void CPSi_big_montmult(u16 *param_1, u16 *param_2, u16 *param_3, int param_4, int param_5, u16 *param_6,
                       u16 *param_7, u16 *param_8, u16 *param_9)
{
  int iVar1;
  
  MI_CpuCopy8(param_1,param_2,param_4 << 1);
  if (param_3 == (u16 *)0x1) {
    CPSi_big_sqr(param_1,param_2,param_4);
  }
  else if (param_3 != (u16 *)0x0) {
    CPSi_big_mult(param_1,param_2,param_3,param_4);
  }
  CPSi_big_mult(param_8,param_1,param_7,param_5);
  MI_CpuClear8(param_8 + param_5,(param_4 - param_5) * 2);
  CPSi_big_mult(param_9,param_8,param_6,param_4);
  CPSi_big_add(param_1,param_1,param_9,param_4);
  memmove(param_1,param_1 + param_5,(param_4 - param_5) * 2);
  MI_CpuClear8(param_1 + (param_4 - param_5),param_5 << 1);
  iVar1 = CPSi_big_compare(param_1,param_6,param_4);
  if (iVar1 == 0) {
    MI_CpuClear8(param_1,param_4 << 1);
  }
  else if (iVar1 == 1) {
    CPSi_big_sub(param_1,param_1,param_6,param_4);
  }
  return;
}


void CPSi_big_montpower(u16 *param_1,u16 *param_2,u16 *param_3,int param_4,u16 *param_5)
{
  u16 *puVar1;
  u16 *puVar2;
  u16 *puVar3;
  u16 *puVar4;
  int iVar5;
  u16 *puVar6;
  u16 *puVar7;
  u16 *puVar8;
  uint local_34;
  
  if (((param_1 == param_2) || (param_1 == param_3)) || (param_1 == param_5)) {
    OSi_TWarning("biginteger.c", 0x223, "dst == src\n");
  }
  puVar1 = (u16 *)(*CPSiAlloc)(param_4 * 0x16);
  if (puVar1 == (u16 *)0x0) {
    OSi_TWarning("biginteger.c", 0x229, "Failed to allocate tmp\n");
  } else {
    MI_CpuClear8(puVar1,param_4 * 0x16);
    puVar6 = puVar1 + param_4;
    puVar7 = puVar6 + param_4;
    puVar8 = puVar7 + param_4;
    puVar2 = puVar8 + param_4;
    puVar3 = puVar2 + param_4;
    puVar4 = puVar3 + param_4;
    iVar5 = count_digits(param_5,param_4);
    puVar1[iVar5] = 1;
    CPSi_big_modinv(puVar6,puVar1,param_5,param_4,puVar7);
    CPSi_big_mult(puVar8,puVar1,puVar6,param_4);
    CPSi_big_sub_small(puVar6,puVar8,1,param_4);
    CPSi_big_div(puVar6,puVar6,param_5,(u16 *)0x0,param_4,puVar4);
    CPSi_big_mult(puVar7,param_2,puVar1,param_4);
    CPSi_big_div((u16 *)0x0,puVar7,param_5,puVar7,param_4,puVar4);
    CPSi_big_div((u16 *)0x0,puVar1,param_5,param_1,param_4,puVar4);
    for (local_34 = 0; local_34 < (uint)(iVar5 << 4); local_34 = local_34 + 1) {
      CPSi_big_montmult(param_1, puVar3, (u16*)1,param_4,iVar5,param_5,puVar6,puVar8,puVar2);
      if ((0x8000U >> (local_34 & 0xf) & (uint)param_3[(iVar5 - ((int)local_34 >> 4)) + -1]) != 0) {
        CPSi_big_montmult(param_1,puVar3,puVar7,param_4,iVar5,param_5,puVar6,puVar8,puVar2);
      }
    }
    CPSi_big_montmult(param_1,puVar3,0,param_4,iVar5,param_5,puVar6,puVar8,puVar2);
    (*CPSiFree)(puVar1);
  }
  return;
}


void CPSi_big_mult(u16 *param_1, u16 *param_2, u16 *param_3, int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  if ((param_1 == param_2) || (param_1 == param_3)) {
    OSi_TWarning("biginteger.c", 0xd1, "dst == src\n");
  }
  MI_CpuClear8(param_1,param_4 << 1);
  iVar1 = count_digits(param_2,param_4);
  iVar2 = count_digits(param_3,param_4);
  for (iVar3 = 0; iVar3 < iVar2; iVar3 = iVar3 + 1) {
    for (iVar4 = 0; (iVar4 < iVar1 && (iVar4 < param_4 - iVar3)); iVar4 = iVar4 + 1) {
      CPSi_big_add_part(param_1,(uint)param_2[iVar4] * (uint)param_3[iVar3],iVar3 + iVar4,param_4);
    }
  }
  return;
}


void CPSi_big_mult_small(u16 *param_1, u16 *param_2, uint param_3, int param_4)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = count_digits(param_2,param_4);
  uVar3 = 0;
  for (iVar2 = 0; iVar2 < iVar1; iVar2 = iVar2 + 1) {
    uVar3 = uVar3 + (param_3 & 0xffff) * (uint)param_2[iVar2];
    param_1[iVar2] = (u16)(uVar3 * 0x10000 >> 0x10);
    uVar3 = uVar3 >> 0x10;
  }
  iVar1 = iVar2;
  if (iVar2 < param_4) {
    iVar1 = iVar2 + 1;
    param_1[iVar2] = (u16)uVar3;
  }
  MI_CpuClear8(param_1 + iVar1,(param_4 - iVar1) * 2);
  return;
}


void CPSi_big_negate(u16 *param_1, int param_2)
{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < param_2; iVar1 = iVar1 + 1) {
    param_1[iVar1] = ~param_1[iVar1];
  }
  CPSi_big_add_small(param_1,param_1,1,param_2);
  return;
}


void CPSi_big_power(u16 *dst,u16 *src,u16 *aExponent,int aLen,u16 *aModulus)
{
  u16 * tmp;
  int iVar2;
  uint uVar3;
  
  if (((dst == src) || (dst == aExponent)) || (dst == aModulus)) {
    OSi_TWarning("biginteger.c", 0x195, "dst == src\n");
  }
  tmp = (u16 *)(*CPSiAlloc)(aLen << 3);
  if (tmp == NULL) {
    OSi_TWarning("biginteger.c", 0x19b, "Failed to allocate tmp\n");
  }
  else {
    MI_CpuClear8(dst + 1,(aLen + -1) * 2);
    *dst = 1;
    iVar2 = count_digits(aExponent,aLen);
    for (uVar3 = (aLen - iVar2) * 0x10; uVar3 < (uint)(aLen << 4); uVar3 = uVar3 + 1) {
      if ((0x8000U >> (uVar3 & 0xf) & (uint)aExponent[(aLen - ((int)uVar3 >> 4)) + -1]) != 0) {
        MI_CpuCopy8(src,dst,aLen << 1);
        uVar3 = uVar3 + 1;
        break;
      }
    }
    for (; uVar3 < (uint)(aLen << 4); uVar3 = uVar3 + 1) {
      CPSi_big_sqr(tmp,dst,aLen);
      MI_CpuCopy8(tmp,dst,aLen << 1);
      if (aModulus != NULL) {
        CPSi_big_div(NULL, dst, aModulus, dst, aLen, tmp + aLen);
      }
      if ((0x8000U >> (uVar3 & 0xf) & (uint)aExponent[(aLen - ((int)uVar3 >> 4)) + -1]) != 0) {
        CPSi_big_mult(tmp, dst, src, aLen);
        MI_CpuCopy8(tmp,dst,aLen << 1);
        if (aModulus != NULL) {
          CPSi_big_div(NULL, dst, aModulus, dst, aLen, tmp + aLen);
        }
      }
    }
    (*CPSiFree)(tmp);
  }
  return;
}


int CPSi_big_sign(u16 *param_1, int param_2)
{
  int iVar1;
  
  if ((param_1[param_2 + -1] & 0x8000) == 0) {
    iVar1 = count_digits(param_1,param_2);
    if (iVar1 == 0) {
      iVar1 = 0;
    } else {
      iVar1 = 1;
    }
  } else {
    iVar1 = -1;
  }
  return iVar1;
}


void CPSi_big_sqr(u16 *param_1, u16 *param_2, int param_3)
{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  if (param_1 == param_2) {
    OSi_TWarning("biginteger.c", 0xff, "dst == src\n");
  }
  iVar3 = count_digits(param_2,param_3);
  if (iVar3 * 2 < param_3) {
    MI_CpuClear8(param_1 + iVar3 * 2,(param_3 + iVar3 * -2) * 2);
  }
  for (iVar4 = 0; (iVar4 < iVar3 && (iVar5 = iVar4 * 2, iVar5 < param_3)); iVar4 = iVar4 + 1) {
    uVar1 = param_2[iVar4];
    uVar2 = param_2[iVar4];
    param_1[iVar4 * 2] = (u16)((uint)uVar1 * (uint)uVar2 * 0x10000 >> 0x10);
    if (iVar5 == param_3 + -1) break;
    param_1[iVar5 + 1] = (u16)((uint)uVar1 * (uint)uVar2 >> 0x10);
  }
  for (iVar4 = 0; iVar5 = iVar4, iVar4 < iVar3; iVar4 = iVar4 + 1) {
    while ((iVar5 = iVar5 + 1, iVar5 < iVar3 && (iVar4 + iVar5 < param_3))) {
      uVar6 = (uint)param_2[iVar5] * (uint)param_2[iVar4];
      if (uVar6 < 0x7fff8001) {
        CPSi_big_add_part(param_1,uVar6 * 2,iVar4 + iVar5,param_3);
      }
      else {
        CPSi_big_add_part(param_1,uVar6,iVar4 + iVar5,param_3);
        CPSi_big_add_part(param_1,uVar6,iVar4 + iVar5,param_3);
      }
    }
  }
  return;
}


void CPSi_big_sub(u16 *param_1,u16 *param_2,u16 *param_3,int param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = count_digits(param_2,param_4);
  iVar2 = count_digits(param_3,param_4);
  if (iVar1 < iVar2) {
    iVar1 = iVar2;
  }
  if (iVar1 != param_4) {
    iVar1 = iVar1 + 1;
  }
  iVar3 = 0;
  for (iVar2 = 0; (iVar3 < iVar1 || ((iVar3 < param_4 && (iVar2 != 0)))); iVar2 = iVar2 >> 0x10) {
    iVar2 = iVar2 + ((uint)param_2[iVar3] - (uint)param_3[iVar3]);
    param_1[iVar3] = (u16)((uint)(iVar2 * 0x10000) >> 0x10);
    iVar3 = iVar3 + 1;
  }
  if ((param_1 != param_2) && (param_1 != param_3)) {
    MI_CpuClear8(param_1 + iVar3,(param_4 - iVar3) * 2);
  }
  return;
}


void CPSi_big_sub_small(u16 *param_1, u16 *param_2, u16 param_3, int param_4)
{
  u16 uVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = (uint)param_3;
  for (iVar3 = 0; iVar3 < param_4; iVar3 = iVar3 + 1) {
    uVar1 = param_2[iVar3];
    param_1[iVar3] = (u16)((uVar1 - uVar2) * 0x10000 >> 0x10);
    uVar2 = uVar1 - uVar2 >> 0x10 & 1;
    if (uVar2 == 0) break;
  }
  if (param_1 != param_2) {
    while (iVar3 = iVar3 + 1, iVar3 < param_4) {
      param_1[iVar3] = param_2[iVar3];
    }
  }
  return;
}


void CPSi_char_from_big(u8 *param_1,u16 *param_2,int param_3,int param_4)
{
  u8 *puVar1;
  u8 *puVar2;
  
  puVar1 = param_1 + param_3 + -1;
  for (; 1 < param_3; param_3 = param_3 + -2) {
    puVar2 = puVar1 + -1;
    *puVar1 = (u8)*param_2;
    puVar1 = puVar1 + -2;
    *puVar2 = (u8)(*param_2 >> 8);
    param_2 = param_2 + 1;
  }
  if (0 < param_3) {
    *puVar1 = (u8)*param_2;
  }
  return;
}










int count_digits(u16 *param_1, int param_2)
{
  for (; (param_2 != 0 && (param_1[param_2 + -1] == 0)); param_2 = param_2 + -1) {
  }
  return param_2;
}


u64 get48bits_1(u16 *param_1)
{
  return (u64)*param_1 << 0x20;
}


u64 get48bits_2(u16 *param_1)
{
  return (u64)CONCAT22(*param_1,param_1[-1]) << 0x10;
}


u64 get48bits_3(u16 *param_1)
{
  return (u64)CONCAT24(*param_1,*(undefined4 *)(param_1 + -2));
}


u64 get64bits(u16 *param_1)
{
  return CONCAT44(CONCAT22(*param_1,param_1[-1]),*(undefined4 *)(param_1 + -3));
}
