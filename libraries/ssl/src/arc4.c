#include <nitro.h>
#include <nitroWiFi.h>
#include <nitroWiFi/decomp/decomp_defs_nitrowifi.h>

void CPSi_rc4_crypt(CPSRc4Ctx *aCtx, u8 *param_2, int param_3)
{
  byte bVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  uVar3 = (uint)aCtx->x;
  uVar4 = (uint)aCtx->y;
  for (iVar5 = 0; iVar5 < param_3; iVar5 = iVar5 + 1) {
    uVar3 = uVar3 + 1 & 0xff;
    bVar1 = aCtx->m[uVar3];
    uVar4 = uVar4 + bVar1 & 0xff;
    bVar2 = aCtx->m[uVar4];
    aCtx->m[uVar3] = bVar2;
    aCtx->m[uVar4] = bVar1;
    param_2[iVar5] = param_2[iVar5] ^ aCtx->m[(uint)bVar1 + (uint)bVar2 & 0xff];
  }
  aCtx->x = (uchar)uVar3;
  aCtx->y = (uchar)uVar4;
  return;
}


void CPSi_rc4_init(CPSRc4Ctx *aCtx, u8 *param_2, int param_3)
{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  aCtx->x = '\0';
  aCtx->y = '\0';
  for (iVar4 = 0; iVar4 < 0x100; iVar4 = iVar4 + 1) {
    aCtx->m[iVar4] = (uchar)iVar4;
  }
  uVar2 = 0;
  uVar3 = 0;
  for (iVar4 = 0; iVar4 < 0x100; iVar4 = iVar4 + 1) {
    bVar1 = aCtx->m[iVar4];
    uVar3 = uVar3 + (uint)bVar1 + (uint)param_2[uVar2] & 0xff;
    aCtx->m[iVar4] = aCtx->m[uVar3];
    aCtx->m[uVar3] = bVar1;
    uVar2 = uVar2 + 1 & 0xff;
    if (param_3 <= (int)uVar2) {
      uVar2 = 0;
    }
  }
  return;
}
