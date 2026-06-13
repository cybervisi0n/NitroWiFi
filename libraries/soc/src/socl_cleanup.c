#include <nitroWiFi/socl.h>

#include "../wcm/include/wcm_cpsif.h"

int SOCL_Cleanup (void)
{
    int result;

    SDK_ASSERT(SOCLiConfigPtr);

    if (SOCLiRequestedIP == 0) {
        SOCLiRequestedIP = CPSMyIp;
    }

    while (SOCL_EINPROGRESS == SOCL_CalmDown()) {
        OS_Sleep(100);
    }

    result = SOCLi_CleanupCommandPacketQueue();

    if (result >= 0) {
#ifdef SDK_MY_DEBUG
        OS_TPrintf("CPS_Cleanup\n");
#endif

        CPS_Cleanup();
        CPS_SetScavengerCallback(NULL);

        if (!SOCLiConfigPtr->lan_buffer) {
            SOCLi_Free(SOCLiCPSConfig.lan_buf);
        }

        SOCLiConfigPtr = NULL;
    }

    return result;
}

int SOCL_CloseAll (void)
{
    SOCLSocket * socket;
    OSIntrMode enable;

    #ifdef SDK_PORT
    SDL_Delay(5);
    WIN_SOCLi_LockSocketList();
    #endif

    for (;;) {
        enable = OS_DisableInterrupts();
        for (socket = SOCLiSocketList; socket; socket = socket->next) {
            if ((int)socket != SOCLiUDPSendSocket && !SOCL_SocketIsWaitingClose(socket)) {
                break;
            }
        }

        (void)OS_RestoreInterrupts(enable);

        if (!socket) {
            break;
        }

        (void)SOCL_Close((int)socket);
    }

    if (SOCLiSocketList == NULL || ((int)SOCLiSocketList == SOCLiUDPSendSocket && SOCLiSocketList->next == NULL)) {
        #ifdef SDK_PORT
        SOCLi_TrashSocket();
        #endif
        if (SOCLiSocketListTrash == NULL) {
            #ifdef SDK_PORT
            WIN_SOCLi_UnlockSocketList();
            #endif
            return SOCL_ESUCCESS;
        }
    }

    #ifdef SDK_PORT
    WIN_SOCLi_UnlockSocketList();
    #endif
    return SOCL_EINPROGRESS;
}

int SOCL_CalmDown (void)
{
    int result;

    if (SOCLiUDPSendSocket) {
        result = SOCL_CloseAll();

        if (result == SOCL_ESUCCESS) {
            (void)SOCL_Close(SOCLiUDPSendSocket);

            #ifdef SDK_PORT
            SOCLi_TrashSocket();
            #endif

            if (SOCL_IsClosed(SOCLiUDPSendSocket)) {
                #ifdef SDK_PORT
                SOCLiUDPSendSocket = 0;
                #else
                SOCLiUDPSendSocket = NULL;
                #endif
            }

            result = SOCL_EINPROGRESS;
        }

        SOCLi_TrashSocket();
    } else {
        if (CPS_CalmDown()) {
            WCM_SetRecvDCFCallback(NULL);
            result = SOCL_ESUCCESS;
        } else {
            result = SOCL_EINPROGRESS;
        }
    }

    return result;
}
