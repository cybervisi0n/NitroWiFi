#include <nitroWiFi/socl.h>
#ifdef SDK_PORT
#include <SDL2/SDL.h>
#endif

SOCLSocket * SOCLiSocketList = NULL;
SOCLSocket * SOCLiSocketListTrash = NULL;
#ifdef SDK_PORT
SDL_mutex * SOCLiSocketListMutex = NULL;
SDL_mutex * SOCLiSocketListTrashMutex = NULL;
#endif

static SOCLSocket ** SOCLi_SocketGetNextPtr(SOCLSocket ** start, SOCLSocket * socket);
static void SOCLi_SocketRegisterList(SOCLSocket ** next, SOCLSocket * socket);
static void SOCLi_SocketUnregisterList(SOCLSocket ** next, SOCLSocket * socket);

#ifdef SDK_PORT
SOCLSocket * WIN_SOCLi_GetSocketFromList(int s)
{
    SOCLSocket*     t;
    WIN_SOCLi_LockSocketList();

    for (t = SOCLiSocketList; t; t = t->next)
    {
        if(t == NULL) {
            break;
        }

        if ((int)t == s)
        {
            WIN_SOCLi_UnlockSocketList();
            return t;
        }

    }
    WIN_SOCLi_UnlockSocketList();
    return NULL;
}

void WIN_SOCLi_LockSocketList()
{
    SDL_LockMutex(SOCLiSocketListMutex);
}
void WIN_SOCLi_UnlockSocketList()
{
    SDL_UnlockMutex(SOCLiSocketListMutex);
}
void WIN_SOCLi_LockSocketListTrash()
{
    SDL_LockMutex(SOCLiSocketListTrashMutex);
}
void WIN_SOCLi_UnlockSocketListTrash()
{
    SDL_UnlockMutex(SOCLiSocketListTrashMutex);
}

void WIN_SOCLi_InitSocketListMutex()
{
    SOCLiSocketListMutex = SDL_CreateMutex();
    SOCLiSocketListTrashMutex = SDL_CreateMutex();
}
#endif

void SOCLi_SocketRegister (SOCLSocket * socket)
{
    #ifdef SDK_PORT
    WIN_SOCLi_LockSocketList();
    #endif
    SOCLi_SocketRegisterList(&SOCLiSocketList, socket);
    #ifdef SDK_PORT
    WIN_SOCLi_UnlockSocketList();
    #endif
}

static void SOCLi_SocketRegisterList (SOCLSocket ** next, SOCLSocket * socket)
{
    socket->next = *next;
    *next = socket;
}

void SOCLi_SocketRegisterTrash (SOCLSocket * socket)
{
    #ifdef SDK_PORT
    WIN_SOCLi_LockSocketList();
    #endif
    SOCLi_SocketRegisterList(&SOCLiSocketListTrash, socket);
    #ifdef SDK_PORT
    WIN_SOCLi_UnlockSocketList();
    #endif
}

void SOCLi_SocketUnregister (SOCLSocket * socket)
{
    #ifdef SDK_PORT
    WIN_SOCLi_LockSocketList();
    #endif
    SOCLi_SocketUnregisterList(&SOCLiSocketList, socket);
    #ifdef SDK_PORT
    WIN_SOCLi_UnlockSocketList();
    #endif
}

static void SOCLi_SocketUnregisterList (SOCLSocket ** next, SOCLSocket * socket)
{
    next = SOCLi_SocketGetNextPtr(next, socket);

    if (next) {
        *next = socket->next;
    }
}

static SOCLSocket ** SOCLi_SocketGetNextPtr (SOCLSocket ** next, SOCLSocket * socket)
{
    SOCLSocket * t;

    for (t = *next; t; t = t->next) {
        #ifdef SDK_PORT
        if ((int)t == (int)socket)
        #else
        if (t == socket)
        #endif
        {
            return next;
        }

        next = &t->next;
    }

    return NULL;
}

void SOCLi_SocketUnregisterTrash (SOCLSocket * socket)
{
    #ifdef SDK_PORT
    WIN_SOCLi_LockSocketList();
    #endif
    SOCLi_SocketUnregisterList(&SOCLiSocketListTrash, socket);
    #ifdef SDK_PORT
    WIN_SOCLi_UnlockSocketList();
    #endif
}

int SOCL_SocketIsInvalid (SOCLSocket * socket)
{
    #ifdef SDK_PORT
    WIN_SOCLi_LockSocketList();
    int val = !SOCLi_SocketGetNextPtr(&SOCLiSocketList, socket);
    WIN_SOCLi_UnlockSocketList();
    return val;
    #endif
    return ((int)socket <= 0) || !SOCLi_SocketGetNextPtr(&SOCLiSocketList, socket);
}

int SOCL_SocketIsInTrash (SOCLSocket * socket)
{
    return SOCLi_SocketGetNextPtr(&SOCLiSocketListTrash, socket) != NULL;
}
