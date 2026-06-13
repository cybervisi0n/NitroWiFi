#ifndef NITROWIFI_H_
#define NITROWIFI_H_

#if defined(SDK_ARM9) || defined(SDK_PORT)
    #include <nitroWiFi/socket.h>
    #include <nitroWiFi/wcm.h>
    #include <nitroWiFi/ssl.h>

    #ifndef SDKWIFI_NO_SO_SYMBOLS
        #include <nitroWiFi/so2soc.h>
        #include <nitroWiFi/iw2wcm.h>
    #endif
#else
#endif

#endif
