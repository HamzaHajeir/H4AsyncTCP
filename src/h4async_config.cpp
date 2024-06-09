#include "h4async_config.h"

#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS
#if !H4AT_HAS_ALTCP
#error "The platform doesn't support LWIP ALTCP TLS MBEDTLS"
#endif
#else
#if H4AT_USE_TLS
#pragma message "TLS is Disabled. Ensure you're using the correct Arduino Core build that supports LwIP ALTCP TLS MBEDTLS"
#endif
#endif