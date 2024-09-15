/*
MIT License

Copyright (c) 2020 Phil Bowles with huge thanks to Adam Sharp http://threeorbs.co.uk
for testing, debugging, moral support and permanent good humour.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once
#include <lwip/opt.h>
#define H4AT_VERSION "0.0.24"
/*
    Debug levels: 
    0 - No debug messages, no debug functions
    1 - Debug functions compiled in + CNX / DCX messages
    2 - TX / RX / ACK messages

    4 - a lot
*/
#define H4AT_DEBUG 0
#define H4AS_SCAVENGE_FREQ 20000
#define H4AT_USE_TLS        1
#define H4AT_TLS_CHECKER    1 // for isCertValid() and isPrivKeyValid()
#define H4AT_USE_TLS_SESSION    1


#define H4AT_HAS_RTOS     (NO_SYS == 0) || TARGET_RP2040 /* || TARGET_RP2350 */

/* The LOCK/UNLOCK operations for RP2040 were set and defaulted to disable, as the lwip calls (currently, with no ALTCP) are already locked */
#define H4AT_RP2040_DONTLOCKUNLOCK  1

#if H4AT_HAS_RTOS
#define H4AS_RTOS_GET_THREAD_NAME   pcTaskGetName(NULL) // For FreeRTOS (ESP32)
#endif

#ifdef ARDUINO_ARCH_ESP32
#define H4AT_HAS_ALTCP      1
#elif defined(ARDUINO_ARCH_ESP8266)
#define H4AT_HAS_ALTCP      0
#undef H4AT_TLS_CHECKER
#define H4AT_TLS_CHECKER    0
#endif


#if LWIP_ALTCP && LWIP_ALTCP_TLS && LWIP_ALTCP_TLS_MBEDTLS
#define H4AT_TLS        H4AT_USE_TLS
#else
#define H4AT_TLS        0
#endif

#if H4AT_TLS
#define H4AT_TLS_SESSION H4AT_USE_TLS_SESSION
#else
#define H4AT_TLS_SESSION 0
#ifdef H4AT_TLS_CHECKER
#undef H4AT_TLS_CHECKER
#endif
#define H4AT_TLS_CHECKER 0
#endif