/*
Creative Commons: Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)
https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

You are free to:

Share — copy and redistribute the material in any medium or format
Adapt — remix, transform, and build upon the material

The licensor cannot revoke these freedoms as long as you follow the license terms. Under the following terms:

Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. 
You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

NonCommercial — You may not use the material for commercial purposes.

ShareAlike — If you remix, transform, or build upon the material, you must distribute your contributions 
under the same license as the original.

No additional restrictions — You may not apply legal terms or technological measures that legally restrict others 
from doing anything the license permits.

Notices:
You do not have to comply with the license for elements of the material in the public domain or where your use is 
permitted by an applicable exception or limitation. To discuss an exception, contact the author:

philbowles2012@gmail.com

No warranties are given. The license may not give you all of the permissions necessary for your intended use. 
For example, other rights such as publicity, privacy, or moral rights may limit how you use the material.
*/
#pragma once
#include <h4async_config.h>

#include<Arduino.h>

#include "lwip/err.h"
#include "lwip/tcpbase.h"
#include "lwip/ip_addr.h"

#include "IPAddress.h"

#include <H4Tools.h>
#include <H4.h>

#include<array>
#include<functional>
#include<map>
#include<queue>
#include<string>
#include<unordered_set>
#include<vector>

#if H4AT_TLS
enum {
    H4AT_TLS_PRIVATE_KEY,
    H4AT_TLS_PRIVAKE_KEY_PASSPHRASE,
    H4AT_TLS_CERTIFICATE,
    H4AT_TLS_CA_CERTIFICATE
};
#endif
enum {
    H4AT_ERR_DNS_FAIL,
    H4AT_ERR_DNS_NF,
    H4AT_HEAP_LIMITER_ON,
    H4AT_HEAP_LIMITER_OFF,
    H4AT_HEAP_LIMITER_LOST,
    H4AT_INPUT_TOO_BIG,
    H4AT_CLOSING,
    H4AT_UNCONNECTED,
    H4AT_OUTPUT_TOO_BIG,
    H4AT_ERR_NO_PCB,
#if H4AT_TLS
    H4AT_BAD_TLS_CONFIG,
    H4AT_WRONG_TLS_MODE,
#endif
    H4AT_MAX_ERROR
};
#define _H4AT_PRINTF(...) _H4T_PRINTF(__VA_ARGS__)
#if H4AT_DEBUG
#define H4AT_PRINTF(...) _H4AT_PRINTF(__VA_ARGS__)
    template<int I, typename... Args>
    void H4AT_PRINT(const char* fmt, Args... args) {
        #ifdef ARDUINO_ARCH_ESP32
        if (H4AT_DEBUG >= I) H4AT_PRINTF(std::string(std::string("H4AT:%d: H=%u M=%u S=%u ")+fmt).c_str(),I,_HAL_freeHeap(),_HAL_maxHeapBlock(),uxTaskGetStackHighWaterMark(NULL),args...);
        #else
        if (H4AT_DEBUG >= I) H4AT_PRINTF(std::string(std::string("H4AT:%d: H=%u M=%u ")+fmt).c_str(),I,_HAL_freeHeap(),_HAL_maxHeapBlock(),args...);
        #endif
    }
    #define H4AT_PRINT1(...) H4AT_PRINT<1>(__VA_ARGS__)
    #define H4AT_PRINT2(...) H4AT_PRINT<2>(__VA_ARGS__)
    #define H4AT_PRINT3(...) H4AT_PRINT<3>(__VA_ARGS__)
    #define H4AT_PRINT4(...) H4AT_PRINT<4>(__VA_ARGS__)

    template<int I>
    void H4AT_dump(const uint8_t* p, size_t len) { if (H4AT_DEBUG >= I) dumphex(p,len); }
    #define H4AT_DUMP1(p,l) H4AT_dump<1>((p),l)
    #define H4AT_DUMP2(p,l) H4AT_dump<2>((p),l)
    #define H4AT_DUMP3(p,l) H4AT_dump<3>((p),l)
    #define H4AT_DUMP4(p,l) H4AT_dump<4>((p),l)
#else
    #define H4AT_PRINTF(...)
    #define H4AT_PRINT1(...)
    #define H4AT_PRINT2(...)
    #define H4AT_PRINT3(...)
    #define H4AT_PRINT4(...)

    #define H4AT_DUMP2(...)
    #define H4AT_DUMP3(...)
    #define H4AT_DUMP4(...)
#endif

#if LWIP_ALTCP
struct altcp_pcb;
#else
#include "lwip_altcp.h" // Contains appropriate preprocessors if TLS macros aren't defined.
#endif
enum tcp_state getTCPState(struct altcp_pcb *conn, bool tls=false);

enum H4AT_ConectionState : uint8_t {
    H4AT_CONN_UNCONNECTED,
    H4AT_CONN_CONNECTED,
    H4AT_CONN_WILLCLOSE,
    H4AT_CONN_ERROR,
    H4AT_CONN_CLOSING
};

class H4AsyncClient;
struct TCPData {
    mbx m;
    size_t tx_len;
    TCPData(const uint8_t* data, size_t length, bool copy) : m(const_cast<uint8_t*>(data),length,copy), tx_len(0){
        // Serial.printf("TCPData()->%p\n", m.data);
    }
    ~TCPData() {
        // Serial.printf("~TCPData(%p)\n", m.data);
        m.clear();
    }
};
using H4AT_NVP_MAP      =std::unordered_map<std::string,std::string>;
using H4AT_FN_ERROR     =std::function<bool(int,int)>;
using H4AT_FN_RXDATA    =std::function<void(const uint8_t* data, size_t len)>;
using H4AT_FN_PTR       =std::function<void(void*)>;
using H4AT_TCP_QUEUE    =std::queue<TCPData*>;
class H4AsyncClient {
        static  void                __scavenge();
        static  bool                _scavenging;
                void                _parseURL(const std::string& url);
                size_t              _processTX(const uint8_t* data, size_t length, bool copy);
                bool                _processQueue();
                void                _popQueue() { if (_queue.size()) { delete _queue.front(); _queue.pop();} }
        static  bool                _validConnection(H4AsyncClient* c) { return openConnections.count(c); }
        static  std::unordered_set<H4AsyncClient*> txQueueClients;
        static  bool                _processingQ;
                H4AT_TCP_QUEUE      _queue;
        static  void    dumptxQueueClients();
        friend  err_t   _raw_sent(void* arg,struct altcp_pcb *tpcb, u16_t len);
        friend  err_t   _raw_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err);
        friend  err_t   _raw_accept(void *arg, struct altcp_pcb *p, err_t err);
        friend  err_t   _tcp_connected(void* arg, altcp_pcb* tpcb, err_t err);
        friend  void    _raw_error(void *arg, err_t err);
                bool                _isSecure=false;
                H4AT_ConectionState _state = H4AT_CONN_UNCONNECTED;
#if H4AT_TLS
                std::array<mbx*,4>  _keys {nullptr,nullptr,nullptr,nullptr};
                enum {
                    H4AT_TLS_NONE,
                    H4AT_TLS_ONE_WAY,
                    H4AT_TLS_TWO_WAY
                } _tls_mode = H4AT_TLS_NONE;
                void                _addSNI(); // Add Server Name Indication to the TLS Context
                uint32_t            _ssl_overhead=0;
                void                _fetchTLSOverhead();
#endif

#if H4AT_TLS_SESSION
                void*               _session = NULL; // Move to private section
                bool                _sessionEnabled = false;
                void                _setTLSSession(); // Commits it into the connection.
                bool                _initTLSSession();
                void                _updateSession(); // Callable on _tcp_connected
                void                _removeSession();
#endif
    protected:
                H4AT_FN_RXDATA      _rxfn=[](const uint8_t* data,size_t len){ _H4AT_PRINTF("RXFN SAFETY\n"); dumphex(data,len); }; // [ ] TODO: Add return value as director to free data.
    public:
        static  std::unordered_set<H4AsyncClient*> openConnections;
        static  std::unordered_set<H4AsyncClient*> unconnectedClients;

                void                printState(std::string context);
        static  void                retryClose(H4AsyncClient* c,altcp_pcb* pcb);
        static  void                checkPCBs(std::string context, int cxt = 0, bool forceprint=false);
                struct  URL {
                    std::string     scheme;
                    std::string     host;
                    uint16_t        port;
                    std::string     path;
                    std::string     query;
                    std::string     fragment;
                    bool            secure=0;
                    ip_addr_t       addr;
                } _URL;

                uint8_t*            _bpp=nullptr;
                H4_FN_VOID          _cbConnect;
                H4_FN_VOID          _cbDisconnect;
                H4_FN_VOID          _cbConnectFail;
                H4AT_FN_ERROR       _cbError=[](int e,int i){ return true; }; // return false to avoid auto-shutdown
#if H4AT_TLS_SESSION
                H4AT_FN_PTR         _cbSession;
#endif
        static  H4_INT_MAP          _errorNames;
        //   size_t              _heapLO;
        //   size_t              _heapHI;
                uint32_t            _lastSeen=0;
                uint32_t            _creatTime=0;
                bool                _nagle=false;
                struct altcp_pcb    *pcb;
                size_t              _stored=0;

                void                enableTLSSession();
                void                disableTLSSession();
                void*               getTLSSession(); // user call
                /*! setTLSSession 
                    user call upon construction, sets the internal pointer.
                    if session is enabled by the user, he must set any previous sessions to prevent memory leak.
                */
                void                setTLSSession(void* session); // 
                void                freeTLSSession(void* session); // user calls it if he wants to discard a session, because of timeout or different server communication

        H4AsyncClient(altcp_pcb* p=0);
        virtual ~H4AsyncClient();
                void                close(){ _shutdown(); }
                void                connect(const std::string& host,uint16_t port);
                void                connect(IPAddress ip,uint16_t port);
                void                connect(const std::string& url);
                bool                connected();
                //
                //void                dump();
                //
        static  std::string         errorstring(int e);
                uint32_t            localAddress();
                IPAddress           localIP();
                std::string         localIPstring();
                uint16_t            localPort();
                size_t              maxPacket(){ return ( _HAL_maxHeapBlock() * (100-H4T_HEAP_CUTIN_PC)) / 100; }
//                size_t              maxPacket(){ return 3285; }
                void                nagle(bool b=true);
                void                onConnect(H4_FN_VOID cb){ _cbConnect=cb; }
                void                onDisconnect(H4_FN_VOID cb){ _cbDisconnect=cb; }
                void                onConnectFail(H4_FN_VOID cb){ _cbConnectFail=cb; }
                void                onError(H4AT_FN_ERROR cb){ _cbError=cb; }
                void                onRX(H4AT_FN_RXDATA f){ _rxfn=f; }
#if H4AT_TLS_SESSION
                void                onSession(H4AT_FN_PTR f){ _cbSession = f; }
#else
                void                onSession(H4AT_FN_PTR f){ }
#endif
                uint32_t            remoteAddress();
                IPAddress           remoteIP();
                std::string         remoteIPstring();
                uint16_t            remotePort();
                void                TX(const uint8_t* d,size_t len,bool copy=true);

                uint16_t            getTLSOverhead() {
#if H4AT_TLS
                                        return _ssl_overhead; 
#else
                                        return 0;
#endif
                                    }
#if H4AT_TLS
                void                secureTLS(const u8_t *ca, size_t ca_len, const u8_t *privkey = nullptr, size_t privkey_len=0,
                                            const u8_t *privkey_pass = nullptr, size_t privkey_pass_len = 0,
                                            const u8_t *cert = nullptr, size_t cert_len = 0);

#endif
#if H4AT_TLS_CHECKER
        static  bool                isCertValid(const u8_t *cert = nullptr, size_t cert_len = 0);
        static  bool                isPrivKeyValid(const u8_t *privkey = nullptr, size_t privkey_len=0,
                                                    const u8_t *privkey_pass = nullptr, size_t privkey_pass_len = 0);
#endif
// syscalls - just don't...
                uint8_t*            _addFragment(const uint8_t* data,u16_t len);
                void                _clearDanglingInput();
                void                _connect();
                void                _handleFragment(const uint8_t* data,u16_t len,u8_t flags);
                void                _notify(int e,int i=0);
        static  void                _scavenge();
                void                _shutdown();

};

class H4AsyncServer {
        static    bool              _bakov;
        altcp_pcb*                  _raw_pcb = NULL;
    protected:
            uint16_t                _port;
            bool                    _secure;
#if H4AT_TLS
            std::array<mbx*,3>       _keys {nullptr,nullptr,nullptr};

#endif
    public:
            size_t                  _heap_alloc=0; // Single Server Accept heap usage.
            size_t                  _block_alloc=0;// Largest memory block required for serving.
            H4AT_FN_ERROR        _srvError;
        H4AsyncServer(uint16_t port): _port(port){}
        virtual ~H4AsyncServer(){}
#if H4AT_TLS
                void        secureTLS(const u8_t *privkey, size_t privkey_len,
                                const u8_t *privkey_pass, size_t privkey_pass_len,
                                const u8_t *cert, size_t cert_len);
#endif

        virtual void        begin();
                void        onError(H4AT_FN_ERROR f){ _srvError=f; }
        virtual void        reset();
        virtual void        route(void* c,const uint8_t* data,size_t len)=0;

        virtual H4AsyncClient* _instantiateRequest(struct altcp_pcb *p);
        static  bool            checkMemory (const H4AsyncServer& srv) {
                                            auto fh=_HAL_freeHeap();
                                            auto fb=_HAL_maxHeapBlock();
                                            auto _heapLO = H4AT_HEAP_THROTTLE_LO + srv._heap_alloc;
                                            auto _heapHI = H4AT_HEAP_THROTTLE_HI + srv._heap_alloc;
                                            auto _blockLO= H4AT_HEAP_THROTTLE_LO + srv._block_alloc;
                                            // Serial.printf("FREE HEAP %u LOW %u HIGH %u BKV %d\n",fh,_heapLO,_heapHI,_bakov);
                                            H4AT_PRINT3("FREE HEAP %u BLOCK %u LOWH %u LOWB %u\n",fh,fb,_heapLO,_blockLO);
                                            // if (fh < _heapLO || (_bakov && (fh < _heapHI))){
                                            if (fh < _heapLO || fb < _blockLO){
                                                _bakov = true;
                                                return false;
                                            }
                                            _bakov = false;
                                            return true;
                                        };

};

class LwIPCoreLocker {
#if H4AT_HAS_RTOS
    static volatile int         _locks;
                    bool        _locking=false;
#endif
    public:
        LwIPCoreLocker();
                    void        unlock();
        ~LwIPCoreLocker();
                    void        lock();
                    bool        locking();
};