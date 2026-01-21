/* 

Licence: 
MIT License

Copyright (c) 2026 H4Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Contact Email: TBD

*/
#include <H4AsyncTCP.h>
#include "IPAddress.h"

#include "lwip/tcp.h"
#include "lwip_altcp.h"
#if H4AT_HAS_ALTCP
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#endif
#include "lwip/dns.h"

#if H4AT_TLS_CHECKER
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#if MBEDTLS_VERSION_MAJOR >= 3
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif
#endif

#if LWIP_ALTCP == 0
u16_t altcp_get_port(struct altcp_pcb *conn, int local){
    return local ? conn->local_port : conn ->remote_port;
}
#endif
std::unordered_set<H4AsyncClient*> H4AsyncClient::txQueueClients;
std::unordered_set<H4AsyncClient*> H4AsyncClient::openConnections;
std::unordered_set<H4AsyncClient*> H4AsyncClient::unconnectedClients;
bool H4AsyncClient::_scavenging = false;
bool H4AsyncClient::_processingQ = false;

H4_INT_MAP H4AsyncClient::_errorNames={
#if H4AT_DEBUG
    {ERR_OK,"No error, everything OK"},
    {ERR_MEM,"Out of memory error"}, // -1
    {ERR_BUF,"Buffer error"},
    {ERR_TIMEOUT,"Timeout"},
    {ERR_RTE,"Routing problem"},
    {ERR_INPROGRESS,"Operation in progress"}, // -5
    {ERR_VAL,"Illegal value"},
    {ERR_WOULDBLOCK,"Operation would block"},
    {ERR_USE,"Address in use"},
    {ERR_ALREADY,"Already connecting"},
    {ERR_ISCONN,"Conn already established"}, // -10
    {ERR_CONN,"Not connected"}, // -11
    {ERR_IF,"Low-level netif error"}, // -12
    {ERR_ABRT,"Connection aborted"}, // -13
    {ERR_RST,"Connection reset"}, // -14
    {ERR_CLSD,"Connection closed"},
    {ERR_ARG,"Illegal argument"},
    {H4AT_ERR_DNS_FAIL,"DNS Fail"},
    {H4AT_ERR_DNS_NF,"Remote Host not found"},
    {H4AT_HEAP_LIMITER_ON,"Heap Limiter ON"},
    {H4AT_HEAP_LIMITER_OFF,"Heap Limiter OFF"},
    {H4AT_HEAP_LIMITER_LOST,"Heap Limiter: packet discarded"},
    {H4AT_INPUT_TOO_BIG,"Input exceeds safe heap"},
    {H4AT_CLOSING,"Client closing"},
    {H4AT_OUTPUT_TOO_BIG,"Output exceeds safe heap"},
    {H4AT_ERR_NO_PCB,"No PCB"},
#if H4AT_TLS
    {H4AT_BAD_TLS_CONFIG,"BAD TLS Config"},
    {H4AT_WRONG_TLS_MODE,"Wrong TLS Mode"}
#endif
#endif
};

//#define TF_ACK_DELAY   0x01U   /* Delayed ACK. */
//#define TF_ACK_NOW     0x02U   /* Immediate ACK. */
//#define TF_INFR        0x04U   /* In fast recovery. */
//#define TF_TIMESTAMP   0x08U   /* Timestamp option enabled */
//#define TF_RXCLOSED    0x10U   /* rx closed by tcp_shutdown */
//#define TF_FIN         0x20U   /* Connection was closed locally (FIN segment enqueued). */
//#define TF_NODELAY     0x40U   /* Disable Nagle algorithm */
//#define TF_NAGLEMEMERR 0x80U   /* nagle enabled, memerr, try to output to prevent delayed ACK to happen */
/*
enum tcp_state {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};
*/

#if H4AT_DEBUG
static const char * const tcp_state_str[] = {
  "CLOSED",
  "LISTEN",
  "SYN_SENT",
  "SYN_RCVD",
  "ESTABLISHED",
  "FIN_WAIT_1",
  "FIN_WAIT_2",
  "CLOSE_WAIT",
  "CLOSING",
  "LAST_ACK",
  "TIME_WAIT"
};
static const char * const h4at_state_str[] = {
  "UNCONNECTED",
  "CONNECTED",
  "WILL_CLOSE",
  "ERROR",
  "CLOSING",
};
#endif

enum tcp_state getTCPState(struct altcp_pcb *conn, bool tls) {
#if LWIP_ALTCP
    LwIPCoreLocker lock;
    if (conn) {
        if (tls){
            if (conn->inner_conn && conn->inner_conn->state) {
                auto inner_state = conn->inner_conn->state;
                struct tcp_pcb *pcb = (struct tcp_pcb *)inner_state;
                if (pcb)
                    return pcb->state;
            }

        } else {
            struct tcp_pcb *pcb = (struct tcp_pcb *)conn->state;
            if (conn->inner_conn) return (tcp_state)-1;
            if (pcb)
                return pcb->state;
        }
    }
    H4AT_PRINT1("GETSTATE %p NO CONN\n", conn);
    return CLOSED;
#else
    if (conn)
        return conn->state;
    return tcp_state::CLOSED;
#endif
}

void H4AsyncClient::printState(std::string context){
    auto state = getTCPState(pcb, _isSecure);
    H4AT_PRINT2("%s\tpcb=%p s=%d \"%s\"\n", context.c_str(), pcb, state, (state >= CLOSED && state <=TIME_WAIT)? tcp_state_str[state]:"???");
}

void H4AsyncClient::retryClose(H4AsyncClient* c,altcp_pcb *pcb)
{
    auto state = getTCPState(pcb, c->_isSecure);
    _H4AT_PRINTF("retryClose %p state=%d\n", pcb, state);
    // Check the presence of the PCB with other Clients ??
    auto checkOtherOwners = [c,pcb] (std::unordered_set<H4AsyncClient*>& set){
        for (auto& _c : set){
            if (_c->pcb == pcb && _c!=c){
                _H4AT_PRINTF("%p found in other client %p\n", pcb, _c);
                return true;
            }
        }
        return false;
    };

    // [ ] Is this neccessary ??
    // If there's another client with this pcb, don't close it, and NULLify the PCB for not closing it again at SCAVENGE
    if (checkOtherOwners(openConnections) || checkOtherOwners(unconnectedClients))
        return;
    
    if (state <= CLOSED || state > TIME_WAIT){
        _H4AT_PRINTF("Already freed/closed %p\n", pcb);
        return;
    }
    LwIPCoreLocker lock;
    err_t err = altcp_close(pcb);
    if (err != ERR_OK){
        _H4AT_PRINTF("%p failed with %d\n", pcb, err);
        if (err == ERR_MEM){
            h4.queueFunction([c, pcb](){ retryClose(c,pcb); }); // h4.once(1000, [pcb](){retruClose(pcb);}); ???
        }
    } 
    else 
    {
        _H4AT_PRINTF("freed %p\n", pcb);
    }
}

void H4AsyncClient::checkPCBs(std::string context, int cxt, bool forceprint) {
    static int count = 0;
    static int active = 0;
    if (cxt > 0) active++;
    else if (cxt < 0) active--;

    int total_active = 0;
    for(auto& c:openConnections) total_active += c->pcb != nullptr;
    for(auto& c:unconnectedClients) total_active += c->pcb != nullptr;
    if (active != total_active) {
        H4AT_PRINT1("ERROR: active=%d total_active=%d\n", active, total_active);
    }
    if (!forceprint && count++ % 20) return;
#if H4AT_DEBUG > 1
    H4AT_PRINTF("%s PCBs:\t",context.c_str());
    // H4AT_PRINTF("openConnections: %d\ttotal_active: %d\n",openConnections.size(), total_active);
    for (auto &c : openConnections)
        if (c->pcb)
            H4AT_PRINTF("%p\t", c->pcb);
    for (auto &uc : unconnectedClients)
        if (uc->pcb)
            H4AT_PRINTF("[UC %p]\t", uc->pcb);
    H4AT_PRINTF("\n");
#endif
        
}

void H4AsyncClient::_notify(int e,int i) { 
    if ((_cbError(e,i) || !pcb) && e) _shutdown();
}

void H4AsyncClient::_shutdown() {
    H4AT_PRINT1("_shutdown %p %d\n",this, _state);
    LwIPCoreLocker lock;
    if (_state == H4AT_CONN_CLOSING) {
        H4AT_PRINT1("Already closing/closed\n");
        return;
    }
    _state = H4AT_CONN_CLOSING;
    _lastSeen=0;
    err_t err = ERR_OK;
    if(pcb){
        auto state = getTCPState(pcb, _isSecure);
        
        H4AT_PRINT1("RAW 1 PCB=%p STATE=%d \"%s\"\n",pcb,state,(state >= CLOSED && state <=TIME_WAIT)? tcp_state_str[state]:"???");
        altcp_arg(pcb, NULL);
        //***************************************************
        altcp_sent(pcb, NULL);
        altcp_recv(pcb, NULL);
        altcp_err(pcb, NULL);
        H4AT_PRINT3("*********** pre closing\n");
        err=altcp_close(pcb);

        if (err) {
            H4AT_PRINT1("Error closing %d \"%s\"\n", err, _errorNames[err].c_str());
            if (err==ERR_MEM) {
                auto pcb_cpy = pcb;
                h4.queueFunction([this, pcb_cpy]
                                    {
                                        // Might try closing later ... ?
                                        // What if we don't close it? Will it be closed by lwip automatically?
                                        // What if lwip reused this pcb for another connection?
                                        retryClose(this,pcb_cpy);
                                    });
            }
        }
        H4AT_PRINT4("*********** NULL IT\n");
        pcb=NULL; // == eff = reset;
    }
    else {
        H4AT_PRINT1("ALREADY SHUTDOWN %p pcb=0!\n", this);
        err = ERR_CLSD;
    }
    H4AT_PRINT2("Informing User\n");
    if (openConnections.count(this)) { // There was an open connection
        if (_cbDisconnect) _cbDisconnect();
        else
            H4AT_PRINT2("NO DISCONNECT HANDLER\n");
        checkPCBs("SHUTDOWN", -1);
    }
    else if (unconnectedClients.count(this)){ // The connection (as a client) was never established
        if (_cbConnectFail) _cbConnectFail();
        else
            H4AT_PRINT2("NO CONNECT FAIL HANDLER\n");
    }
    if (!_scavenging) {
        H4AT_PRINT1("Queueing __scavange()\n");
        _scavenging = true;
        h4.queueFunction([]()
                         { H4AsyncClient::__scavenge(); });
    }
    _clearDanglingInput();
    return _notify(err == ERR_CLSD ? ERR_OK : err);
}

void _raw_error(void *arg, err_t err){
    H4AT_PRINT1("_raw_error c=%p e=%d\n",arg,err);
    auto c=reinterpret_cast<H4AsyncClient*>(arg);
    c->pcb=NULL;
    c->_state=H4AT_CONN_ERROR;
#if H4AT_TLS_SESSION
    c->_removeSession();
#endif
    h4.queueFunction([c,err](){
        H4AT_PRINT1("CONNECTION %p *ERROR* pcb=%p err=%d\n",c,c->pcb, err);
        auto it=H4AsyncClient::openConnections.find(c);
        auto it2=H4AsyncClient::unconnectedClients.find(c);
        if (it != H4AsyncClient::openConnections.end() || it2 != H4AsyncClient::unconnectedClients.end()) // has not been deleted.
            {c->_notify(err,0);}
    });
}

err_t _raw_recv(void *arg, struct altcp_pcb *tpcb, struct pbuf *p, err_t err){
    H4AT_PRINT1("_raw_recv %p tpcb=%p p=%p err=%d data=%p tot_len=%d\n",arg,tpcb,p, err, p ? p->payload:0,p ? p->tot_len:0);
    auto rq=reinterpret_cast<H4AsyncClient*>(arg);
    if (rq->_state!=H4AT_CONN_CONNECTED)
        H4AT_PRINT2("_state=%d \"%s\"\n", rq->_state, h4at_state_str[rq->_state]);
    if (((p == NULL || err!=ERR_OK) && rq->pcb) || rq->_state == H4AT_CONN_CLOSING) {
        H4AT_PRINT1("Will Close!\n");
        if (rq->_state != H4AT_CONN_CLOSING)
            rq->_state = H4AT_CONN_WILLCLOSE;
        h4.queueFunction([=](){ rq->_notify(ERR_CLSD, err); });// * warn ...hanging data when closing?
    } else {
#if H4AT_TLS
        if (!rq->_ssl_overhead) {rq->_fetchTLSOverhead();}
#endif
        auto cpydata=static_cast<uint8_t*>(malloc(p->tot_len));
        if(cpydata){
            pbuf_copy_partial(p,cpydata,p->tot_len,0); // instead of direct memcpy that only considers the first pbuf of the possible pbufs chain.
            auto cpyflags=p->flags;
            auto cpylen=p->tot_len;
            H4AT_PRINT2("* p=%p * FREE DATA %p cpy=%p %d 0x%02x bpp=%p\n",p,p->payload,cpydata,p->tot_len,p->flags,rq->_bpp);
            err=ERR_OK;
            h4.queueFunction([rq,cpydata,cpylen,cpyflags]{
                H4AT_PRINT2("_raw_recv %p data=%p L=%d f=0x%02x \n",rq,cpydata,cpylen,cpyflags);
                LwIPCoreLocker lock; // To ensure no data race between two threads, .
                if (rq->_state == H4AT_CONN_CLOSING || rq->_state == H4AT_CONN_ERROR || !H4AsyncClient::_validConnection(rq)) { // OR !(state==CONNECTED||state==WiLLCLOSE)
                    H4AT_PRINT2("Prevent processing of closing connection\n");
                    return;
                }
                if (rq->_state == H4AT_CONN_WILLCLOSE){ H4AT_PRINT2("WATCHOUT THE CONNECTION UNDER CLOSING!\n"); }
                rq->_lastSeen=millis();
                lock.unlock();
                rq->_handleFragment((const uint8_t*) cpydata,cpylen,cpyflags);
            },[cpydata]{
                H4AT_PRINT3("FREEING NON REBUILT @ %p\n",cpydata);
                free(cpydata);
            });
        } 
        else
        {
            H4AT_PRINT1("No enough memory for malloc at _recv!\n");
            rq->_notify(ERR_MEM, _HAL_freeHeap());
            err = ERR_MEM;
        }
    }
    if (p) {
        altcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
    }
    return err;
}

void H4AsyncClient::dumptxQueueClients() {
    H4AT_PRINT2("txQueueClients %d\n", txQueueClients.size());
#if H4AT_DEBUG>=2
    for (const auto c : txQueueClients) H4AT_PRINTF("%p\t", c);
    H4AT_PRINTF("\n");
#endif
}

err_t _raw_sent(void* arg,struct altcp_pcb *tpcb, u16_t len){
    H4AT_PRINT2("_raw_sent %p pcb=%p len=%d\n",arg,tpcb,len);
    auto rq=reinterpret_cast<H4AsyncClient*>(arg);
    rq->_lastSeen=millis();
    H4AsyncClient::dumptxQueueClients();
    if (H4AsyncClient::txQueueClients.size() && !H4AsyncClient::_processingQ){
        h4.queueFunction([]{
            H4AT_PRINT2("txQueueClients QF %d\n", H4AsyncClient::txQueueClients.size());
            H4AsyncClient::dumptxQueueClients();
            LwIPCoreLocker lock;
            H4AT_PRINT3("After LOCK %d\n", H4AsyncClient::txQueueClients.size());
            auto clients = H4AsyncClient::txQueueClients; 
            for (auto c:clients){
                H4AT_PRINT2("%p->_processQueue()\n", c);
                c->_processQueue();
            }
            H4AsyncClient::_processingQ = false; 
        });
        H4AsyncClient::_processingQ = true;
    }
    return ERR_OK;
}

err_t _tcp_connected(void* arg, altcp_pcb* tpcb, err_t err){
    H4AT_PRINT1("_tcp_connected %p %p e=%d\n",arg,tpcb,err);
    auto rq=reinterpret_cast<H4AsyncClient*>(arg);
    rq->_state = H4AT_CONN_CONNECTED;
    h4.queueFunction([rq,tpcb,err](){
        H4AT_PRINT2("QF tcp_connected %p %p e=%d\n",rq,tpcb,err);
        LwIPCoreLocker lock;
        auto p=reinterpret_cast<altcp_pcb*>(tpcb);
        if (!rq->connected()){
            H4AT_PRINT2("NOT CONNECTED ANYMORE\n");
            return;
        }
#if H4AT_DEBUG
        auto ip_ = altcp_get_ip(tpcb,0);
        IPAddress ip(ip_addr_get_ip4_u32(ip_));
        H4AT_PRINT1("C=%p _tcp_connected p=%p e=%d IP=%s:%d\n",rq,tpcb,err,ip.toString().c_str(),altcp_get_port(tpcb,0));
#endif
        rq->_lastSeen = millis();
        H4AsyncClient::openConnections.insert(rq);
        H4AsyncClient::unconnectedClients.erase(rq);
        H4AsyncClient::checkPCBs("CONNECTED", 1);
        altcp_recv(p, &_raw_recv);
        // ***************************************************
        altcp_sent(p, &_raw_sent);
        if(rq->_cbConnect) rq->_cbConnect();

#if H4AT_TLS
        rq->_fetchTLSOverhead();
#endif

#if H4AT_TLS_SESSION
        rq->_updateSession();
#endif
    });
    return ERR_OK;
}

void _tcp_dns_found(const char * name, ip_addr_t* ipaddr, void * arg) {
    H4AT_PRINT2("_tcp_dns_found %s i=%p p=%p\n",name,ipaddr,arg);
    auto p=reinterpret_cast<H4AsyncClient*>(arg);
    if(ipaddr){
        ip_addr_copy(p->_URL.addr, *ipaddr);
        p->_connect(); // continue on lwip thread
    } else p->_notify(H4AT_ERR_DNS_NF); // [ ] might queue on mainloop..
}
//
//
//

#if H4AT_TLS
void H4AsyncClient::_addSNI()
{
    H4AT_PRINT2("_addSNI\n");
    if (_URL.host.length() && pcb) {
        auto tls_context = static_cast<mbedtls_ssl_context*>(altcp_tls_context(pcb)); 
        if (!tls_context) {
            H4AT_PRINT2("tls_context NULL!\n");
            return;
        }
        int ret;
        if (ret=mbedtls_ssl_set_hostname(tls_context, _URL.host.c_str())) {
            H4AT_PRINT2("FAILED %d [%X]\n", ret, ret);
        }
    }
}

void H4AsyncClient::_fetchTLSOverhead()
{
    if (_isSecure && pcb){
        int ssl_expan = mbedtls_ssl_get_record_expansion(static_cast<mbedtls_ssl_context*>(altcp_tls_context(pcb)));
        if (ssl_expan > 0)
        {
            H4AT_PRINT3("SSL EXPANSION %d\n", ssl_expan);
            _ssl_overhead=ssl_expan;
        }
    }
}
#endif
#if H4AT_TLS_SESSION
void H4AsyncClient::_setTLSSession()
{
    H4AT_PRINT2("_setTLSSession()\n");
#if H4AT_TLS_SESSION
    if (_session == nullptr) {
        H4AT_PRINT2("NO Session is available internally\n");
        return;
    }
    if (!pcb) {
        H4AT_PRINT2("No connection PCB!\n");
        return;
    }
    int ret = altcp_tls_set_session(pcb, static_cast<altcp_tls_session*>(_session));
    H4AT_PRINT2("set session %s ret=%d\n", (ret == ERR_OK ? "SUCCEEDED" : "FAILED"), ret);
#endif
}

bool H4AsyncClient::_initTLSSession()
{
    H4AT_PRINT2("initTLSSession()\n");
    if (!pcb) {
        H4AT_PRINT2("No connection\n");
        return false;
    }
    if (!_session) {
        H4AT_PRINT2("No session pointer\n");
        return false;
    }

    altcp_tls_init_session(static_cast<altcp_tls_session *>(_session));    
	return true;

}
void H4AsyncClient::_updateSession()
{
    H4AT_PRINT2("_updateSession()\n");
    if (_isSecure && _sessionEnabled) {
        auto old_session = _session;
        _session = getTLSSession();

        if (old_session != _session && _cbSession) _cbSession(_session);
    }
}
void H4AsyncClient::_removeSession()
{
    H4AT_PRINT2("_removeSession() en=%d _session=%p\n", _sessionEnabled, _session);
    if (_sessionEnabled) {
        if (_session) {
            freeTLSSession(_session);
            _session = nullptr;
            if (_cbSession) _cbSession(_session);
        }
    }
}
#endif

void H4AsyncClient::enableTLSSession()
{
#if H4AT_TLS_SESSION
    _sessionEnabled = true;
#endif
}

void H4AsyncClient::disableTLSSession()
{
#if H4AT_TLS_SESSION
    _sessionEnabled = false;
#endif
}

void *H4AsyncClient::getTLSSession()
{
    H4AT_PRINT2("getTLSSession()\n");
#if H4AT_TLS_SESSION
    if (!pcb) {
        H4AT_PRINT2("No connection PCB\n");
        return nullptr;
    }
    if (_isSecure && _sessionEnabled) {
        if (!_session) {
            _session = new altcp_tls_session;
            _initTLSSession();
        }
        int ret = altcp_tls_get_session(pcb, static_cast<altcp_tls_session *>(_session));
        if (ret != ERR_OK) {
            H4AT_PRINT1("get session failed, ret=%d\n", ret);
            return nullptr;
        }
        H4AT_PRINT2("_session=%p\n", _session);
        return static_cast<void*>(_session);
    }
#endif
	return nullptr;
}

void H4AsyncClient::setTLSSession(void *session)
{
    H4AT_PRINT2("setTLSSession(%p)\n", session);
#if H4AT_TLS_SESSION
    _session = session;
#endif
}
void H4AsyncClient::freeTLSSession(void* session)
{
    H4AT_PRINT2("freeTLSSession(%p)\n", session);
#if H4AT_TLS_SESSION
    if (session) {
        auto altcp_session = static_cast<altcp_tls_session *>(session);
        altcp_tls_free_session(altcp_session);
        delete altcp_session;
    }
#endif
}


H4AsyncClient::H4AsyncClient(struct altcp_pcb *newpcb) : pcb(newpcb)
{
	//    _heapLO=(_HAL_freeHeap() * H4T_HEAP_CUTOUT_PC) / 100;
	//    _heapHI=(_HAL_freeHeap() * H4T_HEAP_CUTIN_PC) / 100;
    H4AT_PRINT1("H4AC CTOR %p PCB=%p\n",this,pcb);
    if(pcb) { // H4AsyncServer receives the pcb, already connected.
        // A server.
        LwIPCoreLocker lock;
        altcp_arg(pcb, this);
        altcp_recv(pcb, &_raw_recv);
        altcp_err(pcb, &_raw_error);
        altcp_sent(pcb, &_raw_sent);
#if H4AT_TLS
        _isSecure=pcb->inner_conn != NULL;
#endif    
        _lastSeen=millis();
    }
    else {
        // A client.
        unconnectedClients.insert(this);
        _creatTime = millis();
    }
}

H4AsyncClient::~H4AsyncClient()
{
    H4AT_PRINT2("H4AsyncClient DTOR %p pcb=%p _bpp=%p\n", this, pcb, _bpp); 
#if H4AT_TLS
    for (auto& key : _keys)
    {
        if (key) {
            if (key->get())
                key->clear();
            delete key;
            // key=nullptr; // unnecessary
        }
    }
#endif
    while(_queue.size())
        _popQueue();
    txQueueClients.erase(this);
}

void H4AsyncClient::_clearDanglingInput() {
    if(_bpp){
        H4AT_PRINT1("_clearDanglingInput p=%p _s=%d\n",_bpp,_stored);
        free(_bpp);
        _bpp=nullptr;
        _stored=0;
    }
}


/* [ ] CheckURL before parsing ... */
void  H4AsyncClient::_parseURL(const std::string& url){
    if(url.find("http",0)) _parseURL(std::string("http://")+url);
    else {
        std::vector<std::string> vs=split(url,"//");
        _URL = {};
        _URL.secure=url.find("https",0)==std::string::npos ? false:true;
        H4AT_PRINT4("SECURE = %d  %s\n",_URL.secure,_URL.secure ? "TRUE":"FALSE");
        _URL.scheme=vs[0]+"//";
        H4AT_PRINT4("scheme %s\n", _URL.scheme.data());

        std::vector<std::string> vs2=split(vs[1],"?");
        _URL.query=vs2.size()>1 ? vs2[1]:"";
        H4AT_PRINT4("query %s\n", _URL.query.data());

        std::vector<std::string> vs3=split(vs2[0],"/");
        _URL.path=std::string("/")+((vs3.size()>1) ? join(std::vector<std::string>(++vs3.begin(),vs3.end()),"/"):"");
        H4AT_PRINT4("path %s\n", _URL.path.data());

        std::vector<std::string> vs4=split(vs3[0],":");
        _URL.port=vs4.size()>1 ? atoi(vs4[1].data()):(_URL.secure ? 443:80);
        H4AT_PRINT4("port %d\n", _URL.port);

        _URL.host=vs4[0];
        H4AT_PRINT4("host %s\n",_URL.host.data());
    }
}

uint8_t* H4AsyncClient::_addFragment(const uint8_t* data,u16_t len){
    uint8_t* p=nullptr;
    if(_stored + len > maxPacket()){
        _clearDanglingInput();
        _notify(H4AT_INPUT_TOO_BIG,_stored + len);
    }
    else {
        p=static_cast<uint8_t*>(realloc(_bpp,_stored+len));
        if(p){
            _bpp=p;
            memcpy(_bpp+_stored,data,len);
            _stored+=len;
        }
        else {
        //  shouldn't ever happen!
            H4AT_PRINT1("not enough realloc mem\n");
            _clearDanglingInput();
        }
    }
    return p;
}

void H4AsyncClient::_handleFragment(const uint8_t* data,u16_t len,u8_t flags) {
    H4AT_PRINT1("%p _handleFragment %p %d f=0x%02x bpp=%p _s=%d\n",this,data,len,flags,_bpp,_stored);
    if(_state != H4AT_CONN_CLOSING){
        if(flags & PBUF_FLAG_PUSH){
            if(!_stored) _rxfn(data,len);
            else {
                if(_addFragment(data,len)){
                    _rxfn(_bpp,_stored);
                    _clearDanglingInput();
                } else _notify(ERR_MEM,len); 
            }
        } else if(!_addFragment(data,len)) _notify(ERR_MEM,len);
    } else H4AT_PRINT2("HF while closing!!!\n");
}

void H4AsyncClient::_scavenge(){
    static bool started=false;
    if (!started)
    {
        H4AT_PRINT2("Starting the SCAVENGER\n");
        h4.every(
            H4AS_SCAVENGE_FREQ,
            []
            { H4AsyncClient::__scavenge(); },
            nullptr,
            H4AT_SCAVENGER_ID,
            true);
        started = true;
    }
}

void H4AsyncClient::__scavenge()
{
    H4AT_PRINT1("SCAVENGE CONNECTIONS! oc=%u uc=%u\n", openConnections.size(), unconnectedClients.size());
    std::vector<H4AsyncClient*> tbd;
    // Nullified PCBs are not really needed to check, as _shutdown() will reset _lastSeen.
    for(auto &oc:openConnections){
        H4AT_PRINT1("T=%u OC %p ls=%u age(s)=%u SCAV=%u PCB=%p %s\n",millis(),oc,oc->_lastSeen,(millis() - oc->_lastSeen) / 1000,H4AS_SCAVENGE_FREQ, oc->pcb, oc->_state == H4AT_CONN_CLOSING? "CLOSING": "");
        if((millis() - oc->_lastSeen) > H4AS_SCAVENGE_FREQ || oc->_state == H4AT_CONN_CLOSING) tbd.push_back(oc);
    }
    for(auto &uc:unconnectedClients){
        H4AT_PRINT1("T=%u UC %p ct=%u age(s)=%u SCAV=%u PCB=%p\n",millis(),uc,uc->_creatTime,(millis() - uc->_creatTime) / 1000,H4AS_SCAVENGE_FREQ, uc->pcb);
        // if((millis() - uc->_creatTime) > H4AS_SCAVENGE_FREQ) tbd.push_back(uc);
        if((uc->pcb==0 && uc->_state == H4AT_CONN_CLOSING) || ((millis() - uc->_creatTime) > H4AS_SCAVENGE_FREQ)) tbd.push_back(uc);
    }
    for(auto &rq:tbd) {
        H4AT_PRINT1("Scavenging %p [%s]\n",rq, openConnections.count(rq) ? "OC" : unconnectedClients.count(rq) ? "UC" : "UNKNOWN"); 
        rq->_shutdown();
        if (openConnections.count(rq))
            openConnections.erase(rq);
        else
            unconnectedClients.erase(rq);

        delete rq;
    }
    _scavenging = false;
}

void H4AsyncClient::_connect() {
    H4AT_PRINT2("_connect p=%p state=%d\n",pcb, pcb ? getTCPState(pcb, _isSecure) : -1);
    H4AT_PRINT4("ip %s port %d\n", ipaddr_ntoa(&_URL.addr), _URL.port);
    LwIPCoreLocker lock;
#if LWIP_ALTCP
    altcp_allocator_t allocator {altcp_tcp_alloc, nullptr};
#if H4AT_TLS
    H4AT_PRINT1("_URL.secure=%d\ttls_mode=%d\n", _URL.secure, _tls_mode);
    if (_URL.secure && _tls_mode != H4AT_TLS_NONE){
        H4AT_PRINT1("Setting the secure config PCB=%p\n", pcb); // ENSURE YOU'VE CLOSED THE PREVIOUS CONNECTION by rq->close() if didn't receive onConnectFail/onDisconnect() callbacks.
        // secure.
        altcp_tls_config *_tlsConfig = nullptr;
        auto &ca_cert = _keys[H4AT_TLS_CA_CERTIFICATE];
        _isSecure = true;
        switch (_tls_mode){
            case H4AT_TLS_ONE_WAY:
                _tlsConfig = altcp_tls_create_config_client(ca_cert->get(), ca_cert->len);
                H4AT_PRINT2("ONE WAY TLS _tlsConfig=%p\n", _tlsConfig);
                break;

            case H4AT_TLS_TWO_WAY:
            {
                auto &privkey = _keys[H4AT_TLS_PRIVATE_KEY];
                auto &privkey_pass = _keys[H4AT_TLS_PRIVAKE_KEY_PASSPHRASE];
                auto &client_cert = _keys[H4AT_TLS_CERTIFICATE];

                _tlsConfig = altcp_tls_create_config_client_2wayauth(ca_cert->get(), ca_cert->len,
                                                               privkey->get(), privkey->len,
                                                               privkey_pass ? privkey_pass->get() : NULL, privkey_pass ? privkey_pass->len : 0,
                                                               client_cert->get(), client_cert->len);
                H4AT_PRINT2("TWO WAY TLS conf=%p\n", _tlsConfig);
            }
                break;
            default:
            H4AT_PRINT1("WRONG _tls_mode!\n");
            _notify(H4AT_WRONG_TLS_MODE);
        }
        if (_tlsConfig) {
            allocator = altcp_allocator_t{altcp_tls_alloc, _tlsConfig};
        }
        else {
            H4AT_PRINT1("INVALID TLS CONFIGURATION\n");
            _notify(H4AT_BAD_TLS_CONFIG);
            return;
        }
    } else {
        H4AT_PRINT1("SETTING TCP CHANNEL\n");
        allocator = altcp_allocator_t {altcp_tcp_alloc, nullptr};
    }
#endif
#else
#endif
    pcb = altcp_new_ip_type(&allocator, IPADDR_TYPE_ANY);
    if (!pcb) {
        H4AT_PRINT1("NO PCB ASSIGNED!\n");
        _notify(H4AT_ERR_NO_PCB);
        return;
    }
    altcp_arg(pcb, this);
    altcp_err(pcb, &_raw_error);
#if H4AT_TLS_SESSION
    H4AT_PRINT1("_sessionEnabled=%d _session %p\n", _sessionEnabled, _session);
    if (_isSecure && _sessionEnabled) {
        if (_session) { // There's a session has been set by the user, inject it.
            // The user must assure any previous session gets freed, else it will cause memory leak.
            _setTLSSession();
        }
    }
#endif
#if H4AT_TLS
    if (_isSecure)
        _addSNI();
#endif
    _notify(altcp_connect(pcb, &_URL.addr, _URL.port,(altcp_connected_fn)&_tcp_connected));
    _scavenge();
}

//
//      PUBLICS
//
void H4AsyncClient::connect(const std::string& host,uint16_t port){
    H4AT_PRINT2("connect h=%s, port=%d\n",host.data(),port);
    IPAddress ip;
    if(ip.fromString(host.data())) connect(ip,port);
    else {
        _URL.port=port;
        LwIPCoreLocker lock;
        err_t err = dns_gethostbyname(host.data(), &_URL.addr, (dns_found_callback)&_tcp_dns_found, this);
        if(err) _notify(H4AT_ERR_DNS_FAIL,err);
        else _connect();
    }
}

void H4AsyncClient::connect(const std::string& url){
    _parseURL(url);
   connect(_URL.host,_URL.port);
}

void H4AsyncClient::connect(IPAddress ip,uint16_t port){
    H4AT_PRINT2("connect ip=%s, port=%d\n",ip.toString().c_str(),_URL.port);
    _URL.port=port;
    ip_addr_set_ip4_u32(&_URL.addr, ip);
    _connect();
}

bool H4AsyncClient::connected(){ return _state == H4AT_CONN_CONNECTED/*  && pcb && getTCPState(pcb, _isSecure) == ESTABLISHED */; } // Unnecessary checks? (pcb && getState) as there will happen some data races ...

std::string H4AsyncClient::errorstring(int e){
    #ifdef H4AT_DEBUG
        if(_errorNames.count(e)) return _errorNames[e];
        else return stringFromInt(e); 
    #else
        return stringFromInt(e); 
    #endif
}

uint32_t H4AsyncClient::localAddress() { 
    LwIPCoreLocker lock;
    auto ip = altcp_get_ip(pcb,1);
    return ip_addr_get_ip4_u32(ip); 
}
IPAddress H4AsyncClient::localIP(){ return IPAddress( localAddress()); }
std::string H4AsyncClient::localIPstring(){ return std::string(ipaddr_ntoa(altcp_get_ip(pcb,1)));}
    // { return std::string(localIP().toString().c_str()); }
uint16_t H4AsyncClient::localPort(){ return altcp_get_port(pcb,1); };

void H4AsyncClient::nagle(bool enable){
//     Serial.printf("NAGLE %s\n",enable?"ON":"OFF");
    LwIPCoreLocker lock;
    if(pcb){
        if(enable) { altcp_nagle_enable(pcb); _nagle=true; }
        else { altcp_nagle_disable(pcb); _nagle=false; }
        // Serial.printf("PCB FLAGS=0x%02x\n",pcb->flags);
    } //else Serial.printf("NAGLE PCB NULL\n");
}

uint32_t H4AsyncClient::remoteAddress() { 
    LwIPCoreLocker lock;
    auto ip = altcp_get_ip(pcb,0);
    return ip_addr_get_ip4_u32(ip); 
}
IPAddress H4AsyncClient::remoteIP(){ return IPAddress( remoteAddress()); }
std::string H4AsyncClient::remoteIPstring(){ return std::string(ipaddr_ntoa(altcp_get_ip(pcb,0))); }
uint16_t H4AsyncClient::remotePort(){ return altcp_get_port(pcb,0);  }

size_t H4AsyncClient::_processTX(const uint8_t *data, size_t length, bool copy)
{
    H4AT_PRINT2("_processTX(%p,%d,%d)\n", data,length,copy);
    LwIPCoreLocker lock;
    if (!connected()) return ERR_CONN;
    uint8_t flags;
    size_t  sent=0;
    size_t  left=length;
    // dumphex(data,len);

    while(left){
        size_t available=altcp_sndbuf(pcb);
        auto qlen = altcp_sndqueuelen(pcb);
        if(available && qlen < TCP_SND_QUEUELEN){
            auto chunk=std::min(left,available);
            flags=copy ? TCP_WRITE_FLAG_COPY:0;
            if(left - chunk) flags |= TCP_WRITE_FLAG_MORE;
            H4AT_PRINT2("WRITE %p L=%d F=0x%02x LEFT=%d Q=%d\n",data+sent,chunk,flags,left,qlen);
            auto err = altcp_write(pcb, data+sent, chunk, flags);
            if(!err) {
                err=altcp_output(pcb);
                if(err) H4AT_PRINT1("ERR %d after output H=%u sb=%d Q=%d\n",err,_HAL_freeHeap(),altcp_sndbuf(pcb),altcp_sndqueuelen(pcb));
            }

            // lock.unlock();
            if (err) {
                H4AT_PRINT1("ERR %d after write H=%u sb=%d Q=%d\n", err, _HAL_freeHeap(), altcp_sndbuf(pcb), altcp_sndqueuelen(pcb));
                _notify(err,44);
                return err;
            }
            else {
                sent+=chunk;
                left-=chunk;
            }
        }
        else break;
    }

	return sent;
}

bool H4AsyncClient::_processQueue() {
    H4AT_PRINT2("_processQueue %p\n", this);

    LwIPCoreLocker lock;
    if (!connected()) {
        H4AT_PRINT2("_processQueue UNCONNECTED!\n");
        return false;
    }
    bool done=true;

    H4AT_PRINT3("_queue.size() %d\n", _queue.size());
    while (_queue.size() && done) {
        done=false;
        auto& qd=*_queue.front();
        auto sent = _processTX(qd.m.get() + qd.tx_len, qd.m.len - qd.tx_len, qd.m.managed);
        // Serial.printf("sent=%d condition %d\n", sent, sent>0 && sent<=qd.m.len);
        if (sent > 0 && sent <= qd.m.len)
            qd.tx_len += sent;

        if (qd.tx_len == qd.m.len){
            _popQueue();
            done=true;
        }
    }
    // if (_queue.size())
    //     h4.queueFunction([=]{_processQueue();},nullptr,H4AT_TCPQUEUE_ID,true); // Bug in h4.queueFunction (overriding?) for singletons
    if (_queue.empty()) txQueueClients.erase(this);
    return _queue.empty();
}


void H4AsyncClient::TX(const uint8_t* data,size_t len,bool copy){ 
    H4AT_PRINT1("TX pcb=%p data=%p len=%d copy=%d max=%d\n",pcb,data,len,copy, maxPacket());
    LwIPCoreLocker lock;
    if(!connected()){
        H4AT_PRINT1("%p TX called %s!\n", this, _state == H4AT_CONN_CLOSING ? "during close" : _state == H4AT_CONN_WILLCLOSE ? "and it will close" : "before connect or after cnx error");
        _notify(0,_state == H4AT_CONN_UNCONNECTED ? H4AT_UNCONNECTED : H4AT_CLOSING);
    }
    else {
        auto emptyQ = _queue.empty();
        size_t sent=0;
        H4AT_PRINT2("emptyQ %d _processingQ %d\n", emptyQ, _processingQ);
        if (!_processingQ || emptyQ){
            emptyQ=_processQueue();

            if (emptyQ) {
                sent = _processTX(data, len, copy);
                H4AT_PRINT2("_processTX()->%d\n", sent);
            } else {
                H4AT_PRINT2("_queue isn't empty!\n");
            }
        }
        lock.unlock();
        if (sent < len){
            H4AT_PRINT2("Incomplete TX left %d\n", len - sent);
            // Do queue the current TX.
            _queue.push(new TCPData{data+sent, len-sent, copy});
            txQueueClients.insert(this);
        }
    }
    return;
}

#if H4AT_TLS
void H4AsyncClient::secureTLS(const u8_t * ca, size_t ca_len, const u8_t * privkey, size_t privkey_len, const u8_t * privkey_pass, size_t privkey_pass_len, const u8_t * cert, size_t cert_len)
{
    if (!ca || ca_len==0) return;
    H4AT_PRINT4("secureTLS(%p, %d, %p, %d, %p, %d, %p, %d)\n", ca, ca_len, privkey, privkey_len, privkey_pass, privkey_pass_len, cert, cert_len);

    _keys[H4AT_TLS_CA_CERTIFICATE] = new mbx{const_cast<u8_t*>(ca), ca_len};

    _tls_mode = H4AT_TLS_ONE_WAY;
    if (!privkey || privkey_len == 0 || !cert || cert_len == 0) return;

    _keys[H4AT_TLS_PRIVATE_KEY] = new mbx{const_cast<u8_t*>(privkey), privkey_len};
    if (privkey_pass && privkey_pass_len)
        _keys[H4AT_TLS_PRIVAKE_KEY_PASSPHRASE] = new mbx{const_cast<u8_t*>(privkey_pass), privkey_pass_len};
    _keys[H4AT_TLS_CERTIFICATE] = new mbx{const_cast<u8_t*>(cert), cert_len};

    _tls_mode = H4AT_TLS_TWO_WAY;
}
#endif
#if H4AT_TLS_CHECKER
bool H4AsyncClient::isCertValid(const u8_t *cert, size_t cert_len)
{
    static mbedtls_x509_crt chain;
    auto r = mbedtls_x509_crt_parse(&chain, cert, cert_len);
    _H4AT_PRINTF("Certificate(s) parsing %s\n", r ? "Failed" : "Succeeded");
    if (r)
        _H4AT_PRINTF("Parse error %x [%d]\n", r, r);

	return (r==0);
}
bool H4AsyncClient::isPrivKeyValid(const u8_t *privkey, size_t privkey_len,
                                                    const u8_t *privkey_pass, size_t privkey_pass_len)
{
    static mbedtls_pk_context ctx;
    mbedtls_pk_init(&ctx);
#if MBEDTLS_VERSION_MAJOR >= 3
    static mbedtls_ctr_drbg_context ctr_drbg;
    static mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    auto r = mbedtls_pk_parse_key(&ctx, privkey, privkey_len, privkey_pass, privkey_pass_len
                            , mbedtls_ctr_drbg_random, &ctr_drbg
    );
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
#else
    auto r = mbedtls_pk_parse_key(&ctx, privkey, privkey_len, privkey_pass, privkey_pass_len); // Future versions requires RNGs (function f_rng, parameter p_rng)
#endif
    mbedtls_pk_free(&ctx);
    _H4AT_PRINTF("Private Key Parsing %s\n", r ? " Failed" : "Succeeded");
    if (r)
        _H4AT_PRINTF("Parse error %x [%d]\n", r, r);

	return (r==0);
}
#endif