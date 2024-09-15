#include <H4AsyncTCP.h>

#include "lwipopts.h"
#include "lwip/tcpip.h"

#if H4AT_HAS_RTOS
volatile int LwIPCoreLocker::_locks=0;
#endif
#define PRINTAPPENDS "\t=====LOCKER=====\t"

#if NO_SYS == 0
#define H4AT_LWIP_CORE_LOCK() 		LOCK_TCPIP_CORE()
#define H4AT_LWIP_CORE_UNLOCK() 	UNLOCK_TCPIP_CORE()
inline bool canLock() { return strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME) == 0; }
#else
	#if TARGET_RP2040
		#if H4AT_RP2040_DONTLOCKUNLOCK
			#define H4AT_LWIP_CORE_LOCK()
			#define H4AT_LWIP_CORE_UNLOCK()
			inline bool canLock() { return false; }
		#else
			#include <pico/cyw43_arch.h>
			#include <pico/async_context_threadsafe_background.h>
			static auto context = cyw43_arch_async_context();
			#define H4AT_LWIP_CORE_LOCK() 	async_context_acquire_lock_blocking(context)
			#define H4AT_LWIP_CORE_UNLOCK() async_context_release_lock(context)
			inline bool canLock() { 
				auto self = (async_context_threadsafe_background_t*) context;
				return self->lock_mutex.enter_count == 0;	
			}
		#endif
	#endif
#endif
LwIPCoreLocker::LwIPCoreLocker() {
#if H4AT_HAS_RTOS
	lock();
#endif
}

void LwIPCoreLocker::unlock()
{
#if H4AT_HAS_RTOS
	H4AT_PRINT4(PRINTAPPENDS"LwIPCoreLocker::unlock _locks=%d _locking=%d\n", _locks, _locking);
#if TARGET_RP2040 == 0
	if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME) == 0)
	{
		H4AT_PRINT4(PRINTAPPENDS"Don't UNLOCK from LWIP THREAD\n");
		return;
	}
#endif

	if (_locking){
		_locks = _locks - 1;
		if (_locks == 0) {
			H4AT_LWIP_CORE_UNLOCK();
		}
	}
	_locking=false;
#endif
}

LwIPCoreLocker::~LwIPCoreLocker()
{
#if H4AT_HAS_RTOS
	H4AT_PRINT4(PRINTAPPENDS"~LwIPCoreLocker\n");
	unlock();
#endif
}

void LwIPCoreLocker::lock()
{
#if H4AT_HAS_RTOS
	H4AT_PRINT4(PRINTAPPENDS"LwIPCoreLocker _locks=%d _locking=%d\n", _locks, _locking);
	if (_locking) {
		H4AT_PRINT4(PRINTAPPENDS "LwIPCoreLocker Already locking\n");
		return;
	}
#if TARGET_RP2040 == 0
    if (strcmp(H4AS_RTOS_GET_THREAD_NAME, TCPIP_THREAD_NAME) == 0)
	{
		H4AT_PRINT4(PRINTAPPENDS"Don't LOCK from LWIP THREAD\n");
		return;
	}
#else
	if (canLock() == false) {
		H4AT_PRINT4(PRINTAPPENDS"Can't LOCK. Already locked\n");
		return;
	}
#endif
	if (_locks == 0) { // The first lock
		H4AT_LWIP_CORE_LOCK();
	}
	_locks = _locks + 1;
	_locking = true;
#endif
}

bool LwIPCoreLocker::locking() {
#if H4AT_HAS_RTOS
	return _locking;
#else
	return false;
#endif
}
