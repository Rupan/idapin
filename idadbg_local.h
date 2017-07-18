#ifndef IDADBG_LOCAL_H
#define IDADBG_LOCAL_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <deque>
#include <map>
#include <set>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#ifndef _WIN32

#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>

#else

namespace WINDOWS
{
#undef timerisset
#undef timercmp
#undef timerclear
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinUser.h>
#include <Ws2tcpip.h>
};

#endif

#ifndef qnotused
#  define qnotused(x)   (void)x
#endif

//--------------------------------------------------------------------------
// How many miliseconds to wait for incoming packets
#define RCV_TIMEOUT  10

//--------------------------------------------------------------------------
// Wrappers for OS-depended types/functions
//--------------------------------------------------------------------------
#ifdef _WIN32

# if _MSC_VER
#   if PIN_BUILD_NUMBER < 76991 || defined(__LINT__)
#     define snprintf _snprintf
#     define bzero(b,len) (memset((b), '\0', (len)), (void) 0)
#     define bcopy(b1,b2,len) (memmove((b2), (b1), (len)), (void) 0)
#   endif
# endif

# if defined(_WIN64) && PIN_BUILD_NUMBER < 76991
  typedef signed __int64 ssize_t;
# else
  typedef signed int ssize_t;
# endif

typedef WINDOWS::SOCKET PIN_SOCKET;

#define pin_socket      p_socket
#define pin_htons       p_htons
#define pin_bind        p_bind
#define pin_listen      p_listen
#define pin_accept(s, addr, addrlen) p_accept(s, (WINDOWS::sockaddr *)addr, addrlen)
#define pin_select(s, rds, wds, eds, tv) p_select(s, rds, wds, eds, tv)
#define pin_setsockopt(s, level, optname, optval, optlen) p_setsockopt(s, level, optname, (const char*)optval, optlen)
#define pin_closesocket(s)  p_closesocket(s)
typedef WINDOWS::timeval pin_timeval;
typedef WINDOWS::fd_set pin_fd_set;

// the following typedefs are necessary for FD_... macros
#define  fd_set WINDOWS::fd_set
typedef WINDOWS::u_int u_int;
typedef WINDOWS::u_short u_short;
typedef WINDOWS::SOCKET SOCKET;

#define pin_sockaddr    WINDOWS::sockaddr
#define pin_socklen_t   WINDOWS::socklen_t
#define pin_sockaddr_in WINDOWS::sockaddr_in

#else

#define PIN_SOCKET      int
#define  INVALID_SOCKET -1
#define pin_socket      socket
#define pin_accept      accept
#define pin_select      select
#define pin_timeval     struct timeval
#define pin_fd_set      fd_set
#define pin_setsockopt  setsockopt
#define pin_sockaddr_in sockaddr_in
#define pin_htons       htons
#define pin_bind        bind
#define pin_listen      listen
#define pin_sockaddr    sockaddr
#define pin_socklen_t   socklen_t
#define pin_closesocket close

#endif

//--------------------------------------------------------------------------
// Internal macros/types
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// in versions prior to 2.13 locking functions had names without 'PIN_' prefix
#if PIN_PRODUCT_VERSION_MAJOR < 2 || (PIN_PRODUCT_VERSION_MAJOR == 2 && PIN_PRODUCT_VERSION_MINOR <= 12)
#  define PIN_InitLock     InitLock
#  define PIN_GetLock      GetLock
#  define PIN_ReleaseLock  ReleaseLock
#endif

//--------------------------------------------------------------------------
// OS we are running on
#ifdef TARGET_WINDOWS
#define TARGET_OS PIN_TARGET_OS_WINDOWS
#else
#  ifdef TARGET_LINUX
#    define TARGET_OS PIN_TARGET_OS_LINUX
#  else
#    ifdef TARGET_MAC
#      define TARGET_OS PIN_TARGET_OS_MAC
#    else
#      error "Unsupported OS"
#    endif
#  endif
#endif

//--------------------------------------------------------------------------
// Logging & debug
#define MSG(fmt, ...)                                       \
  do                                                        \
  {                                                         \
    if ( debug_level > 0 )                                  \
    {                                                       \
      char _buf[1024];                                      \
      pin_snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__); \
      fprintf(stderr, "%s", _buf);                          \
      LOG(_buf);                                            \
    }                                                       \
  }                                                         \
  while ( 0 )

#define DEBUG(level, fmt, ...)                            \
  do                                                      \
  {                                                       \
    if ( debug_level >= level )                           \
      MSG(fmt, ##__VA_ARGS__);                            \
  }                                                       \
  while ( 0 )

//lint -esym(750, SEMAFORE_WAIT) local macro 'SEMAFORE_WAIT' not referenced
//lint -esym(750, SEMAFORE_CLEAR) local macro 'SEMAFORE_CLEAR' not referenced
//lint -esym(750, SEMAFORE_SET) local macro 'SEMAFORE_SET' not referenced
//lint -esym(750, WAIT_AFTER_CALLBACK) local macro 'WAIT_AFTER_CALLBACK' not referenced
#define SEMAFORE_WAIT(x) \
  do \
  {\
    if ( !PIN_SemaphoreIsSet(x) ) \
    {\
      DEBUG(3, "(%d / %d) WAIT for %s...\n", int(PIN_GetTid()), __LINE__, #x);\
      PIN_SemaphoreWait(x);\
      DEBUG(3, "(%d / %d) WAIT Ok\n", int(PIN_GetTid()), __LINE__);\
    } \
    else\
      PIN_SemaphoreWait(x);\
  }\
  while ( false )

#define APP_WAIT(x) \
  do \
  {\
    DEBUG(3, "(%d / %d) APP_WAIT %s...\n", int(PIN_GetTid()), __LINE__, #x);\
    wait_app_resume(x);\
  }\
  while ( false )

#define SEMAFORE_CLEAR(x) \
  do \
  {\
    DEBUG(2, "(%d / %d) CLEAR %s...\n", int(PIN_GetTid()), __LINE__, #x);\
    PIN_SemaphoreClear(x);\
  }\
  while ( false )

#define SEMAFORE_SET(x) \
  do \
  {\
    DEBUG(2, "(%d / %d) SET %s...\n", int(PIN_GetTid()), __LINE__, #x);\
    PIN_SemaphoreSet(x);\
  }\
  while ( false )

#define WAIT_AFTER_CALLBACK() \
  do \
  {\
    janitor_for_pinlock_t process_state_guard(&process_state_lock);\
    DEBUG(3, "(%d / %d) callback wait...\n", int(PIN_GetTid()), __LINE__);\
    breakpoints.prepare_suspend();\
  }\
  while ( false )

#define app_wait(sem)          APP_WAIT(sem)
#define sema_wait(sem)         SEMAFORE_WAIT(sem)
#define sema_clear(sem)        SEMAFORE_CLEAR(sem)
#define sema_set(sem)          SEMAFORE_SET(sem)
#define wait_after_callback()  WAIT_AFTER_CALLBACK()

//--------------------------------------------------------------------------
// tracebuf entry
struct trc_element_t
{
  idapin_registers_t regs;
  ADDRINT ea;
  THREADID tid;
  pin_tev_type_t type;

  trc_element_t(THREADID _tid, ADDRINT _ea, pin_tev_type_t _type)
    : ea(_ea), tid(_tid), type(_type)
  {
    regs.eip = ea;

    regs.eax =
    regs.ebx =
    regs.ecx =
    regs.edx =
    regs.esi =
    regs.edi =
    regs.ebp =
    regs.esp =
#if defined(PIN_64)
    regs.r8 =
    regs.r9 =
    regs.r10 =
    regs.r11 =
    regs.r12 =
    regs.r13 =
    regs.r14 =
    regs.r15 =
#endif
    regs.eflags =
    regs.cs =
    regs.ds =
    regs.es =
    regs.fs =
    regs.gs =
    regs.ss = BADADDR;
  };
};

//--------------------------------------------------------------------------
class janitor_for_pinlock_t
{
protected:
  PIN_LOCK *resource;
public:
  janitor_for_pinlock_t(PIN_LOCK *lock) : resource(lock)
  {
    PIN_GetLock(resource, PIN_ThreadId() + 1);
  }
  ~janitor_for_pinlock_t()
  {
    if ( resource != NULL )
      release();
  }
  //lint -sem(janitor_for_pinlock_t::release,cleanup)
  void release()
  {
    PIN_ReleaseLock(resource);
    resource = NULL;
  }
};

#endif
