/*

    IDA trace: PIN tool to communicate with IDA's debugger

*/
#ifndef _IDADBG_H
#define _IDADBG_H

#include <vector>
#include <string.h>

using namespace std;

typedef unsigned int uint32;
typedef unsigned char uchar;

// IDA pintool protocol version                  Acceptable client versions
// 1 - initial, deprecated                                 -
// 2 - 64bit addresses, STEP INTO, etc                     2
// 3 - added trace intervals to PTT_SET_TRACE packet       2,3
// 4 - CHANGE_REGVALS packet                               2,3,4
// 5 - Support FPU/XMM registers, PTT_GET_SEGBASE packet   2..5
// 6 - Event notification, PTT_WRITE_MEMORY packet         2..6
// 7 - PTT_READ_SYMBOLS packet                             2..7
#define PIN_PROTOCOL_VERSION 7

#ifdef IDA_SDK_VERSION
// IDA specific declarations
#   define pin_strncpy  ::qstrncpy
#   define pin_snprintf ::qsnprintf
#   define addr_t         ea_t
#   define pin_thid       thid_t
#   define pin_size_t     uint32
#   define pin_pid_t      pid_t
#   define pin_event_id_t event_id_t
#   define pin_bpttype_t  bpttype_t
#ifdef __EA64__
#   define BITNESS 2
#   define PIN_64
#else
#   define BITNESS 1
#endif
#else
// PIN specific declarations
#   define pin_strncpy  strncpy
#   define pin_snprintf snprintf
#   define addr_t ADDRINT
#   define ea_t addr_t
#   define pin_thid OS_THREAD_ID
#   define NO_THREAD pin_thid(0)
#   define pin_size_t uint32
#   define pin_pid_t  uint32
#   define MAXSTR 1024
#   define BADADDR -1
#   define qvector std::vector
#   define qstring std::string

#if defined(_MSC_VER)
typedef unsigned __int64 uint64;
typedef          __int64 int64;
#else
typedef unsigned long long uint64;
typedef          long long int64;
#endif

#ifdef TARGET_IA32
#   define BITNESS    1
#   define HEX_FMT    "%x"
#   define HEX64_FMT  "%llx"
#   define HEX64T_FMT "%llux"
#else
#   define BITNESS   2
#   define PIN_64    1
#   define HEX_FMT   "%lx"
#   define HEX64_FMT "%llx"
#   define HEX64T_FMT "%llux"
#endif

// structures and definitions copied from IDA SDK (idd.hpp)

#define SEGPERM_EXEC  1 // Execute
#define SEGPERM_WRITE 2 // Write
#define SEGPERM_READ  4 // Read

// the replica of event_id_t declared in idd.hpp
enum pin_event_id_t
{
  NO_EVENT       = 0x00000000, // Not an interesting event. This event can be
                               // used if the debugger module needs to return
                               // an event but there are no valid events.
  PROCESS_START  = 0x00000001, // New process has been started.
  PROCESS_EXIT   = 0x00000002, // Process has been stopped.
  THREAD_START   = 0x00000004, // New thread has been started.
  THREAD_EXIT    = 0x00000008, // Thread has been stopped.
  BREAKPOINT     = 0x00000010, // Breakpoint has been reached. IDA will complain
                               // about unknown breakpoints, they should be reported
                               // as exceptions.
  STEP           = 0x00000020, // One instruction has been executed. Spurious
                               // events of this kind are silently ignored by IDA.
  EXCEPTION      = 0x00000040, // Exception.
  LIBRARY_LOAD   = 0x00000080, // New library has been loaded.
  LIBRARY_UNLOAD = 0x00000100, // Library has been unloaded.
  INFORMATION    = 0x00000200, // User-defined information.
                               // This event can be used to return empty information
                               // This will cause IDA to call get_debug_event()
                               // immediately once more.
  _SYSCALL       = 0x00000400, // Syscall (not used yet).
  WINMESSAGE     = 0x00000800, // Window message (not used yet).
  PROCESS_ATTACH = 0x00001000, // Successfully attached to running process.
  PROCESS_DETACH = 0x00002000, // Successfully detached from process.
  PROCESS_SUSPEND= 0x00004000, // Process has been suspended..
                               // This event can be used by the debugger module
                               // to signal if the process spontaneously gets
                               // suspended (not because of an exception,
                               // breakpoint, or single step). IDA will silently
                               // switch to the 'suspended process' mode without
                               // displaying any messages.
  TRACE_FULL     = 0x00008000, // The trace being recorded is full.
};

// Trace event types:
enum pin_tev_type_t
{
  tev_none = 0, // no event
  tev_insn,     // an instruction trace
  tev_call,     // a function call trace
  tev_ret,      // a function return trace
  tev_bpt,      // write, read/write, execution trace
  tev_mem,      // memory layout changed
  tev_event,    // debug event occurred
  tev_trace,    // a trace event (used for tracers like PIN)
  tev_max,      // first unused event type
};

// Hardware breakpoint types. Fire the breakpoint upon:
typedef int bpttype_t;
const bpttype_t
  BPT_WRITE    = 1,             // Write access
  BPT_READ     = 2,             // Read access
  BPT_RDWR     = 3,             // Read/write access
  BPT_SOFT     = 4,             // Software breakpoint
  BPT_EXEC     = 8;             // Execute instruction

#endif

//--------------------------------------------------------------------------
// OS id - will send by PIN tool in response to PTT_HELLO
enum pin_target_os_t
{
  PIN_TARGET_OS_UNDEF   = 0x0000,
  PIN_TARGET_OS_WINDOWS = 0x1000,
  PIN_TARGET_OS_LINUX   = 0x2000,
  PIN_TARGET_OS_MAC     = 0x4000,
};

//--------------------------------------------------------------------------
#pragma pack(push, 1)

struct pin_module_info_t
{
  char name[MAXSTR];    // full name of the module.
  uint64 base;          // module base address. if unknown pass BADADDR
  pin_size_t size;      // module size. if unknown pass 0
  uint64 rebase_to;     // if not BADADDR, then rebase the program to the specified address
};

struct pin_e_breakpoint_t
{
  uint64 hea;           // Possible address referenced by hardware breakpoints
  uint64 kea;           // Address of the triggered bpt from the kernel's point
                        // of view (for some systems with special memory mappings,
                        // the triggered ea might be different from event ea).
                        // Use to BADADDR for flat memory model.
};

struct pin_e_exception_t
{
  uint32 code;          // Exception code
  bool can_cont;        // Execution of the process can continue after this exception?
  uint64 ea;            // Possible address referenced by the exception
  char info[MAXSTR];    // Exception message
};

//--------------------------------------------------------------------------
struct pin_debug_event_t
{
  pin_debug_event_t(uint32 evid = NO_EVENT, uint64 addr = BADADDR)
    : eid(evid), pid(pin_pid_t(0)), tid(NO_THREAD), ea(addr) {}
                          // The following fields must be filled for all events:
  uint32    eid;          // Event code (used to decipher 'info' union)
  pin_pid_t pid;          // Process where the event occured
  pin_thid tid;           // Thread where the event occured
  uint64 ea;              // Address where the event occured
  union
  {
    bool handled;         // not used for the moment
#define PIN_DEBEV_REFRESH_MEMINFO   0x1
    char flags;
  };
  union
  {
    pin_module_info_t modinfo; // PROCESS_START, PROCESS_ATTACH, LIBRARY_LOAD
    int exit_code;             // PROCESS_EXIT, THREAD_EXIT
    char info[MAXSTR];         // LIBRARY_UNLOAD (unloaded library name)
                               // INFORMATION (will be displayed in the
                               //              messages window if not empty)
    pin_e_breakpoint_t bpt;    // BREAKPOINT
    pin_e_exception_t exc;     // EXCEPTION
  };
};

//--------------------------------------------------------------------------
enum packet_type_t
{
  PTT_ACK = 0,
  PTT_ERROR = 1,
  PTT_HELLO = 2,
  PTT_EXIT_PROCESS = 3,
  PTT_START_PROCESS = 4,
  PTT_DEBUG_EVENT = 5,
  PTT_READ_EVENT = 6,
  PTT_MEMORY_INFO = 7,
  PTT_READ_MEMORY = 8,
  PTT_DETACH = 9,
  PTT_COUNT_TRACE = 10,
  PTT_READ_TRACE = 11,
  PTT_CLEAR_TRACE = 12,
  PTT_PAUSE = 13,
  PTT_RESUME = 14,
  PTT_RESUME_START = 15,    // not used since v.2
  PTT_ADD_BPT = 16,
  PTT_DEL_BPT = 17,
  PTT_RESUME_BPT = 18,      // not used since v.2
  PTT_CAN_READ_REGS = 19,
  PTT_READ_REGS = 20,
  PTT_SET_TRACE = 21,
  PTT_SET_OPTIONS = 22,
  PTT_STEP = 23,
  PTT_THREAD_SUSPEND = 24,
  PTT_THREAD_RESUME = 25,
  PTT_CHANGE_REGVALS = 26,
  PTT_GET_SEGBASE = 27,
  PTT_WRITE_MEMORY = 28,
  PTT_READ_SYMBOLS = 29,
  PTT_END = 30
};

//--------------------------------------------------------------------------
struct idapin_packet_t
{
  packet_type_t code;
  pin_size_t size;
  uint64 data;

  idapin_packet_t(packet_type_t c=PTT_ACK) : code(c), size(0), data(BADADDR)
  {
  }
};

//--------------------------------------------------------------------------
struct idapin_packet_v1_t
{
  packet_type_t code;
  pin_size_t size;
  addr_t data;

  idapin_packet_v1_t() : code(PTT_ACK), size(0), data(BADADDR)
  {
  }
};

//--------------------------------------------------------------------------
struct memimages_pkt_t
{
  packet_type_t code;
  pin_size_t size;

  memimages_pkt_t(packet_type_t _code, pin_size_t _size) : code(_code), size(_size)
  {
  }

  memimages_pkt_t() : code(PTT_ACK), size(0)
  {
  }
};

//--------------------------------------------------------------------------
struct pin_memory_info_t
{
  pin_memory_info_t(uint64 startea = 0, uint64 endea = 0, uchar _perm = 0)
    : start_ea(startea), end_ea(endea), reserved(0), bitness(BITNESS), perm(_perm)
  {
    name[0] = '\0';
  }
  uint64   start_ea;
  uint64   end_ea;
  uint32   reserved;
  char   name[MAXSTR];         // Memory area name
  uchar  bitness;              // Number of bits in segment addresses (0-16bit, 1-32bit, 2-64bit)
  uchar  perm;                 // Memory area permissions (0-no information): see segment.hpp
};
typedef qvector<pin_memory_info_t> pin_meminfo_vec_t;

//--------------------------------------------------------------------------

enum mem_actions_t
{
  MA_READ=0,
  MA_WRITE
};

struct idamem_packet_t
{
  mem_actions_t action;               // 0-Read, 1-Write
  uint64 address;
  pin_size_t size;
};

#define MEM_CHUNK_SIZE 1024
struct idamem_response_pkt_t
{
  packet_type_t code;
  pin_size_t size;
  unsigned char buf[MEM_CHUNK_SIZE];
};

#define TRACE_EVENTS_SIZE 1000

struct idapin_registers_t
{
  uint64 eax;
  uint64 ebx;
  uint64 ecx;
  uint64 edx;
  uint64 esi;
  uint64 edi;
  uint64 ebp;
  uint64 esp;
  uint64 eip;
  uint64 r8;
  uint64 r9;
  uint64 r10;
  uint64 r11;
  uint64 r12;
  uint64 r13;
  uint64 r14;
  uint64 r15;
  uint64 eflags;
  uint64 cs;
  uint64 ds;
  uint64 es;
  uint64 fs;
  uint64 gs;
  uint64 ss;
};

struct idatrace_data_t
{
  uint64   ea;
  pin_thid tid;
  uint32   type;
  idapin_registers_t registers;
};

struct idatrace_events_t
{
  packet_type_t code;
  pin_size_t size;
  idatrace_data_t trace[TRACE_EVENTS_SIZE];
};

// currently not used
struct idabpt_packet_t
{
  bpttype_t type;
  uint64 ea;
  pin_size_t size;
};

enum trace_flags_t
{
  TF_TRACE_STEP       = 0x0001,
  TF_TRACE_INSN       = 0x0002,
  TF_TRACE_BBLOCK     = 0x0004,
  TF_TRACE_ROUTINE    = 0x0008,
  TF_REGISTERS        = 0x0010,
  TF_LOG_RET          = 0x0020,
  TF_TRACE_EVERYTHING = 0x0040,
  TF_ONLY_NEW_ISNS    = 0x0080,
  TF_LOGGING          = 0x0100,
  TF_SET_TRACE_SEGS   = 0x0200,
};

struct mem_interval_t
{
  uint64 startea;
  uint64 endea;
};

typedef qvector<mem_interval_t> mem_intervals_t;

struct idalimits_packet_t
{
  // name (and possibly path) of the image to trace, '\0' if we want to
  // trace everything (library calls, etc...)
  char image_name[MAXSTR];
  // maximum number of tevs to enqueue
  uint32 trace_limit;
  // bytes of memory to save if enabled
  pin_size_t bytes;
  // only record new instructions?
  bool only_new;
};

enum pin_regid_t
{
  // segment registers
  PINREG_FIRST_INTREG,
  PINREG_FIRST_SEGREG = PINREG_FIRST_INTREG,
  PINREG_CS = PINREG_FIRST_SEGREG,
  PINREG_DS,
  PINREG_ES,
  PINREG_FS,
  PINREG_GS,
  PINREG_SS,
  PINREG_LAST_SEGREG = PINREG_SS,
  // general registers
  PINREG_FIRST_GPREG,
  PINREG_EAX = PINREG_FIRST_GPREG,
  PINREG_EBX,
  PINREG_ECX,
  PINREG_EDX,
  PINREG_ESI,
  PINREG_EDI,
  PINREG_EBP,
  PINREG_ESP,
  PINREG_EIP,
  PINREG_EFLAGS,
  PINREG_LAST_REG32 = PINREG_EFLAGS,
#ifdef PIN_64
  PINREG64_R8,
  PINREG64_R9,
  PINREG64_R10,
  PINREG64_R11,
  PINREG64_R12,
  PINREG64_R13,
  PINREG64_R14,
  PINREG64_R15,
  PINREG_LAST_GPREG = PINREG64_R15,
#else
  PINREG_LAST_GPREG = PINREG_LAST_REG32,
#endif
  PINREG_LAST_INTREG = PINREG_LAST_GPREG,
  // mmx registers
  PINREG_LAST_REG64 = PINREG_LAST_INTREG,
  // FPU registers
  PINREG_FIRST_REG128,
  PINREG_FIRST_FPREG = PINREG_FIRST_REG128,
  PINREG_ST0 = PINREG_FIRST_FPREG,
  PINREG_ST1,
  PINREG_ST2,
  PINREG_ST3,
  PINREG_ST4,
  PINREG_ST5,
  PINREG_ST6,
  PINREG_ST7,
  PINREG_CTRL,
  PINREG_STAT,
  PINREG_TAGS,
  PINREG_LAST_FPREG = PINREG_TAGS,
  // xmm registers
  PINREG_FIRST_XMMREG,
  PINREG_MXCSR = PINREG_FIRST_XMMREG,
  PINREG_XMM0,
  PINREG_XMM1,
  PINREG_XMM2,
  PINREG_XMM3,
  PINREG_XMM4,
  PINREG_XMM5,
  PINREG_XMM6,
  PINREG_XMM7,
#ifdef PIN_64
  PINREG_XMM8,
  PINREG_XMM9,
  PINREG_XMM10,
  PINREG_XMM11,
  PINREG_XMM12,
  PINREG_XMM13,
  PINREG_XMM14,
  PINREG_XMM15,
  PINREG_LAST_XMMREG = PINREG_XMM15,
#else
  PINREG_LAST_XMMREG = PINREG_XMM7,
#endif
  PINREG_LAST_REG128 = PINREG_LAST_XMMREG,

  // MMX registers: used only for write_registers()
  PINREG_MMX0,
  PINREG_MMX1,
  PINREG_MMX2,
  PINREG_MMX3,
  PINREG_MMX4,
  PINREG_MMX5,
  PINREG_MMX6,
  PINREG_MMX7,

  PINREG_MAX
};

//--------------------------------------------------------------------------
inline int max_regsize(pin_regid_t regind)
{
  if ( (regind >= PINREG_FIRST_INTREG && regind <= PINREG_LAST_REG64)
    || (regind >= PINREG_MMX0 && regind <= PINREG_MMX7) )
  {
    return 8;
  }
  if ( regind >= PINREG_FIRST_REG128 && regind <= PINREG_LAST_REG128 )
    return 16;
  return 0;     // bad regnum
}

//--------------------------------------------------------------------------
enum pin_register_class_t
{
  PIN_RC_GENERAL          = 0x01,
  PIN_RC_SEGMENTS         = 0x02,
  PIN_RC_FPU              = 0x04,
  PIN_RC_XMM              = 0x10,
  PIN_RC_NCLASSES         = 4,       // number of register classes
};

//--------------------------------------------------------------------------
inline int regsize_by_class(pin_register_class_t cls)
{
  switch ( cls )
  {
    case PIN_RC_GENERAL:
    case PIN_RC_SEGMENTS:
      return 8;
    case PIN_RC_FPU:
    case PIN_RC_XMM:
      return 16;
    default:
      return 0;   // bad class
  }
}

//--------------------------------------------------------------------------
inline const char *regclass_name(pin_register_class_t cls)
{
  switch ( cls )
  {
    case PIN_RC_GENERAL:  return "RC_GENERAL";
    case PIN_RC_SEGMENTS: return "RC_SEGMENTS";
    case PIN_RC_FPU:      return "RC_FPU";
    case PIN_RC_XMM:      return "RC_XMM";
    default:              return "RC_UNKNOWN";
  }
}

//--------------------------------------------------------------------------
#define NUMBER_OF_REGS_64   int(PINREG_LAST_REG64  - PINREG_FIRST_INTREG)
#define NUMBER_OF_REGS_128  int(PINREG_LAST_REG128 - PINREG_FIRST_REG128)

//--------------------------------------------------------------------------
typedef unsigned char pin_value64_t[8];
typedef unsigned char pin_value128_t[16];

typedef union
{
  pin_value64_t v64;
  pin_value128_t v128;
} pin_value_t;

class pin_classregs_t
{
public:
  pin_classregs_t(pin_register_class_t cls)  { init(cls); }
  pin_classregs_t()                          { init(PIN_RC_GENERAL); }
  inline pin_regid_t first() const           { return firstreg; }
  inline pin_regid_t last() const            { return lastreg; }
  inline int count() const                   { return lastreg - firstreg + 1; }
  inline size_t itemsize() const             { return valsize; }
  inline size_t size() const                 { return itemsize() * count(); }
  inline void setbuf(void *pv)               { pvals = (rvals_t *)pv; }

  inline bool init(pin_register_class_t cls, bool is_32 = false);

  inline const pin_value_t &operator[](pin_regid_t regno) const
                                             { return *at(regno); }
  inline pin_value_t &operator[](pin_regid_t regno)
                                             { return *at(regno); }
  inline const pin_value_t *at(pin_regid_t regno) const;
  inline       pin_value_t *at(pin_regid_t regno);

private:
  typedef union
  {
    pin_value64_t vals64[NUMBER_OF_REGS_64];
    pin_value128_t vals128[NUMBER_OF_REGS_128];
  } rvals_t;
  rvals_t *pvals;
  pin_regid_t firstreg;
  pin_regid_t lastreg;
  size_t valsize;
  inline bool init(pin_regid_t first, pin_regid_t last);
  inline size_t idx(pin_regid_t regno) const     { return regno - first(); }
};

//--------------------------------------------------------------------------
inline bool pin_classregs_t::init(pin_register_class_t cls, bool is_32bit)
{
#ifndef PIN_64
  is_32bit = true;
#endif
  pin_regid_t firstnum;
  pin_regid_t lastnum;
  switch ( cls )
  {
    case PIN_RC_GENERAL:
      firstnum = PINREG_FIRST_GPREG;
      lastnum = is_32bit ? PINREG_LAST_REG32 : PINREG_LAST_GPREG;
      break;
    case PIN_RC_SEGMENTS:
      firstnum = PINREG_FIRST_SEGREG;
      lastnum = PINREG_LAST_SEGREG;
      break;
    case PIN_RC_FPU:
      firstnum = PINREG_FIRST_FPREG;
      lastnum = PINREG_LAST_FPREG;
      break;
    case PIN_RC_XMM:
      firstnum = PINREG_FIRST_XMMREG;
      lastnum = is_32bit ? PINREG_XMM7 : PINREG_LAST_XMMREG;
      break;
    default:
      return false;   // bad class
  }
  return init(firstnum, lastnum);
}

//--------------------------------------------------------------------------
inline bool pin_classregs_t::init(pin_regid_t firstnum, pin_regid_t lastnum)
{
  firstreg = firstnum;
  lastreg = lastnum;
  size_t s1 = max_regsize(firstnum);
  size_t s2 = max_regsize(lastnum);
  valsize = s1 > s2 ? s1 : s2;
  pvals = NULL;
  return true;
}

//--------------------------------------------------------------------------
class pin_regbuf_t
{
public:
  pin_regbuf_t(int clsmask, bool is_32bit = false)
    : ncls(0), bufsize(0)                           { init(clsmask, is_32bit); }
  size_t get_bufsize() const                        { return bufsize; }
  inline int nclasses() const                       { return ncls; }
  pin_classregs_t *get_class(int i)                 { return &clregs[i]; }
  const pin_classregs_t *get_class(int i) const     { return &clregs[i]; }
  pin_register_class_t get_classid(int i) const     { return classes[i]; }
  inline void setbuf(char *buf);

private:
  int ncls;
  size_t bufsize;
  pin_register_class_t classes[PIN_RC_NCLASSES];
  pin_classregs_t clregs[PIN_RC_NCLASSES];
  void init(int clsmask, bool is_32bit = false);
};

//--------------------------------------------------------------------------
inline void pin_regbuf_t::init(int clsmask, bool is_32bit)
{
#ifndef PIN_64
  is_32bit = true;
#endif
  static pin_register_class_t all_cls[] =
    { PIN_RC_GENERAL, PIN_RC_SEGMENTS, PIN_RC_FPU, PIN_RC_XMM };
  for ( size_t i = 0; i < sizeof(all_cls) / sizeof(all_cls[0]); ++i )
  {
    if ( (clsmask & all_cls[i]) != 0 )
    {
      classes[ncls] = all_cls[i];
      clregs[ncls].init(classes[ncls], is_32bit);
      bufsize += clregs[ncls].size();
      ++ncls;
    }
  }
}

//--------------------------------------------------------------------------
inline void pin_regbuf_t::setbuf(char *buf)
{
  for ( int i = 0; i < ncls; ++i )
  {
    clregs[i].setbuf(buf);
    buf += clregs[i].size();
  }
}

//--------------------------------------------------------------------------
inline const pin_value_t *pin_classregs_t::at(pin_regid_t regno) const
{
  if ( pvals == NULL )
    return NULL;
  return valsize == 8
       ? (const pin_value_t *)&pvals->vals64[idx(regno)]
       : (const pin_value_t *)&pvals->vals128[idx(regno)];
}

//--------------------------------------------------------------------------
inline pin_value_t *pin_classregs_t::at(pin_regid_t regno)
{
  if ( pvals == NULL )
    return NULL;
  return valsize == 8
       ? (pin_value_t *)&pvals->vals64[idx(regno)]
       : (pin_value_t *)&pvals->vals128[idx(regno)];
}

//--------------------------------------------------------------------------
struct pin_regval_t
{
  uint32 regidx;          // pin_regid_t
  char regval[16];        // value
};

//--------------------------------------------------------------------------
struct idapin_regvals_packet_t: idapin_packet_t
{
  idapin_regvals_packet_t(): idapin_packet_t(PTT_CHANGE_REGVALS) {}
  int count() const           { return size; }     // number of registers
  void set_count(int cnt)     { size = cnt;  }
  pin_thid tid() const        { return data; }     // thread_id
  void set_tid(pin_thid thid) { data = thid; }     // thread_id
};

//--------------------------------------------------------------------------
struct idapin_readregs_answer_t: idapin_packet_t
{
  inline idapin_readregs_answer_t(int bufsz = 0, int clmask = 0);
  int bufsize() const         { return size; }     // buffer size
  void set_bufsize(int sz)    { size = sz;   }
  int clmask() const          { return data; }     // output register classes
  void set_clmask(int cls)    { data = cls;  }     // (pin_register_class_t)+
};

inline idapin_readregs_answer_t::idapin_readregs_answer_t(int bufsz, int cls)
  : idapin_packet_t(PTT_ACK)
{
  set_bufsize(bufsz);
  set_clmask(cls);
}

//--------------------------------------------------------------------------
struct idapin_segbase_packet_t: idapin_packet_t
{
  inline idapin_segbase_packet_t(): idapin_packet_t(PTT_GET_SEGBASE) {}
  int tid() const               { return size; }     // thread id
  void set_tid(int thid)        { size = thid; }
  int value() const             { return data; }     // register/base value
  void set_value(int val)       { data = val;  }
};

//--------------------------------------------------------------------------
// symbol address & name in serialized buffer
struct pin_symdef_t
{
  pin_symdef_t()                         {}
  pin_symdef_t(qstring &sname, ea_t sea) { set(sname, sea); }
  ea_t ea() const                        { return *(uint64 *)buf(); }
  int size() const                       { return array.size(); }
  const unsigned char *name() const      { return buf() + sizeof(uint64); }
  unsigned char *name()                  { return buf() + sizeof(uint64); }
  // PIN's stlport does not have data()
#if defined(IDA_SDK_VERSION) || PIN_BUILD_NUMBER >= 76991
  const unsigned char *buf() const       { return array.begin(); }
  unsigned char *buf()                   { return array.begin(); }
#else
  const unsigned char *buf() const       { return array.data(); }
  unsigned char *buf()                   { return array.data(); }
#endif
  inline void set(const qstring &sname, ea_t sea);
  inline char *store(char *buffer) const;
  static inline const char *restore(const char *buffer, const char **sname, ea_t *sea);
private:
  qvector<unsigned char> array;
};

//--------------------------------------------------------------------------
inline void pin_symdef_t::set(const qstring &sname, ea_t sea)
{
  int ssize = sname.size();
  array.resize(sizeof(uint64) + ssize + 1);
  *(uint64 *)buf() = sea;
  memcpy(name(), sname.c_str(), ssize);
  array[ssize+sizeof(uint64)] = '\0';
}

//--------------------------------------------------------------------------
inline char *pin_symdef_t::store(char *buffer) const
{
  memcpy(buffer, buf(), size());
  return buffer + size();
}

//--------------------------------------------------------------------------
inline const char *pin_symdef_t::restore(const char *buffer, const char **sname, ea_t *sea)
{
  *sea = *(uint64 *)buffer;
  buffer += sizeof(uint64);
  *sname = buffer;
  return strchr(buffer, '\0') + 1;
}

#pragma pack(pop)

#endif
