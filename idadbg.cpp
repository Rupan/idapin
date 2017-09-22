/*

    IDA trace: PIN tool to communicate with IDA's debugger

*/

#ifdef __LINT__
// manualy include PIN-specific types in case of LINT
#include "crt/include/types.h"
#endif

//lint +linebuf
//lint -e1075  Ambiguous reference to symbol
#include <pin.H>
//lint +e1075

#include "idadbg.h"
#include "idadbg_local.h"
#include <time.h>

//--------------------------------------------------------------------------
// PIN build 71313 can not load WinSock library
#if defined(_WIN32) && PIN_BUILD_NUMBER == 71313
# error "IDA does not support PIN build #71313. Please use #65163 instead"
#endif

#if PIN_BUILD_NUMBER >= 76991
#ifndef _WIN32
#include <sys/syscall.h>
#endif

// Since build 76991 PIN does not have PIN_IsProcessExiting, Get/ReleaseVmLock
#define PIN_IsProcessExiting() process_exiting()
#define GetVmLock()
#define ReleaseVmLock()
#define PIN_SetExiting()       (process_state = APP_STATE_EXITING)
#elif !defined(_WIN32)
#define PIN_SetExiting()
#endif

//--------------------------------------------------------------------------
// By default we use a separate internal thread for reinstrumentation
// (PIN_RemoveInstrumentation) as there is a a danger of deadlock
// when calling it from listener thread while an application thread is
// waiting on the semaphore.
// There is another issue: breakpoints, thread suspends, pausing and
// waiting for resume on events are implemented by stopping all application
// threads from a separate thread 'suspender'. Suspending on EXCEPTION events
// is implemented by waiting on semaphore in the corresponding callbacks and
// analysis routines. In this case all threads are considered to be
// suspended when an event has been emited and application semaphore cleared:
// we assume that soon thereafter each running thread will be suspended
// on the semaphore inside one of analysis routines. But some threads may be
// waiting somewhere else (system calls and so on). For such threads we can't
// provide the client correct registers as we don't have valid thread contexts
// stored for them.
// For all threads stopped by suspender we can provide valid contexts.
#define SEPARATE_THREAD_FOR_REINSTR

//--------------------------------------------------------------------------
// Command line switches
KNOB<int> knob_ida_port(
        KNOB_MODE_WRITEONCE,
        "pintool",
        "p",
        "23946",
        "Port where IDA Pro is listening for incoming PIN tool's connections");

KNOB<int> knob_connect_timeout(
        KNOB_MODE_WRITEONCE,
        "pintool",
        "T",
        "0",
        "How many seconds wait for client connection (in seconds, 0 - wait for forever)");

KNOB<int> knob_debug_mode(
        KNOB_MODE_WRITEONCE,
        "pintool",
        "idadbg",
        "0",
        "Debug mode");

//--------------------------------------------------------------------------
int pin_client_version;       // client version (from 'HELLO' packet)

//--------------------------------------------------------------------------
// IDA listener (runs in a separate thread)
static VOID ida_pin_listener(VOID *);
// sockets
static PIN_SOCKET srv_socket, cli_socket;
// internal thread identifier
static PIN_THREAD_UID listener_uid;
// this lock prevents listener thread to start serving of requests
static PIN_LOCK start_listener_lock;
// flag: has internal listener thread really started?
static bool listener_ready = false;
// this lock protects 'listener_ready' flag: a thread should acquire it
// when is going to communicate with IDA
static PIN_LOCK listener_ready_lock;

//--------------------------------------------------------------------------
// Handle IDA requests
static bool handle_packets(int total, pin_event_id_t until_ev = NO_EVENT);
static bool read_handle_packet(idapin_packet_t *res = NULL);
static bool handle_packet(const idapin_packet_t *res);
static const char *last_packet = "NONE";      // for debug purposes
// We use this function to communicate with IDA synchronously
// while the listener thread is not active
static bool serve_sync(void);

//--------------------------------------------------------------------------
inline void get_context_regs(const CONTEXT *ctx, idapin_registers_t *regs);
inline void get_phys_context_regs(const PHYSICAL_CONTEXT *ctx, idapin_registers_t *regs);

inline const char *regname_by_idx(pin_regid_t pintool_reg);
inline REG regidx_pintool2pin(pin_regid_t pintool_reg);

//--------------------------------------------------------------------------
// application process state
enum process_state_t
{
  APP_STATE_NONE,          // not started yet -> don't report any event
                           // until the PROCESS_START packet is added
                           // to the events queue
  APP_STATE_RUNNING,       // process thread is running
  APP_STATE_PAUSE,         // pause request received
  APP_STATE_SUSPENDED,     // process suspended - wait for resume
  APP_STATE_WAIT_FLUSH,    // process suspended due to tracebuf is full
  APP_STATE_EXITING,       // process thread is exiting
  APP_STATE_EXITED,        // process exited
  APP_STATE_DETACHED,      // detached
};

// global process state variable and lock for it
static process_state_t process_state = APP_STATE_NONE;
static PIN_LOCK process_state_lock;

//--------------------------------------------------------------------------
struct pin_local_event_t
{
  pin_local_event_t(uint32 evid = NO_EVENT,
                    THREADID ltid = INVALID_THREADID, uint64 addr = BADADDR)
    : debev(evid, addr), tid_local(ltid)
  {
  }
                          // The following fields must be filled for all events:
  pin_debug_event_t debev;
  THREADID tid_local;          // local thread id
};

//--------------------------------------------------------------------------
// break at the very next instruction?
static bool break_at_next_inst = false;

// semaphore used for pausing the whole application
static PIN_SEMAPHORE run_app_sem;

// main thread id: we don't emit THREAD_START event for it
// as IDA registers main thread when handles PROCESS_START event
static THREADID main_thread = INVALID_THREADID;
static bool main_thread_started = false;

// PROCESS_START event prepared by app_start_cb
static pin_local_event_t start_ev;

//--------------------------------------------------------------------------
// thread-local data
class thread_data_t
{
public:
  // to get PIN_StopApplicationThreads() chance to catch safe points
  // we periodically call ExecuteAt() from analysis routines.
  // the following type denotes whether restart is requested and
  // where restart has been issued from (if it has)
  enum restart_mode_t
  {
    RESTART_REQ         = 0x01,        // restart is requested
    RESTART_FROM_CTRL   = 0x02,        // restarted from do_ctrl
    RESTART_FROM_BPT    = 0x04,        // restarted from do_bpt
  };
  inline thread_data_t();
  ~thread_data_t();

  bool is_started() const              { return started; }
  inline void set_started();
  inline void set_finished() const;
  bool ctx_ok() const                  { return ctx != NULL; }
  CONTEXT *get_ctx()                   { create_ctx(); return ctx; }
  bool is_phys_ctx() const             { return is_phys; }
  bool is_ctx_changed() const          { return ctx_changed; }
  bool is_ctx_valid() const            { return ctx_valid; }
  void discard_ctx()                   { ctx_valid = false; }
  inline void suspend();
  inline void wait();
  inline void resume();
  inline void set_excp_handled(bool val);

  bool suspended() const               { return susp; }
  bool excp_handled() const            { return ev_handled; }
  inline pin_thid get_ext_tid() const  { return ext_tid; }

  inline bool save_curr_thread_ctx(const CONTEXT *src_ctx);
  inline void save_ctx(const CONTEXT *src_ctx, bool can_change = true);
  inline void save_phys_ctx(const PHYSICAL_CONTEXT *phys_ctx);
  inline void set_ctx_reg(REG pinreg, ADDRINT regval);
  inline void export_ctx(idapin_registers_t *regs);
  inline bool change_regval(REG regno, const UINT8 *regval);
  inline void continue_execution(int restarted_from);
  inline bool can_break(ADDRINT addr) const;
  int available_regs(int clsmask) const;

  inline bool add_thread_areas(pin_meminfo_vec_t *miv);

  static inline int n_active_threads();
  static inline bool have_suspended_threads();
  static inline bool all_threads_suspended();
  void set_restart_ea(ADDRINT ea)      { restarted_at = ea; }
  inline void set_restart_ctx(const CONTEXT *context);

  static inline thread_data_t *get_thread_data();
  static inline thread_data_t *get_thread_data(THREADID tid);
  static thread_data_t *find_thread_data(THREADID tid, bool create = false);
  static inline bool release_thread_data(THREADID tid);

  static inline THREADID get_thread_id();
  static inline pin_thid get_ext_thread_id(THREADID locat_tid);
  static inline THREADID get_local_thread_id(pin_thid tid_ext);
  static inline void restart_threads_for_suspend();
  static inline void resume_threads_after_suspend();
  static inline bool has_stoppable_threads();

  static inline thread_data_t *get_any_stopped_thread(THREADID *tid);

  static inline bool is_meminfo_changed();
  static inline void set_meminfo_changed(bool val);

  static inline void add_all_thread_areas(pin_meminfo_vec_t *miv);

  static inline ssize_t read_memory(void *dst, ADDRINT ea, size_t size);
  static inline ssize_t write_memory(ADDRINT ea, const void *src, size_t size);

private:
  void create_ctx()                    { if ( !ctx_ok() ) ctx = new CONTEXT; }
  inline void try_init_ext_tid(THREADID locat_tid);
  inline void set_ext_tid(THREADID locat_tid, pin_thid tid);
  inline void save_ctx_nolock(const CONTEXT *src_ctx, bool can_change = true);
  inline void restart_for_suspend();
  inline void resume_after_suspend();
  inline void reexecute_thread(restart_mode_t restart_bit);

#ifdef _WIN32
  void *tibbase;
  WINDOWS::_NT_TIB nt_tib;
  ADDRINT stack_top() const            { return ADDRINT(nt_tib.StackBase); }
  ADDRINT stack_bottom() const         { return ADDRINT(nt_tib.StackLimit); }
  ADDRINT tibstart() const             { return ADDRINT(tibbase); }
  ADDRINT tibend() const               { return tibstart() + sizeof(nt_tib); }
  inline void read_tibmem(char *dst, ADDRINT ea, size_t size) const;
#endif
  CONTEXT *ctx;
  ADDRINT restarted_at;
  PIN_SEMAPHORE thr_sem;
  PIN_LOCK ctx_lock;
  pin_thid ext_tid;
  int state_bits;
  bool ctx_valid;
  bool ctx_changed;
  bool can_change_regs;
  bool susp;
  bool ev_handled;         // true if the last exception was hanlded by debugger
  bool started;
  bool is_phys;
  bool is_stoppable;             // can be stopped by PIN_StopApplicationThreads
  static int thread_cnt;         // number of thread_data_t objects
  static int active_threads_cnt; // number of active threads
  static int suspeded_cnt;
  typedef std::map <THREADID, thread_data_t *> thrdata_map_t;
  static thrdata_map_t thr_data;
  static std::map <pin_thid, THREADID> local_tids;
  static PIN_LOCK thr_data_lock;
  static bool thr_data_lock_inited;
  static PIN_LOCK meminfo_lock;
  static bool meminfo_changed;
};

//--------------------------------------------------------------------------
typedef std::deque<pin_local_event_t> event_list_t;

//--------------------------------------------------------------------------
// Event queue
//-V:ev_queue_t:730 Not all members of a class are initialized inside the constructor: lock
class ev_queue_t
{
public:
  ev_queue_t();
  ~ev_queue_t();
  //lint -sem(ev_queue_t::init,initializer)
  void init();
  inline void push_back(const pin_local_event_t &ev);
  inline void push_front(const pin_local_event_t &ev);
  inline void add_ev(const pin_local_event_t &ev, bool front);
  inline bool pop_front(pin_local_event_t *out_ev, bool *can_resume);
  inline bool back(pin_local_event_t *out_ev);
  inline size_t size();
  inline bool empty();
  inline void last_ev(pin_local_event_t *out_ev);
  bool send_event(bool *can_resume);
  inline bool can_send_event() const;
  inline void add_symbol(const std::string &name, ea_t ea);
  inline char *export_symbols(int *bufsize);  // return value should be freed

private:
  event_list_t queue;
  PIN_LOCK lock;
  pin_local_event_t last_retrieved_ev;
  std::vector<pin_symdef_t> symbols;
  int sym_size;
};

//--------------------------------------------------------------------------
// Manager of breakpoints, pausing, stepping, thread susending
//-V:bpt_mgr_t:730 Not all members of a class are initialized inside the constructor: bpt_lock
class bpt_mgr_t
{
public:
  bpt_mgr_t();
  ~bpt_mgr_t();
  //lint -sem(bpt_mgr_t::cleanup,initializer)
  inline void cleanup();

  // return values: true - bpt really added/removed, false - else
  inline void add_soft_bpt(ADDRINT at);
  inline void del_soft_bpt(ADDRINT at);

  // have bpt at given address?
  inline bool have_bpt_at(ADDRINT addr);

  // set stepping thread ID
  inline void set_step(THREADID stepping_tid);

  // inform bpt_mgr that we are about to suspend/resume
  // return value:
  //   true - need reinstrumentation
  inline bool prepare_resume();
  inline void prepare_suspend();

  // instrumentation callback: add analysis routines
  inline void add_rtns(INS ins, ADDRINT ins_addr);

  // IfCall callback for ctrl_rtn (should be inlined by PIN; run tool  with
  // -log_inline command line option to check what routines PIN really inlines)
  static ADDRINT ctrl_rtn_enabled();

  bool need_control_cb() const;
  inline void update_ctrl_flag() const;

private:
  enum ev_id_t
  {
    EV_PAUSED       = 0,
    EV_SINGLE_STEP  = 1,
    EV_BPT          = 2,
    EV_INITIAL_STOP = 3,
    EV_NO_EVENT     = 4
  };
  typedef std::set<ADDRINT> addrset_t;

  inline bool have_bpt_at_nolock(ADDRINT addr);

  // analysis routines
  static void PIN_FAST_ANALYSIS_CALL bpt_rtn(ADDRINT addr, const CONTEXT *ctx);
  static void PIN_FAST_ANALYSIS_CALL ctrl_rtn(ADDRINT addr, const CONTEXT *ctx);

  inline void do_bpt(ADDRINT addr, const CONTEXT *ctx);
  inline void do_ctrl(ADDRINT addr, const CONTEXT *ctx);
  void emit_event(ev_id_t eid, ADDRINT addr, THREADID tid);

  static bool control_enabled;

  addrset_t bpts;
  // Sometimes PIN starts reinstrumenting not immediately but after some period.
  // So during this period we keep newly added bpts in the special set
  // (pending_bpts) and handle them in ctrl_rtn until we detect
  // reinstrumentation really started. Note that using ctrl_rtn for breakpoints
  // can dramatically slow down the execution so we will try to get rid
  // of such pending breakpoints as soon as possible
  addrset_t pending_bpts;
  // this lock controls access to breakpoints
  PIN_LOCK bpt_lock;
  // thread ID of the last dbg_set_resume_mode request
  THREADID stepping_thread;
  // true if we need to reinstrument just after resume
  bool need_reinst;
};

//--------------------------------------------------------------------------
// Application suspender (runs in a separate thread)
// This thread waits on the semaphore and tries to suspend the application
// with PIN_StopApplicationThreads if the application should be paused
class suspender_t
{
public:
  suspender_t();
  bool start();
  bool finish();
  bool wait_termination();

  inline void stop_threads(const pin_local_event_t &ev);
  inline void pause_threads();
  bool resume_threads();
  inline void copy_pending_events(THREADID curr_tid = INVALID_THREADID);
  inline void wakeup();

private:
  enum state_t
  {
    IDLE,
    RUNNING,
    STOPPING,
    PAUSING,
    STOPPED,
    RESUMING,
    EXITING,
  };
  void copy_pending_events_nolock(THREADID curr_tid);
  void suspend_threads(state_t new_susp_state, const pin_local_event_t &ev);
  inline void add_pending_event(const pin_local_event_t &ev);
  void thread_worker();
  static VOID thread_hnd(VOID *ud);
  inline bool can_stop_app_threads() const;

  event_list_t pending_events;
  PIN_LOCK lock;
  PIN_SEMAPHORE sem;
  PIN_THREAD_UID thread_uid;
  std::vector<CONTEXT *> contexts;
  process_state_t next_process_state;
  state_t state;
};

//--------------------------------------------------------------------------
// This class implements analysis routines, instrumentation callbacks,
// init/update instrumentation according to client's requests
class instrumenter_t
{
public:
  static bool init();
  static bool finish();
  static bool wait_termination();
  static void init_instrumentations();
  static void update_instrumentation(uint32 trace_types);
  static inline void reinit_instrumentations();
  static inline void remove_instrumentations();
  static inline void resume();

  static inline size_t tracebuf_size();
  static inline bool tracebuf_is_full();
  static inline void clear_trace();
  static int get_trace_events(idatrace_events_t *out_trc_events);
  static bool set_limits(bool only_new, uint32 enq_size, const char *imgname);
  static void process_image(const IMG &img, bool as_default);
  static inline void add_trace_intervals(int cnt, const mem_interval_t *ivs);
  static inline bool write_regs(pin_thid tid, int cnt, const pin_regval_t *values);

  enum instr_state_t
  {
    INSTR_STATE_INITIAL,
    INSTR_STATE_NEED_REINIT,
    INSTR_STATE_REINIT_STARTED,
    INSTR_STATE_OK,
  };
  static inline bool instr_state_ok();

private:
  static void add_instrumentation(trace_flags_t inst);

  // logic IF-routines (should be inlined by PIN; run tool with -log_inline
  // command line option to check what routines PIN does really inline)
  static ADDRINT ins_enabled(VOID *);
  static ADDRINT trc_enabled(VOID *);
  static ADDRINT rtn_enabled(VOID *);

  // logic THEN-routines
  static VOID PIN_FAST_ANALYSIS_CALL ins_logic_cb(
        const CONTEXT *ctx,
        VOID *ip,
        pin_tev_type_t tev_type);
  static VOID PIN_FAST_ANALYSIS_CALL rtn_logic_cb(
        ADDRINT ins_ip,
        ADDRINT target_ip,
        BOOL is_indirect,
        BOOL is_ret);
  static inline void store_trace_entry(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type);
  static inline void add_to_trace(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type);
  static inline void add_to_trace(ADDRINT ea, pin_tev_type_t tev_type);
  static inline void prepare_and_wait_trace_flush();
  static inline void register_recorded_insn(ADDRINT addr);
  static inline bool insn_is_registered(ADDRINT addr);
  static inline bool check_address(ADDRINT addr);
  static inline bool check_address(ADDRINT addr, pin_tev_type_t type);
  static inline bool addrok(ADDRINT ea);// does addr belong to set of intervals?
  static inline void add_interval(ADDRINT start, ADDRINT end);

  // instrumentation callbacks: insert logic routines
  static VOID instruction_cb(INS ins, VOID *);
  static VOID trace_cb(TRACE trace, VOID *);
  static VOID routine_cb(TRACE trace, VOID *);
  static bool add_bbl_logic_cb(INS ins, bool first);
  static bool add_rtn_logic_cb(INS ins);

  static uint32 curr_trace_types();

  // recorded instructions
  typedef std::deque<trc_element_t> trc_deque_t;
  static PIN_LOCK tracebuf_lock;
  static trc_deque_t trace_addrs;
  // semaphore used for pausing when trace buffer is full
  static PIN_SEMAPHORE tracebuf_sem;

  // Already recorded instructions, those should be skipped if
  // only_new_instructions flag is true.
  // NOTE: as we have limited memory in the PIN tool we cannot let it grow
  // without limit, we need to remember a maximum number of "skip_limit"
  // element(s), or the PIN tool would die because it runs out of memory
  typedef std::deque<ADDRINT> addr_deque_t;
  static addr_deque_t all_addrs;
  // only record new instructions?
  static bool only_new_instructions;
  // acceptable intervals: if excluding debugger segments and/or library functions
  struct intv_t
  {
    intv_t(ADDRINT s = BADADDR, ADDRINT e = BADADDR): start(s), end(e) {}
    ADDRINT start;
    ADDRINT end;
  };
  typedef std::vector<intv_t> intvlist_t;
  struct ea_checker_t
  {
    intvlist_t intervals;
    intvlist_t::const_iterator curr_iv;
    bool trace_everything; // do not limit tracing addrs by segments/libs
  };
  static ea_checker_t ea_checker;

  // max trace buffer size (max number of events in the buffer)
  static uint32 enqueue_limit;
  // remember only the last 1 million instructions
  static const uint32 skip_limit;
  // name of the image to trace
  static string image_name;

  static instr_state_t state;

  // trace mode switches
  static bool tracing_instruction;
  static bool tracing_bblock;
  static bool tracing_routine;
  static bool tracing_registers;
  static bool log_ret_isns;

  static uchar instrumentations;

#ifdef SEPARATE_THREAD_FOR_REINSTR
  static VOID reinstrumenter(VOID *);
  static bool reinstr_started;
  static PIN_SEMAPHORE reinstr_sem;
  static PIN_THREAD_UID reinstr_uid;
#endif
};

//--------------------------------------------------------------------------
// Logging/debug
static int debug_level = 0;

//#debug MUTEX_DEBUG

/*
#ifdef MUTEX_DEBUG
//--------------------------------------------------------------------------
class dbg_janitor_for_pinlock_t: public janitor_for_pinlock_t
{
protected:
  const char *lname;
  int lline;
public:
  dbg_janitor_for_pinlock_t(int line, const char *name, PIN_LOCK *lock)
    : janitor_for_pinlock_t(lock), lname(name), lline(line)
  {
    MSG("LOCK %s at %d\n", name, line);
  }
  ~dbg_janitor_for_pinlock_t()
  {
    MSG("UNLOCK %s/%d\n", lname, lline);
  }
};
#define MUTEX_GUARD(n, x) dbg_janitor_for_pinlock_t n(__LINE__, #x, &x)
#else
#define MUTEX_GUARD(n, x) janitor_for_pinlock_t n(&x)
#endif
*/

//--------------------------------------------------------------------------
// Avoid a possible bug in PIN 76991: suspender calls PIN_StopApplicationThreads()
// and then PIN_GetStoppedThreadId which can crash If between these calls a new thread
// is created. We introduce a thread counter and do not call PIN_GetStoppedThreadId -
// just resume threads instead. In this case we know for sure that the last
// thread start/finish callback incremented 'thr_age' also issued suspend request
// which should cause one more suspender iteration.
// (the bug was revealed by pc_linux_pin_threads64.elf)
static int thr_age = 0;    //lint -e843
inline void inc_thr_age(const char *from)
{
  DEBUG(2, "%s: inc_thr_age -> %d\n", from, thr_age+1);
#ifndef _WIN32
  janitor_for_pinlock_t process_state_guard(&process_state_lock);
  ++thr_age;
#endif
}

//--------------------------------------------------------------------------
// PIN address to void *
inline void *pvoid(ADDRINT addr)
{
  return (void *)addr;
}

//--------------------------------------------------------------------------
// queued events
static ev_queue_t events;

// The folowing object manages bpt/pausing/single step/thread suspend
static bpt_mgr_t breakpoints;

// The folowing object suspends/resumes application threads
static suspender_t suspender;

//--------------------------------------------------------------------------
// the following functions access process state; they don't acquire
// process_state_lock, it MUST be acquired by caller
inline bool process_started()
{
  return process_state != APP_STATE_NONE;
}

//--------------------------------------------------------------------------
inline bool process_exited()
{
  return process_state == APP_STATE_EXITED;
}

//--------------------------------------------------------------------------
inline bool process_exiting()
{
  return process_state == APP_STATE_EXITING || process_exited();
}

//--------------------------------------------------------------------------
inline bool process_detached()
{
  return process_state == APP_STATE_DETACHED;
}

//--------------------------------------------------------------------------
inline bool process_pause()
{
  return process_state == APP_STATE_PAUSE;
}

//--------------------------------------------------------------------------
inline bool process_suspended()
{
  return process_state == APP_STATE_SUSPENDED
      || process_state == APP_STATE_WAIT_FLUSH;
}

//--------------------------------------------------------------------------
inline char *tail(char *in_str) { return strchr(in_str, '\0'); }
inline const char *tail(const char *in_str) { return strchr(in_str, '\0'); }

//--------------------------------------------------------------------------
inline ADDRINT get_ctx_ip(const CONTEXT *ctx)
{
  return ctx == NULL ? BADADDR : (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);
}

//--------------------------------------------------------------------------
inline void get_context_regs(const CONTEXT *ctx, idapin_registers_t *regs)
{
  regs->eax = (ADDRINT)PIN_GetContextReg(ctx, REG_GAX);
  regs->ebx = (ADDRINT)PIN_GetContextReg(ctx, REG_GBX);
  regs->ecx = (ADDRINT)PIN_GetContextReg(ctx, REG_GCX);
  regs->edx = (ADDRINT)PIN_GetContextReg(ctx, REG_GDX);
  regs->esi = (ADDRINT)PIN_GetContextReg(ctx, REG_GSI);
  regs->edi = (ADDRINT)PIN_GetContextReg(ctx, REG_GDI);
  regs->ebp = (ADDRINT)PIN_GetContextReg(ctx, REG_GBP);
  regs->esp = (ADDRINT)PIN_GetContextReg(ctx, REG_STACK_PTR);
  regs->eip = (ADDRINT)PIN_GetContextReg(ctx, REG_INST_PTR);
#if defined(PIN_64)
  regs->r8  = (ADDRINT)PIN_GetContextReg(ctx, REG_R8);
  regs->r9  = (ADDRINT)PIN_GetContextReg(ctx, REG_R9);
  regs->r10 = (ADDRINT)PIN_GetContextReg(ctx, REG_R10);
  regs->r11 = (ADDRINT)PIN_GetContextReg(ctx, REG_R11);
  regs->r12 = (ADDRINT)PIN_GetContextReg(ctx, REG_R12);
  regs->r13 = (ADDRINT)PIN_GetContextReg(ctx, REG_R13);
  regs->r14 = (ADDRINT)PIN_GetContextReg(ctx, REG_R14);
  regs->r15 = (ADDRINT)PIN_GetContextReg(ctx, REG_R15);

  regs->eflags = (ADDRINT)PIN_GetContextReg(ctx, REG_RFLAGS);
#else
  regs->eflags = (ADDRINT)PIN_GetContextReg(ctx, REG_EFLAGS);
#endif
  regs->cs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_CS);
  regs->ds = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_DS);
  regs->es = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_ES);
  regs->fs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_FS);
  regs->gs = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_GS);
  regs->ss = (ADDRINT)PIN_GetContextReg(ctx, REG_SEG_SS);
}

//--------------------------------------------------------------------------
inline void get_phys_context_regs(const PHYSICAL_CONTEXT *ctx, idapin_registers_t *regs)
{
  regs->eax = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GAX);
  regs->ebx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GBX);
  regs->ecx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GCX);
  regs->edx = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GDX);
  regs->esi = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GSI);
  regs->edi = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GDI);
  regs->ebp = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_GBP);
  regs->esp = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_STACK_PTR);
  regs->eip = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_INST_PTR);
#if defined(PIN_64)
  regs->r8  = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R8);
  regs->r9  = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R9);
  regs->r10 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R10);
  regs->r11 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R11);
  regs->r12 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R12);
  regs->r13 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R13);
  regs->r14 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R14);
  regs->r15 = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_R15);

  regs->eflags = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_RFLAGS);
#else
  regs->eflags = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_EFLAGS);
#endif
  regs->cs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_CS);
  regs->ds = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_DS);
  regs->es = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_ES);
  regs->fs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_FS);
  regs->gs = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_GS);
  regs->ss = (ADDRINT)PIN_GetPhysicalContextReg(ctx, REG_SEG_SS);
}

//--------------------------------------------------------------------------
// fill some common fields of event and add it to the queue
inline void enqueue_event(pin_local_event_t &ev)
{
  ev.debev.pid = PIN_GetPid();
  ev.debev.handled = false;
  // put PROCESS_START event into the front of the queue to be sent to IDA
  // before any LIBRARY_LOAD event because IDA needs
  // existing main thread context when suspends execution on LIBRARY_LOAD
  // (in case 'Suspend on library load/unload' option is enabled)
  events.add_ev(ev, ev.debev.eid == PROCESS_START);
}

//--------------------------------------------------------------------------
inline bool pop_debug_event(pin_local_event_t *out_ev, bool *can_resume)
{
  if ( !events.pop_front(out_ev, can_resume) )
    return false;
  if ( out_ev->tid_local != INVALID_THREADID )
  {
    out_ev->debev.tid = thread_data_t::get_ext_thread_id(out_ev->tid_local);
  }
  else if ( out_ev->debev.eid != NO_EVENT )
  {
    thread_data_t *td = thread_data_t::get_any_stopped_thread(&out_ev->tid_local);
    if ( td == NULL )
    {
      MSG("PINtool error: undefined event TID and no stopped thread found\n");
    }
    else
    {
      out_ev->debev.tid = td->get_ext_tid();
      CONTEXT *ctx = td->get_ctx();
      out_ev->debev.ea = get_ctx_ip(ctx);
      DEBUG(2, "pop event->correct tid(%d)/ea(%p)\n", out_ev->debev.tid, pvoid(out_ev->debev.ea));
    }
  }
  if ( thread_data_t::is_meminfo_changed() || out_ev->debev.eid == THREAD_START )
    out_ev->debev.flags |= PIN_DEBEV_REFRESH_MEMINFO;
  return true;
}

//--------------------------------------------------------------------------
// prepare suspend (don't acquire process_state_lock, it must be done by caller)
inline void suspend_on_semaphore(pin_local_event_t &ev)
{
  enqueue_event(ev);
  if ( !process_suspended() )
  {
    sema_clear(&run_app_sem);
    process_state = APP_STATE_SUSPENDED;
    DEBUG(2, "suspend_on_semaphore\n");
    breakpoints.prepare_suspend();
  }
}

//--------------------------------------------------------------------------
// prepare suspend (don't acquire process_state_lock, it must be done by caller)
inline void do_suspend(pin_local_event_t &ev)
{
  if ( !listener_ready )
  {
    suspend_on_semaphore(ev);
    return;
  }
  if ( process_suspended() )
  { // process already suspended - just add event to the queue
    enqueue_event(ev);
  }
  else
  {
    DEBUG(3, "do_suspend\n");
    breakpoints.prepare_suspend();
    suspender.stop_threads(ev);
  }
}

//--------------------------------------------------------------------------
// fill some common fields of event, add it to the queue and suspend process
inline bool suspend_at_event(pin_local_event_t &ev, bool use_sem)
{
  janitor_for_pinlock_t process_state_guard(&process_state_lock);
  if ( !process_detached() && !process_exiting() )
  {
    if ( use_sem )
      suspend_on_semaphore(ev);
    else
      do_suspend(ev);
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
inline bool wait_for_thread_termination(PIN_THREAD_UID tuid)
{
  return PIN_WaitForThreadTermination(tuid, 10000, NULL);
}

//--------------------------------------------------------------------------
// This function is called when the application exits
static VOID fini_cb(INT32 code, VOID *)
{
#ifndef _WIN32
  // generate and send PROCESS_EXIT event
  // (on Windows it was sent earlier by prepare_fini_cb)
  pin_local_event_t evt(PROCESS_EXIT, thread_data_t::get_thread_id());
  evt.debev.exit_code = code;
  enqueue_event(evt);
  PIN_SetExiting();         // terminate listener
#else
  qnotused(code);
#endif
  MSG("Waiting for internal threads to exit...\n");
  instrumenter_t::finish();
  bool ok = suspender.wait_termination();
  if ( !ok )
    MSG("Can not stop suspender thread\n");
  if ( !instrumenter_t::wait_termination() )
  {
    MSG("Can not stop instrumenter thread\n");
    ok = false;
  }
  if ( listener_uid != INVALID_PIN_THREAD_UID
    && !wait_for_thread_termination(listener_uid) )
  {
    MSG("Can not stop listener thread\n");
    ok = false;
  }
  if ( ok )
    DEBUG(2, "FINI: Everything OK\n");
}

#if PIN_BUILD_NUMBER >= 76991
//--------------------------------------------------------------------------
// This function is called when the application exits
static VOID prepare_fini_cb(VOID *)
{
  THREADID thr = thread_data_t::get_thread_id();
  DEBUG(2, "PREPARE_FINI (thread = %d/main=%d)\n", thr, main_thread);
  // THREAD_EXIT, PROCESS_EXIT events should be sent after all other ones -
  // move them from suspender to the listener queue
  suspender.copy_pending_events();
  suspender.finish();
  DEBUG(2, "PREPARE_FINI: Everything OK\n");
  // on Windows ws2_32.dll can be unloaded before fini_cb and main thread's
  // thread_fini_cb, so we can not send events to IDA from them, the better
  // place seems to be here. The problem is we do not have yet correct exit code
  // here - just pass 0.
  // Also we should terminate listener thread and send all remaining events here
#ifdef _WIN32
  // terminate listener and wait for its termination
  PIN_SetExiting();
  for ( int i = 0; i <= RCV_TIMEOUT && listener_uid != INVALID_PIN_THREAD_UID; ++i )
    PIN_Sleep(1);
  // generate artifical THREAD_EXIT and PROCESS_EXIT events
  int fake_code = 0;
  pin_local_event_t exit_thr_ev(THREAD_EXIT, thr);
  exit_thr_ev.debev.exit_code = fake_code;
  enqueue_event(exit_thr_ev);
  pin_local_event_t exit_ev(PROCESS_EXIT, thr);
  exit_ev.debev.exit_code = fake_code;
  enqueue_event(exit_ev);
  // add the last empty event for read_handle_packet to be able to send ACK for
  // the last event (PROCESS_EXIT), otherwise we can hang on Win10
  pin_local_event_t last_empty_ev(NO_EVENT, INVALID_THREADID);
  enqueue_event(last_empty_ev);

  // send remaining events
  while ( !events.empty() )
    if ( !read_handle_packet() )
      break;
#endif
}
#endif

//--------------------------------------------------------------------------
const char *pin_basename(const char *path)
{
  if ( path != NULL )
  {
    const char *f1 = strrchr(path, '/');
    const char *f2 = strrchr(path, '\\');
    const char *file = max(f1, f2);
    if ( file != NULL )
      return file+1;
  }
  return path;
}

//--------------------------------------------------------------------------
// Pin calls this function every time an img is loaded
//lint -e{1746} parameter 'img' could be made const reference
static VOID image_load_cb(IMG img, VOID *)
{
  ADDRINT start_ea = IMG_LowAddress(img);
  ADDRINT end_ea = IMG_HighAddress(img);

#ifdef _WIN32
  // prepare library prefix
  std::string imgbase = pin_basename(IMG_Name(img).c_str());
  transform(imgbase.begin(), imgbase.end(), imgbase.begin(), ::tolower);
  size_t pos = imgbase.find('.');
  if ( pos != std::string::npos )
    imgbase.resize(pos);
  imgbase += '_';
#endif
  int nsyms = 0;
  for ( SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) )
  {
#ifdef _WIN32
    std::string symname = imgbase + SYM_Name(sym);
#else
    std::string symname = SYM_Name(sym);
#endif
    events.add_symbol(symname, SYM_Address(sym));
    ++nsyms;
  }
  MSG("Loading library %s %p:%p, %d symbols\n", IMG_Name(img).c_str(), pvoid(start_ea), pvoid(end_ea), nsyms);

  pin_local_event_t event(LIBRARY_LOAD,
                          thread_data_t::get_thread_id(), IMG_Entry(img));
  pin_debug_event_t &ev = event.debev;
  pin_strncpy(ev.modinfo.name, IMG_Name(img).c_str(), sizeof(ev.modinfo.name));
  ev.modinfo.base = start_ea;
  ev.modinfo.size = (pin_size_t)(end_ea - start_ea);
  ev.modinfo.rebase_to = BADADDR;

  instrumenter_t::process_image(img, false);

  do_suspend(event);
  wait_after_callback();
}

//--------------------------------------------------------------------------
// Pin calls this function every time an img is unloaded
// You can't instrument an image that is about to be unloaded
//lint -e{1746} parameter 'img' could be made const reference
static VOID image_unload_cb(IMG img, VOID *)
{
  pin_local_event_t ev(LIBRARY_UNLOAD);
  pin_strncpy(ev.debev.info, IMG_Name(img).c_str(), sizeof(ev.debev.info));
  enqueue_event(ev);

  MSG("Unloading %s\n", IMG_Name(img).c_str());
}

//--------------------------------------------------------------------------
static void exit_process(int code)
{
  process_state = APP_STATE_EXITING;
  sema_set(&run_app_sem);
  suspender.resume_threads();
  PIN_ExitProcess(code);
}

//--------------------------------------------------------------------------
static void emit_process_start_ev()
{
  start_ev.tid_local = main_thread;
  thread_data_t *tdata = thread_data_t::get_thread_data(main_thread);
  tdata->set_started();
  suspend_at_event(start_ev, true);
  start_ev.debev.eid = NO_EVENT;  // reset event after adding to the queue
  // Handle packets in the main thread until we receive the RESUME request
  // to PROCESS_START event
  // We need this to add breakpoints before the application's code is
  // executed, otherwise, we will run into race conditions
  if ( !handle_packets(-1, PROCESS_START) )
  {
    MSG("Error handling initial requests, exiting...\n");
    exit_process(-1);
  }
  PIN_ReleaseLock(&start_listener_lock); // let listener thread to start serving
}

//--------------------------------------------------------------------------
// This routine is executed every time a thread is created
//lint -e{818} Pointer parameter 'ctx' could be declared as pointing to const
static VOID thread_start_cb(THREADID tid, CONTEXT *ctx, INT32, VOID *)
{
  inc_thr_age("thread_start");
  thread_data_t::set_meminfo_changed(true);

  DEBUG(2, "thread_start_cb(%d/%d)\n", int(tid), int(thread_data_t::get_ext_thread_id(tid)));

  if ( tid != main_thread )
  {
    // don't emit THREAD_START here because we don't have correct thread stack
    // segments here. They should be available in ctrl_rtn (unfortunately not
    // always too) - so that's better place to emit THREAD_START event
    breakpoints.prepare_suspend();
  }
  else
  {
    // do not emit THREAD_START if we are inside main thread:
    // IDA has stored main thread when processed PROCESS_START event
    main_thread_started = true;
    thread_data_t *tdata = thread_data_t::get_thread_data(tid);
    tdata->save_ctx(ctx);
    if ( start_ev.debev.eid != NO_EVENT )
    {
      DEBUG(2, "thread_start: Emit PROCESS_START prepared by app_start_cb\n");
      emit_process_start_ev();
    }
  }
}

//--------------------------------------------------------------------------
// This routine is executed every time a thread is destroyed.
static VOID thread_fini_cb(THREADID tid, const CONTEXT *ctx, INT32 code, VOID *)
{
  inc_thr_age("thread_fini");
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  tdata->save_ctx(ctx);
  thread_data_t::set_meminfo_changed(true);

  pin_local_event_t ev(THREAD_EXIT, tid, get_ctx_ip(ctx));
  ev.debev.exit_code = code;
  tdata->set_finished();
  DEBUG(2, "THREAD FINISH: %d AT %p\n", tid, pvoid(ev.debev.ea));

  if ( suspend_at_event(ev, tid == main_thread) )
    wait_after_callback();
}

//--------------------------------------------------------------------------
static void detach_process()
{
  process_state = APP_STATE_DETACHED;
  sema_set(&run_app_sem);
  suspender.resume_threads();
  PIN_Detach();
}

//--------------------------------------------------------------------------
inline void error_msg(const char *msg)
{
  MSG("%s: %s\n", msg, strerror(errno));
}

#ifdef _WIN32
static int (WSAAPI *p_WSAStartup)(WINDOWS::WORD, WINDOWS::WSADATA *);
static int (WSAAPI *p_WSAGetLastError)(void);
static WINDOWS::SOCKET (WSAAPI *p_socket)(int af, int type, int protocol);
static int (WSAAPI *p_bind)(WINDOWS::SOCKET, const struct WINDOWS::sockaddr *, int );
static int (WSAAPI *p_setsockopt)(WINDOWS::SOCKET, int, int, const char *optval, int optlen);
static int (WSAAPI *p_listen)(WINDOWS::SOCKET s, int backlog);
static WINDOWS::SOCKET (WSAAPI *p_accept)(WINDOWS::SOCKET, struct WINDOWS::sockaddr *, int *);
static int (WSAAPI *p_recv)(WINDOWS::SOCKET s, char *buf, int len, int flags);
static int (WSAAPI *p_send)(WINDOWS::SOCKET s, const char *buf, int len, int flags);
static int (WSAAPI *p_select)(int, fd_set *, fd_set *, fd_set *, const struct WINDOWS::timeval *);
static int (WSAAPI *p_closesocket)(WINDOWS::SOCKET s);
static u_short (WSAAPI *p_htons)(u_short hostshort);
// __WSAFDIsSet is used implicitely by FD_ISSET, redefine it
#define __WSAFDIsSet p__WSAFDIsSet
static int (WSAAPI *p__WSAFDIsSet)(WINDOWS::SOCKET fd, fd_set *);
#endif

//--------------------------------------------------------------------------
static void check_network_error(int fd, ssize_t ret, const char *from_where)
{
  if ( ret == -1 )
  {
#ifdef _WIN32
    int err = p_WSAGetLastError();
    bool timeout = err == WSAETIMEDOUT;
#else
    int err = errno;
    bool timeout = err == EAGAIN;
#endif
    if ( !timeout )
    {
      MSG("A network error %d happened in %s, exiting from application...\n", err, from_where);
      pin_closesocket(fd);
      exit_process(-1);
    }
    MSG("Timeout, called from %s\n", from_where);
  }
}

//--------------------------------------------------------------------------
static ssize_t pin_recv(PIN_SOCKET fd, void *buf, size_t n, const char *from_where)
{
  char *bufp = (char*)buf;
  ssize_t total = 0;
  while ( n > 0 )
  {
    ssize_t ret;
#ifdef _WIN32
    ret = p_recv(fd, bufp, (int)n, 0);
#else
    do
      ret = read(fd, bufp, n);
    while ( ret == -1 && errno == EINTR );
#endif
    check_network_error(fd, ret, from_where);
    if ( ret <= 0 )
      return ret;
    n -= ret;
    bufp += ret;
    total += ret;
  }
  return total;
}

//--------------------------------------------------------------------------
inline bool pin_sockwait(int milisec)
{
  fd_set rdset;
  pin_timeval tv = { 0, milisec * 1000 };
  FD_ZERO(&rdset);
  FD_SET(cli_socket, &rdset);
#ifdef _WIN32
  return pin_select(cli_socket+1, &rdset, NULL, NULL, &tv) > 0;
#else
  int res;
  do
    res = pin_select(cli_socket+1, &rdset, NULL, NULL, &tv);
  while ( res == -1 && errno == EINTR );
  return res > 0;
#endif
}

//--------------------------------------------------------------------------
static ssize_t pin_send(const void *buf, size_t n, const char *from_where)
{
  ssize_t ret;
#ifdef _WIN32
  ret = p_send(cli_socket, (const char *)buf, (int)n, 0);
#else
  do
    ret = send(cli_socket, buf, n, 0);
  while ( ret == -1 && errno == EINTR );
#endif
  check_network_error(cli_socket, ret, from_where);
  return ret;
}

//--------------------------------------------------------------------------
static const char *const packet_names[] =
{
  "ACK",            "ERROR",         "HELLO",          "EXIT PROCESS",
  "START PROCESS",  "DEBUG EVENT",   "READ EVENT",     "MEMORY INFO",
  "READ MEMORY",    "DETACH",        "COUNT TRACE",    "READ TRACE",
  "CLEAR TRACE",    "PAUSE",         "RESUME",         "RESUME START",
  "ADD BPT",        "DEL BPT",       "RESUME BPT",     "CAN READ REGS",
  "READ REGS",      "SET TRACE",     "SET OPTIONS",    "STEP INTO",
  "THREAD SUSPEND", "THREAD RESUME", "CHANGE_REGVALS", "GET_SEGBASE",
  "WRITE MEMORY",   "READ SYMBOLS",
};

//--------------------------------------------------------------------------
static bool accept_conn()
{
  struct pin_sockaddr_in sa;
  pin_socklen_t clilen = sizeof(sa);
  //lint -e565 tag 'sockaddr' not previously seen, assumed file-level scope
  cli_socket = pin_accept(srv_socket, ((struct sockaddr *)&sa), &clilen);
  if ( cli_socket == INVALID_SOCKET )
    return false;
  // accepted, client should send 'hello' packet, read it
  // read version 1 packet as it is may be shorter than the modern one
  idapin_packet_v1_t req_v1;
  DEBUG(4, "Receiving packet, expected %d bytes...\n",(uint32)sizeof(req_v1));
  int bytes = pin_recv(cli_socket, &req_v1, sizeof(req_v1), "read_handle_packet");
  if ( bytes <= 0 )
  {
    if ( bytes != 0 )
      MSG("recv: connection closed by peer\n");
    else
      error_msg("recv");
    return false;
  }
  if ( req_v1.code != PTT_HELLO )
  {
    if ( req_v1.code > PTT_END )
      MSG("Unknown packet type %d\n", req_v1.code);
    else
      MSG("'HELLO' expected, '%s' received)\n", packet_names[req_v1.code]);
    return false;
  }
  pin_client_version = req_v1.size;
  if ( pin_client_version == 1 )
  {
    // version 1 (incompatible) client - send v1 packet answer and exit
    MSG("Incompatible client (version 1) - disconnect\n");
    req_v1.size = PIN_PROTOCOL_VERSION;
    req_v1.data = sizeof(ADDRINT);
    req_v1.code = PTT_ACK;
    pin_send(&req_v1, sizeof(req_v1), __FUNCTION__);
    pin_closesocket(cli_socket);
    return false;
  }
  // valid client: read the rest of 'hello' packed
  idapin_packet_t req;
  memcpy(&req, &req_v1, sizeof(idapin_packet_v1_t));
  int rest = sizeof(idapin_packet_t) - sizeof(idapin_packet_v1_t);
  if ( rest > 0 )
  {
    char *ptr = (char *)&req + sizeof(idapin_packet_v1_t);
    if ( pin_recv(cli_socket, ptr, rest, "accept_conn") != rest )
      return false;
  }
  // response: we send target OS id and the size of ADDRINT to let the client
  // know if we're using the correct IDA version (32 or 64 bits)
  idapin_packet_t ans;
  ans.data = sizeof(ADDRINT) | addr_t(TARGET_OS);
  // ...and the version of the protocol
  // (and accept client version lesser than the current version of the tool)
  ans.size = PIN_PROTOCOL_VERSION;
  if ( pin_client_version < PIN_PROTOCOL_VERSION )
  {
    MSG("Client protocol version is %d - accept it\n", pin_client_version);
    ans.size = pin_client_version;
  }
  else
  {
    pin_client_version = PIN_PROTOCOL_VERSION;
  }
  ans.code = PTT_ACK;
  if ( !pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__) )
    return false;

  return true;
}

static int optval;
//--------------------------------------------------------------------------
static bool set_sockopt(PIN_SOCKET sock, int level, int optname, int val)
{
  optval = val;
#if defined(_WIN32) || PIN_BUILD_NUMBER < 76991
  return pin_setsockopt(sock, level, optname, &optval, sizeof(optval)) == 0;
#else
  // setsockopt is not implemented in PinCRT, fortunately syscall() is, use it
#ifdef PIN_64
  return syscall(54, sock, level, optname, &optval, sizeof(optval)) == 0;
#else
  long parms[] = { sock, level, optname, (long)&optval, sizeof(optval) };
  return syscall(0x66, 0xE, parms) == 0;
#endif
#endif
}

//--------------------------------------------------------------------------
static bool init_socket(void)
{
  // Since PIN #71313 we can not use WinSock library (hope in the future it will be
  // implemented in PinCRT like Linux sockets), now load library ws2_32.dll manualy
#ifdef _WIN32
  WINDOWS::HMODULE h = WINDOWS::LoadLibrary(TEXT("ws2_32.dll"));
  if ( h == NULL )
  {
    error_msg("Load ws2_32.dll");
    return false;
  }
  *(WINDOWS::FARPROC*)&p_WSAStartup = GetProcAddress(h, TEXT("WSAStartup"));
  *(WINDOWS::FARPROC*)&p_WSAGetLastError = GetProcAddress(h, TEXT("WSAGetLastError"));
  *(WINDOWS::FARPROC*)&p_socket = GetProcAddress(h, TEXT("socket"));
  *(WINDOWS::FARPROC*)&p_bind = GetProcAddress(h, TEXT("bind"));
  *(WINDOWS::FARPROC*)&p_setsockopt = GetProcAddress(h, TEXT("setsockopt"));
  *(WINDOWS::FARPROC*)&p_listen = GetProcAddress(h, TEXT("listen"));
  *(WINDOWS::FARPROC*)&p_accept = GetProcAddress(h, TEXT("accept"));
  *(WINDOWS::FARPROC*)&p_recv = GetProcAddress(h, TEXT("recv"));
  *(WINDOWS::FARPROC*)&p_send = GetProcAddress(h, TEXT("send"));
  *(WINDOWS::FARPROC*)&p_select = GetProcAddress(h, TEXT("select"));
  *(WINDOWS::FARPROC*)&p_closesocket = GetProcAddress(h, TEXT("closesocket"));
  *(WINDOWS::FARPROC*)&p_htons = GetProcAddress(h, TEXT("htons"));
  *(WINDOWS::FARPROC*)&p__WSAFDIsSet = GetProcAddress(h, TEXT("__WSAFDIsSet"));

  if ( p_WSAStartup == NULL
    || p_WSAGetLastError == NULL
    || p_socket == NULL
    || p_bind == NULL
    || p_setsockopt == NULL
    || p_listen == NULL
    || p_accept == NULL
    || p_recv == NULL
    || p_send == NULL
    || p_select == NULL
    || p_closesocket == NULL
    || p_htons == NULL
    || p__WSAFDIsSet == NULL )
  {
    error_msg("Get socket proc");
    return false;
  }

  WINDOWS::WORD wVersionRequested = 0x0202;
  WINDOWS::WSADATA wsaData;
  int err = p_WSAStartup(wVersionRequested, &wsaData);
  if ( err != 0 )
  {
    error_msg("WSAStartup");
    return false;
  }
  DEBUG(2, "init_win_soc ended\n");
#endif

  int portno = knob_ida_port;
  srv_socket = pin_socket(AF_INET, SOCK_STREAM, 0);
  if ( srv_socket == (PIN_SOCKET)-1 )
  {
    error_msg("socket");
    return false;
  }

  if ( !set_sockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, 1) )
    error_msg("set_sockopt(SO_REUSEADDR)");

  struct pin_sockaddr_in sa;
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port   = pin_htons(portno);
  if ( pin_bind(srv_socket, (pin_sockaddr *)&sa, sizeof(sa)) != 0 )
  {
    error_msg("bind");
    return false;
  }

  if ( pin_listen(srv_socket, 1) == 0 )
  {
    MSG("Listening at port %d, protocol version is %d, PIN version %d.%d.%d\n",
         (int)portno, PIN_PROTOCOL_VERSION,
         PIN_PRODUCT_VERSION_MAJOR, PIN_PRODUCT_VERSION_MINOR,
         PIN_BUILD_NUMBER);

    int to = knob_connect_timeout;

    if ( to != 0 )
    {
      pin_timeval tv;
      pin_fd_set read_descs;
      tv.tv_sec = to;
      tv.tv_usec = 0;
      FD_ZERO(&read_descs);
      FD_SET(srv_socket, &read_descs);
      if ( pin_select(srv_socket + 1, &read_descs, NULL, NULL, &tv) == -1 )
      {
        error_msg("select");
        return false;
      }
      if ( !FD_ISSET(srv_socket, &read_descs) )
      {
        MSG("client connect timeout\n");
        return false;
      }
    }
    return accept_conn();
  }
  return false;
}

//--------------------------------------------------------------------------
// On Windows internal threads are blocked until the application
// has finished initializing its DLL's.
// So, at first we use synchronous function serve_sync() to wait for resume
// packet after breakpoint/pause/trace buffer transferring.
// We stop using synchronous serving when the listener thread really starts
inline void wait_app_resume(PIN_SEMAPHORE *sem)
{
  if ( !serve_sync() )
  {
    // Don't know what to do if serve_sync() fails: just set semaphore
    // (to avoid deadlock) and return. Would it be better to exit application?
    sema_set(sem);
  }
  sema_wait(sem);
}

//--------------------------------------------------------------------------
static VOID app_start_cb(VOID *)
{
  DEBUG(2, "Setting process started to true\n");
  process_state = APP_STATE_RUNNING;
  main_thread = thread_data_t::get_thread_id();

  IMG img;
  img.invalidate();
  for ( img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) )
  {
    if ( IMG_IsMainExecutable(img) )
      break;
  }

  if ( !img.is_valid() )
  {
    MSG("Cannot find the 1st instruction of the main executable!\n");
    abort();
  }

  // by default, we set the limits of the trace to the main binary
  ADDRINT start_ea = IMG_LowAddress(img);
  ADDRINT end_ea = IMG_HighAddress(img);

  // Mistery: in wow64 the app_start_cb callback can be called twice?
  static bool app_start_cb_called = false;
  if ( !app_start_cb_called )
  {
    app_start_cb_called = true;
    MSG("Head image: %s Start %p End %p\n", IMG_Name(img).c_str(), pvoid(start_ea), pvoid(end_ea));
    instrumenter_t::process_image(img, true);
  }

  start_ev.debev.eid = PROCESS_START;
  start_ev.debev.ea = IMG_Entry(img);
  pin_strncpy(start_ev.debev.modinfo.name, IMG_Name(img).c_str(), sizeof(start_ev.debev.modinfo.name));
  start_ev.debev.modinfo.base = start_ea;
  start_ev.debev.modinfo.rebase_to = BADADDR;
  start_ev.debev.modinfo.size = (uint32)(end_ea - start_ea);

  if ( main_thread_started )
  { // emit PROCESS_START event only if main thread already started to be sure
    // we have valid register values. If the thread was not started yet -
    // do nothing (will generate the event in thread_start_cb)
    DEBUG(2, "Emit PROCESS_START by app_start_cb\n");
    emit_process_start_ev();
  }
}

//--------------------------------------------------------------------------
static VOID context_change_cb(
        THREADID tid,
        CONTEXT_CHANGE_REASON reason,
        const CONTEXT *ctxt_from,
        CONTEXT *ctxt_to,
        INT32 sig,
        VOID *)
{
  pin_local_event_t ev(EXCEPTION, tid);
  pin_debug_event_t &event = ev.debev;
  event.exc.code = sig;
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  if ( ctxt_from != NULL )
  {
    tdata->save_ctx(ctxt_from, false);
    event.ea = get_ctx_ip(ctxt_from);
  }
  event.exc.ea = event.ea;

  switch ( reason )
  {
    case CONTEXT_CHANGE_REASON_FATALSIGNAL:
      event.exc.can_cont = false;
      snprintf(event.exc.info, sizeof(event.exc.info), "Fatal signal %d at %p", sig, pvoid(event.ea));
      break;
    case CONTEXT_CHANGE_REASON_SIGNAL:
      snprintf(event.exc.info, sizeof(event.exc.info), "Signal %d at %p", sig, pvoid(event.ea));
      break;
    case CONTEXT_CHANGE_REASON_EXCEPTION:
      snprintf(event.exc.info, sizeof(event.exc.info), "Exception 0x%x at address %p", sig, pvoid(event.ea));
      break;
    case CONTEXT_CHANGE_REASON_SIGRETURN:
      MSG("Context changed: signal return %d at %p\n", sig, pvoid(event.ea));
      return;
    case CONTEXT_CHANGE_REASON_APC:
      MSG("Context changed: Asynchronous Process Call %d at %p\n", sig, pvoid(event.ea));
      return;
    case CONTEXT_CHANGE_REASON_CALLBACK:
      MSG("Context changed: Windows Call-back %d at %p\n", sig, pvoid(event.ea));
      return;
    default:
      MSG("Context changed at %p: unknown reason %d\n", pvoid(event.ea), int(reason));
      return;
  }
  tdata->set_excp_handled(false);
  suspend_at_event(ev, true);

  MSG("EXCEPTION at %p -> %p (thread %d)\n", pvoid(event.ea),
                           pvoid(get_ctx_ip(ctxt_to)), int(event.tid));

  app_wait(&run_app_sem);
  if ( tdata->excp_handled() )
  {
    if ( reason == CONTEXT_CHANGE_REASON_EXCEPTION && sig == INT32(0x80000003) )
    {
      // I don't know why but trying to mask int3 we pass control
      // to the same address (resulting the same exception) and will
      // run into infinite loop
      // So we don't mask the exception and continue execution
      MSG("Don't mask INT3 exception to avoid infinite loop\n");
    }
    else
    {
      MSG("Mask exception\n");
      PIN_SaveContext(ctxt_from, ctxt_to);
    }
  }
  else
  {
    MSG("Pass exception to the application\n");
  }
}

//--------------------------------------------------------------------------
//lint -e{818} Pointer parameter 'ctxt' could be declared as pointing to const
//                            'ex_info' could be declared as pointing to const
static EXCEPT_HANDLING_RESULT internal_excp_cb(
        THREADID tid,
        EXCEPTION_INFO *ex_info,
        PHYSICAL_CONTEXT *ctxt,
        VOID * /* v */)
{
  pin_local_event_t ev(EXCEPTION, tid);
  pin_debug_event_t &event = ev.debev;
  event.exc.code = PIN_GetExceptionCode(ex_info);
  event.ea = ea_t(PIN_GetExceptionAddress(ex_info));
  event.exc.ea = event.ea;
  string strinfo = PIN_ExceptionToString(ex_info);
  strncpy(event.exc.info, strinfo.c_str(), sizeof(event.exc.info));
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  tdata->save_phys_ctx(ctxt);

  MSG("INTERNAL EXCEPTION (thread %d, code=%x): %s\n", int(tid), event.exc.code, event.exc.info);
  ADDRINT exc_ip = PIN_GetPhysicalContextReg(ctxt, REG_INST_PTR);
  if ( event.ea != exc_ip )
  {
    MSG("ExceptionAddress(%p) differs from ExceptionEIP (%p)!!!\n", pvoid(event.ea), pvoid(exc_ip));
  }

  tdata->set_excp_handled(false);
  suspend_at_event(ev, true);
  app_wait(&run_app_sem);
  if ( tdata->excp_handled() )
  {
    MSG("Continue execution after internal exception\n");
    return EHR_HANDLED;
  }
  else
  {
    MSG("Execute default system procedure for internal exception\n");
    return EHR_CONTINUE_SEARCH;
  }
}

//--------------------------------------------------------------------------
// only one thread can serve requests at each point in time, use for this
// the first one the control was passed to.
static THREADID serving_thread = INVALID_THREADID;
static PIN_LOCK serving_thread_lock;

//--------------------------------------------------------------------------
// serve requests synchronously in case the listener thread is not started yet
static bool serve_sync(void)
{
  THREADID thr = thread_data_t::get_thread_id();
  {
    janitor_for_pinlock_t process_state_guard(&serving_thread_lock);
    if ( serving_thread == thr )
    {
      MSG("Internal PINTOOL error: wrong serving thread in serve_sync()\n");
      return false;        // something wrong: recursive call?
    }
    if ( serving_thread != INVALID_THREADID )
      return true;         // another thread is serving reqests
    serving_thread = thr;  // this thread will be serving requests
  }
  bool ok = true;
  while ( true )
  {
    {
      janitor_for_pinlock_t process_state_guard(&process_state_lock);
      if ( process_detached() || process_exiting() )
      {
        ok = false;
        break;
      }
      if ( !(process_pause() || process_suspended()) )
        break;
    }
    janitor_for_pinlock_t listener_state_guard(&listener_ready_lock);
    if ( listener_ready )
    {
      // listener thread already started - all requests will be processed by it
      break;
    }
    if ( !read_handle_packet() )
    {
      ok = false;
      break;
    }
  }
  janitor_for_pinlock_t process_state_guard(&process_state_lock);
  if ( serving_thread == thr )
    serving_thread = INVALID_THREADID;    // reset serving thread ID
  return ok;
}

//--------------------------------------------------------------------------
// separate internal thread for asynchronous IDA requests serving
static VOID ida_pin_listener(VOID *)
{
  MSG("Listener started (thread = %d)\n", thread_data_t::get_thread_id());

  {
    janitor_for_pinlock_t listener_start_guard(&start_listener_lock);
    janitor_for_pinlock_t listener_state_guard(&listener_ready_lock);
    listener_ready = true;
  }

  MSG("Listener is ready\n");

  while ( true )
  {
    DEBUG(4, "Handling events in ida_pin_listener\n");
    if ( !read_handle_packet() )
      break;
    if ( process_detached() )
    {
      MSG("Detached\n");
      pin_closesocket(cli_socket);
      // possible reattach?
#ifdef TRY_TO_SUPPORT_REATTACH
      if ( !accept_conn() )
        break;
      MSG("New connection accepted\n");
      process_state = APP_STATE_RUNNING;
      break_at_next_inst = true;
      instrumenter_t::init_instrumentations();
#else
      pin_closesocket(srv_socket);
      break;
#endif
    }
    if ( PIN_IsProcessExiting() )
    {
      DEBUG(2, "PIN_IsProcessExiting() -> Ok...\n");
      if ( events.empty() && process_exited() )
      {
        MSG("Process is exiting...\n");
        break;
      }
    }
  }
  MSG("Listener exited\n");
  listener_uid = INVALID_PIN_THREAD_UID;
}

//--------------------------------------------------------------------------
static void handle_start_process(void)
{
  if ( PIN_IsAttaching() )
    break_at_next_inst = true;

  // initialized stuff
  breakpoints.prepare_resume();
  instrumenter_t::init_instrumentations();

  // Initialize the semaphore used for the whole application pausing
  PIN_SemaphoreInit(&run_app_sem);
  sema_set(&run_app_sem);

  PIN_InitLock(&listener_ready_lock);
  PIN_InitLock(&serving_thread_lock);

  // A number of first packets should be processed by the main thread
  // so we prevent listener from serving them
  PIN_InitLock(&start_listener_lock);
  PIN_GetLock(&start_listener_lock, PIN_ThreadId() + 1);

  events.init();

  // Init symbol table
  PIN_InitSymbols();

  // Register image_load_cb to be called when an image is loaded
  IMG_AddInstrumentFunction(image_load_cb, 0);

  // Register image_unload_cb to be called when an image is unloaded
  IMG_AddUnloadFunction(image_unload_cb, 0);

  // Register callbacks to be called when a thread begins/ends
  PIN_AddThreadStartFunction(thread_start_cb, 0);
  PIN_AddThreadFiniFunction(thread_fini_cb, 0);

  // Register fini_cb to be called when the application exits
#if PIN_BUILD_NUMBER >= 76991
  PIN_AddFiniFunction(fini_cb, 0);
  PIN_AddPrepareForFiniFunction(prepare_fini_cb, 0);
#else
  PIN_AddFiniUnlockedFunction(fini_cb, 0);
#endif
  // Register aplication start callback
  PIN_AddApplicationStartFunction(app_start_cb, 0);

  // Register context change function
  PIN_AddContextChangeFunction(context_change_cb, 0);

  // Register PIN exception callback
  PIN_AddInternalExceptionHandler(internal_excp_cb, 0);

  // Create the thread for communicating with IDA
  THREADID thread_id = PIN_SpawnInternalThread(ida_pin_listener, NULL, 0, &listener_uid);
  if ( thread_id == INVALID_THREADID )
  {
    MSG("PIN_SpawnInternalThread(listener) failed\n");
    exit(-1);
  }

  suspender.start();

  if ( !instrumenter_t::init() )
    exit(-1);

  // Start the program, never returns
  PIN_StartProgram();
}

//--------------------------------------------------------------------------
static void add_segment(pin_meminfo_vec_t *miv, pin_memory_info_t &mi)
{
  pin_meminfo_vec_t::reverse_iterator p;
  for ( p = miv->rbegin(); p != miv->rend(); ++p )
  {
    if ( p->start_ea == mi.start_ea )
    {
      DEBUG(3, "add_segment: skip existing segment %s/%p\n",
                              p->name, pvoid(mi.start_ea));
      return;
    }

    // if we found the correct position insert it
    if ( p->end_ea <= mi.start_ea )
    {
      miv->insert(p.base(), mi);
      return;
    }
  }
  miv->insert(miv->begin(), mi);
}

#ifdef _WIN32

//--------------------------------------------------------------------------
// convert Windows protection modes to IDA protection modes
inline uchar win_prot_to_ida_perm(uint32 protection)
{
  uchar perm = 0;

  if ( protection & PAGE_READONLY )
    perm |= SEGPERM_READ;
  if ( protection & PAGE_READWRITE )
    perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_WRITECOPY )
    perm |= SEGPERM_READ | SEGPERM_WRITE;
  if ( protection & PAGE_EXECUTE )
    perm |= SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READ )
    perm |= SEGPERM_READ | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_READWRITE )
    perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
  if ( protection & PAGE_EXECUTE_WRITECOPY )
    perm |= SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;

  return perm;
}

//--------------------------------------------------------------------------
inline bool get_win_meminfo(WINDOWS::MEMORY_BASIC_INFORMATION *mi, ADDRINT ea)
{
  uint32 code = WINDOWS::VirtualQuery(pvoid(ea),  // address of region
                             mi,                  // addr of information buffer
                             sizeof(*mi));        // size of buffer
  if ( code != sizeof(*mi) )
  {
    if ( code != 0 )
      MSG("Unexpected return code from VirtualQuery %d (expected %z)\n",
                                                    code, sizeof(*mi));
    return false;
  }
  DEBUG(3, "VirtualQuery(%p): base = %p, size = %zx, protect=0x%x, allocprotect=0x%x, state=0x%x\n", pvoid(ea), mi->BaseAddress, (size_t)mi->RegionSize, mi->Protect, mi->AllocationProtect, mi->State);
  return true;
}

//--------------------------------------------------------------------------
static ADDRINT get_win_reginfo(pin_meminfo_vec_t *miv, ADDRINT ea, ADDRINT end)
{
  WINDOWS::MEMORY_BASIC_INFORMATION meminfo;
  if ( !get_win_meminfo(&meminfo, ea) )
    return BADADDR; // no more region

  ADDRINT startea = ADDRINT(meminfo.BaseAddress);
  ADDRINT endea = startea + meminfo.RegionSize;
  if ( endea < startea )
    endea = BADADDR;

  // skip the area if it isn't interesting for/accessible by IDA
  // and return a pointer to the next (eventual) area
  if ( (meminfo.State & (MEM_FREE|MEM_RESERVE)) != 0
    || (meminfo.Protect & PAGE_NOACCESS) != 0 )
  {
    return endea;
  }

  pin_memory_info_t mi(startea, endea, win_prot_to_ida_perm(meminfo.Protect));
  if ( mi.end_ea > end )
    mi.end_ea = end;
  miv->push_back(mi);
  return endea;
}

//--------------------------------------------------------------------------
inline void get_win_regions(pin_meminfo_vec_t *miv, ADDRINT start, ADDRINT end)
{
  for ( ADDRINT ea = start; ea < end; ea = get_win_reginfo(miv, ea, end) )
    ;
}

//--------------------------------------------------------------------------
static uint32 get_mem_page_size()
{
  static uint32 page_size = 0;
  if ( page_size == 0 )
  {
    WINDOWS::SYSTEM_INFO si;
    WINDOWS::GetSystemInfo(&si);
    page_size = si.dwPageSize;
  }
  return page_size;
}

//--------------------------------------------------------------------------
inline bool get_win_segment_protection(int *prot, ADDRINT ea)
{
  WINDOWS::MEMORY_BASIC_INFORMATION meminfo;
  if ( !get_win_meminfo(&meminfo, ea) )
    return false;
  *prot = meminfo.Protect;
  return true;
}

//--------------------------------------------------------------------------
// set segment protection and insert it to the vector
inline void add_thread_segment(pin_meminfo_vec_t *miv, pin_memory_info_t &mi)
{
  int prot;
  if ( get_win_segment_protection(&prot, mi.start_ea) )
    mi.perm = win_prot_to_ida_perm(prot);
  DEBUG(3, "add_thread_segment(%s, %p-%p (prot=%x)\n",
           mi.name, pvoid(mi.start_ea), pvoid(mi.end_ea), prot);
  add_segment(miv, mi);
}

//--------------------------------------------------------------------------
// Enumerate all accessible segments. Yes, we will get PIN segments also
// but for the moment there is no way to filter them out
static void get_os_segments(pin_meminfo_vec_t &miv)
{
  // collect thread-related segments
  thread_data_t::add_all_thread_areas(&miv);

  // add WIN system regions
  WINDOWS::SYSTEM_INFO si;
  WINDOWS::GetSystemInfo(&si);
  ADDRINT total_vm = (ADDRINT)si.lpMaximumApplicationAddress;

  pin_meminfo_vec_t miv1;
  ADDRINT prev_ea = 0;
  for ( pin_meminfo_vec_t::iterator p = miv.begin(); p != miv.end(); ++p )
  {
    get_win_regions(&miv1, prev_ea, p->start_ea);
    prev_ea = p->end_ea;
  }
  get_win_regions(&miv1, prev_ea, total_vm);

  for ( pin_meminfo_vec_t::iterator p = miv1.begin(); p != miv1.end(); ++p )
    add_segment(&miv, *p);
}
#else

#ifdef __linux__

//--------------------------------------------------------------------------
const char *skip_spaces(const char *ptr)
{
  if ( ptr != NULL )
  {
    while ( isspace(*ptr) )
      ptr++;
  }
  return ptr;
}

//--------------------------------------------------------------------------
struct mapfp_entry_t
{
  addr_t ea1;
  addr_t ea2;
  addr_t offset;
  uint64 inode;
  char perm[8];
  char device[8];
  string fname;
};

//--------------------------------------------------------------------------
static bool read_mapping(FILE *mapfp, mapfp_entry_t *me)
{
  char line[2*MAXSTR];
  if ( !fgets(line, sizeof(line), mapfp) )
    return false;

  me->ea1 = BADADDR;

  uint32 len = 0;
  int code = sscanf(line, HEX_FMT "-" HEX_FMT " %s " HEX_FMT " %s " HEX64T_FMT "x%n",
                     &me->ea1,
                     &me->ea2,
                     me->perm,
                     &me->offset,
                     me->device,
                     &me->inode,
                     &len);
  if ( code == 6 && len < sizeof(line) )
  {
    char *ptr = &line[len];
    ptr = (char *)skip_spaces(ptr);
    // remove trailing spaces and eventual (deleted) suffix
    static const char delsuff[] = " (deleted)";
    const int suflen = sizeof(delsuff) - 1;
    char *end = (char*)tail(ptr);
    while ( end > ptr && isspace(end[-1]) )
      *--end = '\0';
    if ( end-ptr > suflen && strncmp(end-suflen, delsuff, suflen) == 0 )
      end[-suflen] = '\0';
    me->fname = ptr;
  }
  return (signed)me->ea1 != BADADDR;
}

//--------------------------------------------------------------------------
static void get_os_segments(pin_meminfo_vec_t &miv)
{
  FILE *mapfp = fopen("/proc/self/maps", "rb");
  if ( mapfp == NULL )
  {
    error_msg("ERROR: could not open /proc/self/maps");
    return;
  }
  mapfp_entry_t me;
  while ( read_mapping(mapfp, &me) )
  {
    // for some reason linux lists some areas twice
    // ignore them
    size_t i;
    for ( i=0; i < miv.size(); i++ )
      if ( miv[i].start_ea == me.ea1 )
        break;
    if ( i != miv.size() )
      continue;

    // do we really want to hide the PIN's segments? I guess yes, but...
    if ( me.fname != "pinbin" )
    {
      pin_memory_info_t mi;
      mi.start_ea = me.ea1;
      mi.end_ea   = me.ea2;
      pin_strncpy(mi.name, me.fname.c_str(), sizeof(mi.name));
      mi.bitness = BITNESS;

      if ( strchr(me.perm, 'r') != NULL ) mi.perm |= SEGPERM_READ;
      if ( strchr(me.perm, 'w') != NULL ) mi.perm |= SEGPERM_WRITE;
      if ( strchr(me.perm, 'x') != NULL ) mi.perm |= SEGPERM_EXEC;

      add_segment(&miv, mi);
    }
  }
  fclose(mapfp);
}

#else
// MacOSX
static void get_os_segments(pin_meminfo_vec_t &) {}
#endif

#endif

//--------------------------------------------------------------------------
static bool handle_memory_info(void)
{
  bool ret = false;

  DEBUG(2, "handle_memory_info started\n");
  // Visit every loaded image and fill miv vector
  pin_meminfo_vec_t miv;
  ADDRINT img_min_ea = 0;
  ADDRINT img_max_ea = 0;
  for ( IMG img= APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img) )
  {
    for ( SEC sec= IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
    {
      pin_memory_info_t mi;
      ea_t sec_ea = SEC_Address(sec);
      if ( sec_ea != 0 )
      {
        mi.start_ea = sec_ea;
        mi.end_ea   = sec_ea + SEC_Size(sec);

        if ( img_min_ea == 0 || img_min_ea > sec_ea )
          img_min_ea = sec_ea;

        if ( img_max_ea == 0 || img_max_ea < mi.end_ea )
          img_max_ea = mi.end_ea;

        string sec_name;
        sec_name = IMG_Name(img) + ":" + SEC_Name(sec);
        memset(mi.name, '\0', sizeof(mi.name));
        pin_strncpy(mi.name, sec_name.c_str(), sizeof(mi.name));
        mi.bitness = BITNESS;

        mi.perm = 0;
        if ( SEC_IsReadable(sec) )
          mi.perm |= SEGPERM_READ;
        if ( SEC_IsWriteable(sec) )
          mi.perm |= SEGPERM_WRITE;
        if ( SEC_IsExecutable(sec) )
          mi.perm |= SEGPERM_EXEC;

        add_segment(&miv, mi);
      }
    }
  }

  get_os_segments(miv);

  memimages_pkt_t pkt(PTT_MEMORY_INFO, (uint32)miv.size());

  // send a packet with the number of segments
  if ( pin_send(&pkt, sizeof(pkt), "handle_memory_info(1)") )
  {
    ret = true;

    // and, then, send the information for all images
    pin_meminfo_vec_t::iterator p;
    for ( p = miv.begin(); p != miv.end(); ++p )
    {
      pin_memory_info_t &mi = *p;
      if ( !pin_send(&mi, sizeof(mi), "handle_memory_info(2)") )
      {
        ret = false;
        break;
      }
    }
    thread_data_t::set_meminfo_changed(false);
  }

  return ret;
}

//--------------------------------------------------------------------------
static char *get_io_buff(size_t size)
{
  static size_t curr_size = 0;
  static char *packet_io_buf = NULL;
  if ( size > curr_size )
  {
    void *p = realloc(packet_io_buf, size);
    if ( p == NULL )
      free(packet_io_buf);
    packet_io_buf = (char *)p;
    curr_size = size;
  }
  return packet_io_buf;
}

//--------------------------------------------------------------------------
static bool handle_read_symbols()
{
  bool ret = false;

  int bufsize = 0;
  char *symbuf = events.export_symbols(&bufsize);
  idapin_packet_t pkt(PTT_ACK);
  pkt.size = bufsize;
  // send a packet with the size of the buffer
  if ( pin_send(&pkt, sizeof(pkt), "symbols(1)") )
  {
    // send the buffer
    ret = bufsize == 0 ? true : pin_send(symbuf, bufsize, "symbols(2)");
  }
  free(symbuf);

  return ret;
}
//--------------------------------------------------------------------------
inline const char *hexval(const void *ptr, int size)
{
  static char buf[64*3];
  buf[0] = 0;
  if ( size == int(sizeof(ADDRINT)) )
  {
    ADDRINT ea = *(ADDRINT *)ptr;
    if ( ea == 0 )
      return "0";
    snprintf(buf, sizeof(buf), "%p", pvoid(ea));
  }
  else
  {
    int pos = 0;
    const unsigned char *s = (const unsigned char *)ptr;
    for ( int i = 0; i < size; ++i, pos += 3 )
      snprintf(&buf[pos], sizeof(buf) - pos, "%02x ", s[i]);
  }
  return buf;
}

//--------------------------------------------------------------------------
inline const char *hexval(const void *ptr, pin_regid_t reg_idx)
{
  int size = reg_idx <= PINREG_LAST_INTREG
           ? sizeof(ADDRINT)
           : max_regsize(reg_idx);
  return hexval(ptr, size);
}

//--------------------------------------------------------------------------
static bool handle_read_memory(ADDRINT ea, pin_size_t size)
{
  DEBUG(2, "Reading %d bytes at address %p\n", size, pvoid(ea));

  idamem_response_pkt_t pkt;
  // read the data asked by IDA
  size_t copy_size = size < sizeof(pkt.buf) ? size : sizeof(pkt.buf);
  ssize_t read_bytes = thread_data_t::read_memory(pkt.buf, ea, copy_size);
  pkt.size = (uint32)read_bytes;
  pkt.code = PTT_READ_MEMORY;

  ssize_t bytes = pin_send(&pkt, sizeof(pkt), __FUNCTION__);
  return bytes == sizeof(pkt);
}

//--------------------------------------------------------------------------
static ssize_t handle_write_memory(ADDRINT ea, pin_size_t size)
{
  DEBUG(2, "Writing %d bytes at address %p\n", size, pvoid(ea));

  char *buffer = (char *)get_io_buff(size);
  if ( pin_recv(cli_socket, buffer, size, "write memory") != ssize_t(size) )
    return false;
  return thread_data_t::write_memory(ea, buffer, size);
}

//--------------------------------------------------------------------------
static bool handle_read_trace(void)
{
  idatrace_events_t trc_events;
  instrumenter_t::get_trace_events(&trc_events);
  trc_events.code = PTT_ACK;
  ssize_t bytes = pin_send(&trc_events, sizeof(trc_events), __FUNCTION__);
  return bytes == sizeof(trc_events);
}

//--------------------------------------------------------------------------
static bool handle_read_regs(THREADID tid, int cls)
{
  thread_data_t *tdata = thread_data_t::get_thread_data(tid);
  if ( pin_client_version < 5 )
  { // version < 5: use idapin_registers_t structure
    idapin_registers_t regs;
    tdata->export_ctx(&regs);
    DEBUG(2, "get_context_regs(%d): ip = %p)\n", int(tid), pvoid(regs.eip));
    ssize_t bytes = pin_send(&regs, sizeof(regs), __FUNCTION__);
    return bytes == sizeof(regs);
  }
  CONTEXT *context = tdata->get_ctx();
  int clmask = tdata->available_regs(cls);
  pin_regbuf_t regbuf(clmask);
  size_t bufsize = regbuf.get_bufsize();
  idapin_readregs_answer_t ans(bufsize, clmask);

  if ( !pin_send(&ans, sizeof(ans), __FUNCTION__) )
    return false;
  if ( bufsize != 0 )
  {
    char *buf = get_io_buff(bufsize);
    memset(buf, 0, bufsize);
    regbuf.setbuf(buf);
    for ( int i = 0; i < regbuf.nclasses(); ++i )
    {
      pin_classregs_t *reg_class = regbuf.get_class(i);
      if ( reg_class == NULL )
      {
        MSG("Internal error at %d: unexpected NULL value\n", __LINE__);
        return false;
      }
      DEBUG(2, "Thread %d/%d: Get registers (class=%s/%02x)\n", tdata->get_ext_tid(), tid, regclass_name(regbuf.get_classid(i)), regbuf.get_classid(i));
      for ( int j = 0; j < reg_class->count(); ++j )
      {
        pin_regid_t regid = pin_regid_t(reg_class->first() + j);
        REG pin_regid = regidx_pintool2pin(regid);
        if ( pin_regid != REG_LAST )
        {
          PIN_REGISTER pinreg;
          PIN_GetContextRegval(context, pin_regid, (UINT8 *)pinreg.byte);
          int size = REG_Size(pin_regid);
          if ( size < int(sizeof(ADDRINT)) )
            size = sizeof(ADDRINT);
          pin_value_t *vptr = reg_class->at(regid);
          memcpy(vptr->v128, pinreg.byte, size);
          DEBUG(2, "Get register %s/%d: %s\n", regname_by_idx(regid), REG_Size(pin_regid), hexval(vptr, size));
        }
      }
    }
    if ( !pin_send(buf, bufsize, __FUNCTION__) )
      return false;
  }
  return true;
}

//--------------------------------------------------------------------------
static bool get_segbase(ADDRINT *base, THREADID tid_local, ADDRINT segval)
{
  thread_data_t *tdata = thread_data_t::find_thread_data(tid_local);
  if ( tdata == NULL )
    return false;

  CONTEXT *ctx = tdata->get_ctx();
  ADDRINT gs = PIN_GetContextReg(ctx, REG_SEG_GS);
  ADDRINT fs = PIN_GetContextReg(ctx, REG_SEG_FS);
  DEBUG(2, "get_segbase: gs=%p, fs=%p\n", (void *)gs, (void *)fs);
  if ( segval == gs )
  {
    *base = PIN_GetContextReg(ctx, REG_SEG_GS_BASE);
    // try FS if GS gave NULL base and both FS and GS have the same value
    if ( *base != 0 || segval != fs )
      return true;
  }
  if ( segval == fs )
  {
    *base = PIN_GetContextReg(ctx, REG_SEG_FS_BASE);
  }
  else if ( segval == PIN_GetContextReg(ctx, REG_SEG_CS)
         || segval == PIN_GetContextReg(ctx, REG_SEG_DS)
         || segval == PIN_GetContextReg(ctx, REG_SEG_SS)
         || segval == PIN_GetContextReg(ctx, REG_SEG_ES) )
  {
    *base = 0;    // assume CS, DS, SS, ES have base of 0
  }
  else
  {
    return false; // unmatched value
  }
  return true;
}

//--------------------------------------------------------------------------
static bool handle_limits(void)
{
  bool ret = false;
  idalimits_packet_t ans;
  ssize_t bytes = pin_recv(cli_socket, &ans, sizeof(ans), __FUNCTION__);
  idapin_packet_t res;
  if ( bytes == sizeof(ans) )
  {
    if ( !instrumenter_t::set_limits(ans.only_new,
                                     ans.trace_limit, ans.image_name) )
    {
      res.code = PTT_ERROR;
    }
    else
    {
      res.code = PTT_ACK;
    }

    // send the answer and terminate the application if the selected
    // configuration is not supported
    bytes = pin_send(&res, sizeof(res), __FUNCTION__);
    if ( res.code == PTT_ERROR || bytes != sizeof(res) )
    {
      MSG("Unsupported configuration or network error while setting limits, calling PIN_ExitApplication\n");
      PIN_ExitApplication(-1);
    }
    ret = true;
  }
  return ret;
}

//--------------------------------------------------------------------------
inline void prepare_pause()
{
  pin_local_event_t lastev;
  if ( events.back(&lastev) )
  {
    DEBUG(2, "prepare_pause: already have events - do nothing\n");
  }
  else
  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    DEBUG(2, "prepare_pause: enable suspender, state = %d\n", process_state);
    if ( process_state == APP_STATE_RUNNING )
    {
      process_state = APP_STATE_PAUSE;
      suspender.pause_threads();
    }
  }
}

//--------------------------------------------------------------------------
// We expect IDA sends RESUME request as a response to every event
// The following function performs buffered resume:
// we do actual resume only when the event queue becomes empty
static bool do_resume(idapin_packet_t *ans, const idapin_packet_t &request)
{
  if ( thread_data_t::all_threads_suspended() )
  {
    MSG("Can't resume: all threads are suspended\n");
    ans->code = PTT_ERROR;
    return pin_send(ans, sizeof(idapin_packet_t), __FUNCTION__);
  }
  pin_event_id_t eid = pin_event_id_t(request.data);
  {
    pin_local_event_t last_ev_local;
    events.last_ev(&last_ev_local);
    pin_debug_event_t &last_ev = last_ev_local.debev;
    THREADID tid_local = last_ev_local.tid_local;
    if ( pin_event_id_t(last_ev.eid) != eid )
      MSG("Unexpected resume: eid=%x (%x expected)\n", eid, int(last_ev.eid));

    if ( eid == EXCEPTION )
    {
      // examine request.size field: should exception be passed to application?
      thread_data_t *tdata = thread_data_t::find_thread_data(tid_local);
      if ( tdata != NULL )
        tdata->set_excp_handled(request.size != 0);
      else
        MSG("RESUME error: can't find thread data for %d\n", tid_local);
    }

    if ( eid == THREAD_EXIT )
    {
      // we had to keep thread context until THREAD_EXIT event is processed
      // by the client. Now we can release it
      thread_data_t::release_thread_data(tid_local);
    }

    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    bool can_resume;
    if ( events.send_event(&can_resume) )
    {
      DEBUG(2, "Have events, did not resume, just sent event\n");
    }
    else
    {
      if ( can_resume )
      {
        DEBUG(2, "Event queue is empty, do actual resume\n");
        suspender.resume_threads();
        if ( process_suspended() )
        {
          process_state = APP_STATE_RUNNING;
          if ( breakpoints.prepare_resume() )
            instrumenter_t::reinit_instrumentations();
          sema_set(&run_app_sem);
        }
      }
      else
      {
        DEBUG(2, "Event queue is empty, but actual resume is not allowed - "
                 "probably because of pending PROCESS_ATTACH\n");
      }
    }
    if ( eid == PROCESS_EXIT )
      process_state = APP_STATE_EXITED;
  }
  instrumenter_t::resume();
  ans->code = PTT_ACK;
  return pin_send(ans, sizeof(idapin_packet_t), __FUNCTION__);
}

//--------------------------------------------------------------------------
inline THREADID get_thread_from_packet(const idapin_packet_t &pkt)
{
  return thread_data_t::get_local_thread_id(pin_thid(pkt.data));
}

//--------------------------------------------------------------------------
static bool handle_packet(const idapin_packet_t *res)
{
  bool ret = false;
  idapin_packet_t ans;
  ans.size = 0;
  ans.code = PTT_ERROR;

  if ( res->code > PTT_END )
  {
    MSG("Unknown packet type %d\n", res->code);
    return false;
  }

  DEBUG(2, "(thread %d) Handle packet(%s)\n", int(thread_data_t::get_thread_id()), packet_names[res->code]);
  last_packet = packet_names[res->code];

  switch ( res->code )
  {
    case PTT_START_PROCESS:
      // does not return
      handle_start_process();
      break;
    case PTT_EXIT_PROCESS:
      MSG("Received EXIT PROCESS, exiting from process...\n");
      // does not return
      exit_process(0);
      break;
    case PTT_DEBUG_EVENT:
      ans.data = 0;
      if ( !events.empty() && process_started() )
      {
        DEBUG(2, "Total of %d events recorded\n", (uint32)events.size());
        ans.size = (uint32)events.size();
        ans.code = PTT_DEBUG_EVENT;
      }
      else
      {
        ans.size = 0;
        ans.code = PTT_ACK;
      }
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      break;
    case PTT_READ_EVENT:
      if ( pin_client_version < 6 )
      {
        pin_local_event_t evt;
        if ( !pop_debug_event(&evt, NULL) )
          evt.debev.eid = NO_EVENT;
        if ( evt.debev.eid != NO_EVENT )
          DEBUG(2, "Send event: %x (%d, %p)\n",
                evt.debev.eid, evt.debev.tid, pvoid(evt.debev.ea));
        ret = pin_send(&evt.debev, sizeof(evt.debev), __FUNCTION__);
      }
      // versions 6 and higher do not use event polling
      break;
    case PTT_MEMORY_INFO:
      ret = handle_memory_info();
      break;
    case PTT_READ_SYMBOLS:
      ret = handle_read_symbols();
      break;
    case PTT_READ_MEMORY:
      ans.data = 0;
      ans.code = PTT_READ_MEMORY;
      ret = handle_read_memory(res->data, res->size);
      break;
    case PTT_WRITE_MEMORY:
      ans.code = PTT_ACK;
      ans.size = handle_write_memory(res->data, res->size);
      ret = pin_send(&ans, sizeof(idapin_packet_t), "PTT_WRITE_MEMORY");
      break;
    case PTT_DETACH:
      MSG("Detach request processed\n");
      ans.data = 0;
      ans.code = PTT_ACK;
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      // this function is asynchronous
      detach_process();
      break;
    case PTT_PAUSE:
      // execution thread will be suspended later in control_cb()
      // here we just send ACK and set corresponding state
      DEBUG(2, "Pause request received...\n");
      ans.code = PTT_ACK;
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      prepare_pause();
      MSG("Pause request processed\n");
      break;
    case PTT_RESUME:
      DEBUG(2, "Resuming after event %x\n", int(res->data));
      ret = do_resume(&ans, *res);
      break;
    case PTT_COUNT_TRACE:
      ans.code = PTT_ACK;
      ans.data = instrumenter_t::tracebuf_size();
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      break;
    case PTT_READ_TRACE:
      ret = handle_read_trace();
      break;
    case PTT_CLEAR_TRACE:
      instrumenter_t::clear_trace();
      ret = true;
      break;
    case PTT_ADD_BPT:
      MSG("Adding software breakpoint at %p\n", pvoid(res->data));
      breakpoints.add_soft_bpt(ADDRINT(res->data));
      ans.code = PTT_ACK;
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      break;
    case PTT_DEL_BPT:
      MSG("Remove software breakpoint at %p\n", pvoid(res->data));
      breakpoints.del_soft_bpt(ADDRINT(res->data));
      ans.code = PTT_ACK;
      ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      break;
    case PTT_CAN_READ_REGS:
      {
        THREADID tid_local = get_thread_from_packet(*res);
        thread_data_t *tdata = thread_data_t::find_thread_data(tid_local);
        int cls = res->size;
        ans.data = tdata == NULL ? 0 : tdata->available_regs(cls);
        ans.code = ans.data != 0 ? PTT_ACK : PTT_ERROR;
        ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      }
      break;
    case PTT_READ_REGS:
      {
        THREADID tid = get_thread_from_packet(*res);
        pin_register_class_t cls = pin_register_class_t(res->size);
        ret = handle_read_regs(tid, cls);
      }
      break;
    case PTT_GET_SEGBASE:
      {
        idapin_segbase_packet_t *pkt = (idapin_segbase_packet_t *)res;
        THREADID tid_local = thread_data_t::get_local_thread_id(pkt->tid());
        ADDRINT base;
        if ( get_segbase(&base, tid_local, pkt->value()) )
        {
          ans.code = PTT_ACK;
          ans.data = base;
          DEBUG(2, "Get segment base(%x, %x): %p\n",
                pkt->tid(), int(pkt->value()), pvoid(base));
        }
        else
        {
          DEBUG(2, "Get segment base(%x, %x) - FAILED\n",
                pkt->tid(), int(pkt->value()));
          ans.code = PTT_ERROR;
        }
        ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      }
      break;
    case PTT_SET_TRACE:
      {
        ans.code = PTT_ACK;
        uint32 trace_types = (uint32)res->data;
        MSG("Set trace to %d\n", trace_types);
        if ( (trace_types & TF_SET_TRACE_SEGS) != 0 && res->size != 0 )
        { // get trace intervals (res->size contains number of intervals)
          ssize_t psize = res->size * sizeof(mem_interval_t);
          mem_interval_t *ivs = (mem_interval_t *)get_io_buff(psize);
          if ( ivs != NULL
            && pin_recv(cli_socket, ivs, psize, "trace_intervals") == psize )
          {
            instrumenter_t::add_trace_intervals(res->size, ivs);
          }
          else
          {
            ans.code = PTT_ERROR;
          }
        }
        instrumenter_t::update_instrumentation(trace_types);
        ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      }
      break;
    case PTT_SET_OPTIONS:
      ans.code = PTT_ACK;
      if ( pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__) )
        ret = handle_limits();
      break;
    case PTT_STEP:
      ans.code = PTT_ACK;
      if ( pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__) )
      {
        breakpoints.set_step(get_thread_from_packet(*res));
        ret = true;
      }
      break;
    case PTT_THREAD_SUSPEND:
      ans.code = PTT_ACK;
      if ( pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__) )
      {
        THREADID tid = get_thread_from_packet(*res);
        thread_data_t *tdata = thread_data_t::find_thread_data(tid);
        if ( tdata == NULL )
        {
          ans.code = PTT_ERROR;
          ret = false;
        }
        else
        {
          tdata->suspend();
          ret = true;
        }
      }
      break;
    case PTT_THREAD_RESUME:
      ans.code = PTT_ACK;
      if ( pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__) )
      {
        THREADID tid = get_thread_from_packet(*res);
        thread_data_t *tdata = thread_data_t::find_thread_data(tid);
        if ( tdata == NULL )
        {
          ans.code = PTT_ERROR;
          ret = false;
        }
        else
        {
          tdata->resume();
          ret = true;
        }
      }
      break;
    case PTT_CHANGE_REGVALS:
      {
        ans.code = PTT_ACK;
        idapin_regvals_packet_t *pkt = (idapin_regvals_packet_t *)res;
        // read register values
        ssize_t psize = sizeof(pin_regval_t) * pkt->count();
        pin_regval_t *values = (pin_regval_t *)get_io_buff(psize);
        if ( pin_recv(cli_socket, values, psize, "register values") != psize
          || !instrumenter_t::write_regs(pkt->tid(), pkt->count(), values) )
        {
          ans.code = PTT_ERROR;
        }
        ret = pin_send(&ans, sizeof(idapin_packet_t), __FUNCTION__);
      }
      break;
    default:
      MSG("UNKNOWN PACKET RECEIVED WITH CODE %d\n", res->code);
      break;
  }
  DEBUG(4, "LAST PACKET WAS %s\n", last_packet);
  return ret;
}

//--------------------------------------------------------------------------
static bool read_handle_packet(idapin_packet_t *res)
{
  idapin_packet_t ipack;
  if ( res == NULL )
    res = &ipack;
  DEBUG(4, "Receiving packet, expected %d bytes...\n",(uint32)sizeof(*res));

  if ( events.can_send_event() )
  {
    // every 10ms try to send event
    while ( !events.send_event(NULL) )
    {
      if ( listener_uid == PIN_ThreadUid() && PIN_IsProcessExiting() )
         return false;
      if ( pin_sockwait(10) )
        break;
    }
  }

  ssize_t bytes = pin_recv(cli_socket, res, sizeof(*res), "read_handle_packet");
  if ( bytes == -1 )
  {
    error_msg("recv");
    return false;
  }

  if ( bytes == 0 )
  {
    MSG("Connection closed by peer, exiting...\n");
    exit_process(0);
  }

  if ( !handle_packet(res) )
  {
    MSG("Error handling %s packet, exiting...\n", last_packet);
    exit_process(0);
  }
  return true;
}

//--------------------------------------------------------------------------
static bool handle_packets(int total, pin_event_id_t until_ev)
{
  int packets = 0;
  while ( total == -1 || packets++ < total )
  {
    idapin_packet_t res;
    if ( !read_handle_packet(&res) )
      return false;
    if ( res.code == PTT_RESUME )
    {
      pin_event_id_t last_ev = pin_event_id_t(res.data);
      if ( until_ev != NO_EVENT && last_ev == until_ev )
      {
        MSG("Expected resume packet, received (ev=%x)\n", int(last_ev));
        break;
      }
    }
  }

  if ( total == packets )
    DEBUG(2, "Maximum number of packets reached, exiting from handle_packets...\n");
  else
    DEBUG(2, "Expected packet received, exiting from handle_packets...\n");

  return true;
}

//--------------------------------------------------------------------------
// Start communication with IDA
static bool listen_to_ida(void)
{
  // initialize the socket and connect to ida
  if ( !init_socket() )
  {
    DEBUG(2, "listen_to_ida: init_socket() failed!\n");
    return false;
  }

  MSG("CONNECTED TO IDA\n");

  // Handle the 1st packets, PTT_START_PROCESS should be one of them:
  // this request leads to installing PIN callbacks and calling
  // PIN_StartProgram() which never returns.
  // The next portion of packets (variable number, until resume to
  // PROCESS_START event) will be handled in the application start
  // callback. Then we serve packets synchronously by callback/analysis
  // routines until the separate internal thread (listener) becomes active.
  // Finally, the rest of packets will be served by the listened thread.
  bool ret = handle_packets(5);

  // normally we should never reach this point: it could happen
  // if there was no PTT_START_PROCESS request among the first 5 packets
  MSG("Exiting from listen_to_ida\n");

  return ret;
}

//--------------------------------------------------------------------------
static void open_console(void)
{
#ifdef _WIN32
  if ( WINDOWS::AllocConsole() )
  { //-V:freopen:530 The return value of function 'freopen' is required to be utilized
    // in 32bit mode PIN runtime doesn't handle correctly freopen("CONOUT$", ...
    // (redirects standard output to file "CONOUT$" instead of console)
    // so do not call freopen() for in case of 32bit here because it looks like
    // the console output works even better without these calls
#if defined(PIN_64)
    if ( freopen("CONIN$", "rb", stdin) == NULL )
      error_msg("CONIN");
    if ( freopen("CONOUT$", "wb", stdout) == NULL )
      error_msg("CONOUT");
    if ( freopen("CONOUT$", "wb", stderr) == NULL )
      error_msg("stderr -> CONOUT$");
#endif
    std::ios::sync_with_stdio();
  }
#endif
}

//--------------------------------------------------------------------------
static INT32 usage()
{
  fprintf(stderr, "Pin Tool to communicate with IDA's debugger\n");
  fprintf(stderr, "\n%s\n", KNOB_BASE::StringKnobSummary().c_str());
  return -1;
}

//--------------------------------------------------------------------------
int main(int argc, char * argv[])
{
  // Initialize pin command line
  if ( PIN_Init(argc, argv) )
  {
    MSG("PIN_Init call failed!\n");
    return usage();
  }

  int value = knob_debug_mode.Value();
  if ( value <= 0 )
  {
    const char *envval = getenv("IDAPIN_DEBUG");
    if ( envval != NULL )
      value = atoi(envval);
  }
  if ( value > 0 )
  {
    debug_level = value;
    open_console();
    MSG("IDA PIN Tool version $Revision: #159 $\nInitializing PIN tool...\n\n");
  }

  DEBUG(2, "IDA PIN Tool started (debug level=%d)\n", debug_level);
  // Connect to IDA's debugger; it only returns in case of error
  if ( !listen_to_ida() )
  {
    DEBUG(2, "listen_to_ida() failed\n");
  }

  return 0;
}

//--------------------------------------------------------------------------
// Implementation of local classes
//--------------------------------------------------------------------------
int thread_data_t::thread_cnt = 0;
int thread_data_t::active_threads_cnt = 0;
int thread_data_t::suspeded_cnt = 0;
thread_data_t::thrdata_map_t thread_data_t::thr_data;
std::map <pin_thid, THREADID> thread_data_t::local_tids;
bool thread_data_t::thr_data_lock_inited = false;
PIN_LOCK thread_data_t::thr_data_lock;
PIN_LOCK thread_data_t::meminfo_lock;
bool thread_data_t::meminfo_changed = false;

//--------------------------------------------------------------------------
// thr_data_lock should be acquired by the caller
inline thread_data_t::thread_data_t()
  : ctx(NULL), restarted_at(BADADDR),
    ext_tid(NO_THREAD), state_bits(0),
    ctx_valid(false), ctx_changed(false), can_change_regs(false), susp(false),
    ev_handled(false), started(false), is_phys(false), is_stoppable(false)
{
  PIN_SemaphoreInit(&thr_sem);
  PIN_SemaphoreSet(&thr_sem);
  PIN_InitLock(&ctx_lock);
#ifdef _WIN32
  tibbase = NULL;
  nt_tib.StackBase = NULL;
  nt_tib.StackLimit = NULL;
#endif
  ++thread_cnt;
  DEBUG(2, "Thread data created (#threads=%d)\n", thread_cnt);
}

//--------------------------------------------------------------------------
// thr_data_lock should be acquired by the caller
inline thread_data_t::~thread_data_t()
{
  delete ctx;
  local_tids.erase(ext_tid);
#ifdef _WIN32
  tibbase = NULL;
#endif
  --thread_cnt;
  DEBUG(2, "Thread data deleted (#threads=%d)\n", thread_cnt);
}

//--------------------------------------------------------------------------
inline void thread_data_t::suspend()
{
  sema_clear(&thr_sem);
  susp = true;
  janitor_for_pinlock_t plj(&thr_data_lock);
  ++suspeded_cnt;
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_excp_handled(bool val)
{
  DEBUG(3, "thread_data_t::set_excp_handled(%d/%d)\n", ext_tid, val);
  ev_handled = val;
}

//--------------------------------------------------------------------------
// This function suspends frosen thread
// (should be called only from analysis routine)
inline void thread_data_t::wait()
{
  // do not suspend thread if listener thread has not started yet
  if ( listener_ready )
    sema_wait(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::resume()
{
  susp = false;
  janitor_for_pinlock_t plj(&thr_data_lock);
  --suspeded_cnt;
  sema_set(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::save_ctx(const CONTEXT *src_ctx, bool can_change)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  save_ctx_nolock(src_ctx, can_change);
}

//--------------------------------------------------------------------------
inline void thread_data_t::save_ctx_nolock(const CONTEXT *src_ctx, bool can_change)
{
  DEBUG(3, "%d/%x: save thread context: ip=%p\n", ext_tid, ext_tid, (void*)get_ctx_ip(src_ctx));
  PIN_SaveContext(src_ctx, get_ctx());
  ctx_changed = false;
  ctx_valid = true;
  is_phys = false;
  can_change_regs = can_change;
}

//--------------------------------------------------------------------------
// This function stores thread context and calculates thread-specific segments
// (stack, TIB, stack page guard).
// The ONLY PLACE it can be called from is an analysis routine
// inside the current thread because PIN modifies TIB and can provide
// incorrect stack limits when called from callbacks or another threads
// (including internal ones)
inline bool thread_data_t::save_curr_thread_ctx(const CONTEXT *src_ctx)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  save_ctx_nolock(src_ctx);

  bool ok = true;
#ifdef _WIN32
  ADDRINT curr_sp = PIN_GetContextReg(ctx, REG_STACK_PTR);
  if ( curr_sp > stack_top() || curr_sp < stack_bottom() )
  { // no valid stack limits, try to refresh
    set_meminfo_changed(true);
    nt_tib.StackBase = NULL;
    nt_tib.StackLimit = NULL;
    if ( tibbase == NULL )
      tibbase = WINDOWS::NtCurrentTeb();

    size_t read_bytes = PIN_SafeCopy(&nt_tib, tibbase, sizeof(nt_tib));
    // additional test: verify that TIB->Self contains the TIB's linear address
    if ( read_bytes != sizeof(WINDOWS::_NT_TIB) || nt_tib.Self != tibbase )
    {
      MSG("Bad TIB structure for thread %x at addr %p\n", ext_tid, tibbase);
      ok = false;
    }
    else
    {
      if ( curr_sp > stack_top() || curr_sp < stack_bottom() )
      {
        DEBUG(2, "%x: bad TIB stack [%p,%p] desn't contain SP value %p\n",
                  ext_tid, nt_tib.StackLimit, nt_tib.StackBase, pvoid(curr_sp));
        ok = false;
      }
    }
  }
#endif
  return ok;
}

//--------------------------------------------------------------------------
inline bool thread_data_t::is_meminfo_changed()
{
  janitor_for_pinlock_t plj(&meminfo_lock);
  return meminfo_changed;
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_meminfo_changed(bool val)
{
  DEBUG(2, "set_meminfo_changed %d -> %d\n", meminfo_changed, val);
  janitor_for_pinlock_t plj(&meminfo_lock);
  meminfo_changed = val;
}

//--------------------------------------------------------------------------
inline void thread_data_t::add_all_thread_areas(pin_meminfo_vec_t *miv)
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  for ( thrdata_map_t::iterator p = thr_data.begin(); p != thr_data.end(); ++p )
    p->second->add_thread_areas(miv);
}

//--------------------------------------------------------------------------
bool thread_data_t::add_thread_areas(pin_meminfo_vec_t *miv)
{
#ifdef _WIN32
  janitor_for_pinlock_t plj(&ctx_lock);
  if ( stack_top() == 0 )
  {
    MSG("No valid stack limits for %x\n", ext_tid);
    return false;
  }
  // add TIB area, suppose the whole page is reserved for the TIB
  pin_memory_info_t tib_mi(ADDRINT(tibbase),
                           ADDRINT(tibbase) + get_mem_page_size(),
                           SEGPERM_READ | SEGPERM_WRITE);
  snprintf(tib_mi.name, sizeof(tib_mi.name), "TIB[%08X]", ext_tid);
  add_thread_segment(miv, tib_mi);

  pin_memory_info_t stk_mi(stack_bottom(), stack_top(),
                           SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC);
  snprintf(stk_mi.name, sizeof(stk_mi.name), "Stack[%08X]", ext_tid);
  add_thread_segment(miv, stk_mi);

  // Look for stack PAGE_GUARD
  ADDRINT ea_guard = stack_bottom() - get_mem_page_size();
  int prot;
  if ( get_win_segment_protection(&prot, ea_guard) && (prot & PAGE_GUARD) != 0 )
  {
    pin_memory_info_t gr_mi(ea_guard, ea_guard + get_mem_page_size(),
                             win_prot_to_ida_perm(prot));
    snprintf(gr_mi.name, sizeof(gr_mi.name), "Stack PAGE GUARD[%08X]", ext_tid);
    add_segment(miv, gr_mi);
  }
#endif
  return true;
}

//--------------------------------------------------------------------------
inline ssize_t thread_data_t::read_memory(void *dst, ADDRINT ea, size_t size)
{
  ssize_t read_bytes = PIN_SafeCopy(dst, pvoid(ea), size);
#ifdef _WIN32
  if ( read_bytes > 0 )
  {
    for ( thrdata_map_t::iterator p = thr_data.begin(); p != thr_data.end(); ++p )
      p->second->read_tibmem((char *)dst, ea, size);
  }
#endif
  return read_bytes;
}

//--------------------------------------------------------------------------
inline ssize_t thread_data_t::write_memory(ADDRINT ea, const void *src, size_t size)
{
  return PIN_SafeCopy(pvoid(ea), src, size);
}

#ifdef _WIN32
//--------------------------------------------------------------------------
// read a portion of memory from thread's TIB: we should take it from the saved
// area because PIN doesn't give correct TIB when accessed from internal threads
inline void thread_data_t::read_tibmem(char *dst, ADDRINT ea, size_t size) const
{
  ADDRINT end = ea + size;
  if ( ea >= tibend() || end <= tibstart() || stack_top() == 0 )
    return;
  int dst_off = 0;
  int src_off = 0;
  if ( ea <= tibstart() )
    dst_off = tibstart() - ea;
  else
    src_off = ea - tibstart();
  if ( end > tibend() )
    end = tibend();
  size_t cmn_size = end - (ea + dst_off);
  DEBUG(2, "read_tibmem(%p, %p, %d) TIB=(%p/%d): "
           "read from %p/%d and put it to %p stack: %p-%p\n",
           dst, pvoid(ea), int(size), tibbase, int(tibend()-tibstart()),
           pvoid(ea + src_off), int(cmn_size), dst + dst_off,
           pvoid(stack_bottom()), pvoid(stack_top()));
  memcpy(dst + dst_off, ((char *)&nt_tib) + src_off, cmn_size);
}
#endif

//--------------------------------------------------------------------------
inline void thread_data_t::set_ctx_reg(REG pinreg, ADDRINT regval)
{
  PIN_SetContextReg(get_ctx(), pinreg, regval);
}

//--------------------------------------------------------------------------
inline void thread_data_t::save_phys_ctx(const PHYSICAL_CONTEXT *phys_ctx)
{
  set_ctx_reg(REG_GAX, PIN_GetPhysicalContextReg(phys_ctx, REG_GAX));
  set_ctx_reg(REG_GBX, PIN_GetPhysicalContextReg(phys_ctx, REG_GBX));
  set_ctx_reg(REG_GCX, PIN_GetPhysicalContextReg(phys_ctx, REG_GCX));
  set_ctx_reg(REG_GDX, PIN_GetPhysicalContextReg(phys_ctx, REG_GDX));
  set_ctx_reg(REG_GSI, PIN_GetPhysicalContextReg(phys_ctx, REG_GSI));
  set_ctx_reg(REG_GDI, PIN_GetPhysicalContextReg(phys_ctx, REG_GDI));
  set_ctx_reg(REG_GBP, PIN_GetPhysicalContextReg(phys_ctx, REG_GBP));
  set_ctx_reg(REG_STACK_PTR, PIN_GetPhysicalContextReg(phys_ctx, REG_STACK_PTR));
  set_ctx_reg(REG_INST_PTR, PIN_GetPhysicalContextReg(phys_ctx, REG_INST_PTR));
#if defined(PIN_64)
  set_ctx_reg(REG_R8,  PIN_GetPhysicalContextReg(phys_ctx, REG_R8));
  set_ctx_reg(REG_R9,  PIN_GetPhysicalContextReg(phys_ctx, REG_R9));
  set_ctx_reg(REG_R10, PIN_GetPhysicalContextReg(phys_ctx, REG_R10));
  set_ctx_reg(REG_R11, PIN_GetPhysicalContextReg(phys_ctx, REG_R11));
  set_ctx_reg(REG_R12, PIN_GetPhysicalContextReg(phys_ctx, REG_R12));
  set_ctx_reg(REG_R13, PIN_GetPhysicalContextReg(phys_ctx, REG_R13));
  set_ctx_reg(REG_R14, PIN_GetPhysicalContextReg(phys_ctx, REG_R14));
  set_ctx_reg(REG_R15, PIN_GetPhysicalContextReg(phys_ctx, REG_R15));

  set_ctx_reg(REG_RFLAGS, PIN_GetPhysicalContextReg(phys_ctx, REG_RFLAGS));
#else
  set_ctx_reg(REG_EFLAGS, PIN_GetPhysicalContextReg(phys_ctx, REG_EFLAGS));
#endif
  set_ctx_reg(REG_SEG_CS, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_CS));
  set_ctx_reg(REG_SEG_DS, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_DS));
  set_ctx_reg(REG_SEG_ES, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_ES));
  set_ctx_reg(REG_SEG_FS, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_FS));
  set_ctx_reg(REG_SEG_GS, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_GS));
  set_ctx_reg(REG_SEG_SS, PIN_GetPhysicalContextReg(phys_ctx, REG_SEG_SS));
  FPSTATE fpstate;
  PIN_GetPhysicalContextFPState (phys_ctx, &fpstate);
  set_ctx_reg(REG_FPCW, fpstate.fxsave_legacy._fcw);
  set_ctx_reg(REG_FPSW, fpstate.fxsave_legacy._fsw);
  set_ctx_reg(REG_FPTAG, fpstate.fxsave_legacy._ftw);
  for ( int i = 0; i < 8; ++i )
  {
    const UINT8 *v = (const UINT8 *)&fpstate.fxsave_legacy._sts[i];
    DEBUG(2, "PHYS REG: ST%d = %s\n", i, hexval(v, 10));
    PIN_SetContextRegval(ctx, REG(REG_ST0+i), v);
  }

  set_ctx_reg(REG_MXCSR, fpstate.fxsave_legacy._mxcsr);
  for ( int i = 0; i <= PINREG_LAST_XMMREG - PINREG_XMM0; ++i )
  {
    const UINT8 *v = (const UINT8 *)&fpstate.fxsave_legacy._xmms[i];
    pin_regid_t idx = pin_regid_t(PINREG_XMM0 + i);
    REG regid = regidx_pintool2pin(idx);
    DEBUG(2, "PHYS REG: %s = %s\n", regname_by_idx(idx), hexval(v, 16));
    PIN_SetContextRegval(ctx, regid, v);
  }
  ctx_changed = false;
  is_phys = true;
  ctx_valid = true;
}

//--------------------------------------------------------------------------
int thread_data_t::available_regs(int clsmask) const
{
  if ( !ctx_ok() || !is_ctx_valid() )
  {
    MSG("Thread %d: context is not available, thread is sleeping?\n", ext_tid);
    return 0;
  }
  if ( pin_client_version >= 5 )
    return clsmask;
  return clsmask & (PIN_RC_SEGMENTS|PIN_RC_GENERAL);
}

//--------------------------------------------------------------------------
inline bool thread_data_t::change_regval(REG regno, const UINT8 *regval)
{
  if ( !can_change_regs || is_phys )
  {
    MSG("Thread %d: can't change register values at this point\n", ext_tid);
    return false;
  }
  CONTEXT *context = get_ctx();
  PIN_REGISTER old_fpreg_value;
  if ( REG_is_mm(regno) )
  {
    // PIN doesn't suport MMX modification, change corresponding ST reg
    regno = REG(regno - REG_MM_BASE + REG_ST_BASE);
    if ( !REG_is_st(regno) )
      return false;
    PIN_GetContextRegval(context, regno, (UINT8 *)old_fpreg_value.byte);
    memcpy(old_fpreg_value.byte, regval, 8);    //-V512 underflow
    regval = old_fpreg_value.byte;
  }
  PIN_REGISTER oldreg;
  PIN_GetContextRegval(context, regno, (UINT8 *)oldreg.byte);
  int size = REG_Size(regno);
  if ( memcmp(regval, oldreg.byte, size) != 0 )
  {
    PIN_SetContextRegval(context, regno, regval);
    ctx_changed = true;
  }
  return true;
}

//--------------------------------------------------------------------------
inline void thread_data_t::continue_execution(int restarted_from)
{
  ctx_valid = false;
  if ( ctx_changed )
  {
    // we use PIN_ExecuteAt() to change register values
    // even in case IP should not be changed. After PIN_ExecuteAt()
    // our control routine will be called again for instructoin
    // pointed by IP: so we use "restarted_at" variable to preserve stopping
    // on the same instruction twice
    ctx_changed = false;
    is_stoppable = false;
    MSG("Thread %d: context is to be changed, apply changes\n", get_ext_tid());
  }
  else if ( (state_bits & RESTART_REQ) != 0 )
  {
    // should not wait on a semaphore inside an analysis routine because
    // PIN_StopApplicationThreads() can stop threads only on safe points.
    // So we make the thread stoppable: periodically call ExecuteAt() to pass
    // the execution control to the safe point just before the analysis routine
    // (and so give a chance PIN_StopApplicationThreads to reach the safe point)
    is_stoppable = true;
    suspender.wakeup(); // the thread is stoppable, activate the suspender
    DEBUG(2, "Thread %d: should be restarted\n", get_ext_tid());
  }
  else
  {
    is_stoppable = false;
    state_bits &= ~restarted_from;
    if ( state_bits == 0 )
      set_restart_ea(BADADDR);
    DEBUG(3, "Thread %d: normal return from routine\n", get_ext_tid());
    return;
  }
  CONTEXT *context = get_ctx();
  set_restart_ctx(context);
  state_bits |= restarted_from;
  PIN_ExecuteAt(context);     // never returns
}

//--------------------------------------------------------------------------
inline bool thread_data_t::can_break(ADDRINT addr) const
{
  return restarted_at != addr;
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_restart_ctx(const CONTEXT *context)
{
  set_restart_ea(get_ctx_ip(context));
}

//--------------------------------------------------------------------------
inline void thread_data_t::export_ctx(idapin_registers_t *regs)
{
  janitor_for_pinlock_t plj(&ctx_lock);
  get_context_regs(ctx, regs);
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_thread_data()
{
  return get_thread_data(get_thread_id());
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_thread_data(THREADID tid)
{
  return find_thread_data(tid, true);
}

//--------------------------------------------------------------------------
thread_data_t *thread_data_t::find_thread_data(THREADID tid, bool create)
{
  if ( !thr_data_lock_inited )
  {
    PIN_InitLock(&thr_data_lock);
    PIN_InitLock(&meminfo_lock);
    thr_data_lock_inited = true;
  }
  janitor_for_pinlock_t plj(&thr_data_lock);
  thrdata_map_t::iterator it = thr_data.find(tid);
  thread_data_t *tdata;
  if ( it != thr_data.end() )
  {
    tdata = it->second;
  }
  else
  {
    if ( !create )
      return NULL;
    MSG("Created thread data (%d)\n", tid);
    tdata = new thread_data_t;
    thr_data[tid] = tdata;
  }
  tdata->try_init_ext_tid(tid);
  return tdata;
}

//--------------------------------------------------------------------------
inline thread_data_t *thread_data_t::get_any_stopped_thread(THREADID *tid)
{
  for ( thrdata_map_t::iterator p = thr_data.begin();
        p != thr_data.end();
        ++p )
  {
    if ( p->second->suspended() )
    {
      *tid = p->first;
      return p->second;
    }
  }
  return NULL;
}

//--------------------------------------------------------------------------
inline bool thread_data_t::release_thread_data(THREADID tid)
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  thrdata_map_t::iterator it = thr_data.find(tid);
  if ( it == thr_data.end() )
    return false;
  DEBUG(2, "release_thread_data(%d, %d/%X)\n",
        tid, it->second->ext_tid, it->second->ext_tid);
  delete it->second;
  thr_data.erase(it);
  return true;
}

//--------------------------------------------------------------------------
inline THREADID thread_data_t::get_thread_id()
{
  return PIN_ThreadId();
}

//--------------------------------------------------------------------------
// There is no way to get external (OS-specific) thread id directly by local id.
// So we assume the control is inside the same thread here (as should be normaly).
// If it's not so - left external id undefined in hope to be more lucky later.
inline void thread_data_t::try_init_ext_tid(THREADID local_tid)
{
  if ( ext_tid == NO_THREAD )
  {
    if ( local_tid == get_thread_id() )
    {
      set_ext_tid(local_tid, PIN_GetTid());
      DEBUG(2, "init ext TID for %d: %d/%X\n", local_tid, ext_tid, ext_tid);
    }
    else
    {
      MSG("try_init_ext_tid(%d) failed inside %d\n",
               int(local_tid), int(get_thread_id()));
    }
  }
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_ext_tid(THREADID local_tid, pin_thid tid)
{
  ext_tid = tid;
  local_tids[tid] = local_tid;
}

//--------------------------------------------------------------------------
inline pin_thid thread_data_t::get_ext_thread_id(THREADID local_tid)
{
  thread_data_t *tdata = find_thread_data(local_tid);
  return tdata == NULL ? NO_THREAD : tdata->ext_tid;
}

//--------------------------------------------------------------------------
inline THREADID thread_data_t::get_local_thread_id(pin_thid tid_ext)
{
  std::map <pin_thid, THREADID>::iterator it = local_tids.find(tid_ext);
  return it == local_tids.end() ? INVALID_THREADID: it->second;
}

//--------------------------------------------------------------------------
inline void thread_data_t::restart_threads_for_suspend()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  for ( thrdata_map_t::iterator p = thr_data.begin(); p != thr_data.end(); ++p )
    p->second->restart_for_suspend();
}

//--------------------------------------------------------------------------
inline void thread_data_t::restart_for_suspend()
{
  state_bits |= RESTART_REQ;
  if ( susp )
    sema_set(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::resume_threads_after_suspend()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  for ( thrdata_map_t::iterator p = thr_data.begin(); p != thr_data.end(); ++p )
    p->second->resume_after_suspend();
}

//--------------------------------------------------------------------------
inline bool thread_data_t::has_stoppable_threads()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  for ( thrdata_map_t::iterator p = thr_data.begin(); p != thr_data.end(); ++p )
    if ( p->second->is_stoppable )
      return true;
  return false;
}

//--------------------------------------------------------------------------
inline void thread_data_t::resume_after_suspend()
{
  state_bits &= ~RESTART_REQ;
  is_stoppable = false;
  if ( susp )
    sema_clear(&thr_sem);
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_started()
{
  if ( started )
  {
    MSG("ERROR: set_started() called for already active thread %d\n", get_local_thread_id(ext_tid));
    return;
  }
  started = true;
  janitor_for_pinlock_t plj(&thr_data_lock);
  ++active_threads_cnt;
}

//--------------------------------------------------------------------------
inline void thread_data_t::set_finished() const
{
  if ( !started )
  {
    // if an application creates a huge amount of short-living threads
    // a THREAD_FINI callback can be issued without corresponding preceding
    // THREAD_START callback (a bug in PIN?)
    // (happened for pc_linux_pin_threads64.elf)
    MSG("THREAD FINI callback called for non-active thread %d (0x%x)\n", get_local_thread_id(ext_tid), ext_tid);
    return;
  }
  janitor_for_pinlock_t plj(&thr_data_lock);
  --active_threads_cnt;
}

//--------------------------------------------------------------------------
inline int thread_data_t::n_active_threads()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  return active_threads_cnt;
}

//--------------------------------------------------------------------------
inline bool thread_data_t::have_suspended_threads()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  return suspeded_cnt != 0;
}

//--------------------------------------------------------------------------
inline bool thread_data_t::all_threads_suspended()
{
  janitor_for_pinlock_t plj(&thr_data_lock);
  return thread_cnt != 0 && suspeded_cnt == thread_cnt;
}

//--------------------------------------------------------------------------
ev_queue_t::ev_queue_t()
{
  init();
}

//--------------------------------------------------------------------------
void ev_queue_t::init()
{
  queue.clear();
  PIN_InitLock(&lock);
  last_retrieved_ev.debev.eid = NO_EVENT;
  symbols.clear();
  sym_size = 0;
}

//--------------------------------------------------------------------------
ev_queue_t::~ev_queue_t()
{
}

//--------------------------------------------------------------------------
inline void ev_queue_t::push_back(const pin_local_event_t &ev)
{
  add_ev(ev, false);
}

//--------------------------------------------------------------------------
inline void ev_queue_t::push_front(const pin_local_event_t &ev)
{
  add_ev(ev, true);
}

//--------------------------------------------------------------------------
// IDA expects PROCESS_ATTACH event to be sent after all THREAD_START events.
// A THREAD_START event can be emited only by thread_start_cb() which
// in turn may be called after PROCESS_ATTACH event. So we don't
// send PROCESS_ATTACH until all threads are reported or timeout (1sec) expired
inline uint32 get_initial_thread_count()
{
  static time_t started = 0;    //-V795 year 2038
  if ( started == 0 )
  {
    time(&started);
    ++started;
  }
  else
  {
    time_t curr;    //-V795 year 2038
    time(&curr);
    if ( curr > started )
      return 0;       // timeout (1sec): return minimal number
  }
#if defined(_MSC_VER) || PIN_BUILD_NUMBER < 65163
  return uint32(-1);  // No PIN_GetInitialThreadCount - return max possible val
#else
  return PIN_GetInitialThreadCount();
#endif
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::pop_front(pin_local_event_t *out_ev, bool *can_resume)
{
  janitor_for_pinlock_t ql_guard(&lock);
  if ( !queue.empty() )
  {
    // number of sent THREAD_START events (initially == 1 because main thread
    // doesn't need to be notified with THREAD_START)
    static uint32 n_started_threads = 1;
    *out_ev = queue.front();
    if ( out_ev->debev.eid == PROCESS_ATTACH )
    { // Send ATTACH only if all THREAD_START events have already been sent
      if ( n_started_threads < get_initial_thread_count() )
      { // not all THREAD_START events sent
        if ( queue.size() == 1 )
        {
          if ( can_resume )
            *can_resume = false;
          return false;
        }
        // move PROCESS_ATTACH event to the end of the queue
        // and take one from the front
        queue.pop_front();
        queue.push_back(*out_ev);
        *out_ev = queue.front();
      }
    }
    if ( out_ev->debev.eid == THREAD_START )
      ++n_started_threads;
    last_retrieved_ev = *out_ev;
    queue.pop_front();
    return true;
  }
  if ( can_resume )
    *can_resume = true;
  return false;
}

//--------------------------------------------------------------------------
inline void ev_queue_t::last_ev(pin_local_event_t *out_ev)
{
  janitor_for_pinlock_t ql_guard(&lock);
  *out_ev = last_retrieved_ev;
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::back(pin_local_event_t *out_ev)
{
  janitor_for_pinlock_t ql_guard(&lock);
  if ( !queue.empty() )
  {
    *out_ev = queue.back();
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
inline size_t ev_queue_t::size()
{
  janitor_for_pinlock_t ql_guard(&lock);
  return queue.size();
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::empty()
{
  return size() == 0;
}

//--------------------------------------------------------------------------
inline void ev_queue_t::add_ev(const pin_local_event_t &ev, bool front)
{
  DEBUG(3, "ev_queue_t::add_ev %x\n", int(ev.debev.eid));
  janitor_for_pinlock_t ql_guard(&lock);
  if ( front )
    queue.push_front(ev);
  else
    queue.push_back(ev);
  DEBUG(3, "ev_queue_t::add_ev ended\n");
}

//--------------------------------------------------------------------------
inline bool ev_queue_t::can_send_event() const
{
  return pin_client_version >= 6 && last_retrieved_ev.debev.eid == NO_EVENT;
}

//--------------------------------------------------------------------------
bool ev_queue_t::send_event(bool *can_resume)
{
  if ( pin_client_version < 6 )
    return !empty();
  pin_local_event_t evt;
  while ( pop_debug_event(&evt, can_resume) )
  {
    if ( evt.debev.eid != NO_EVENT )
    {
      static int pktno = 1;
      idapin_packet_t pkt(PTT_DEBUG_EVENT);
      pkt.size = evt.debev.eid;
      pkt.data = pktno++;
      if ( !pin_send(&pkt, sizeof(idapin_packet_t), __FUNCTION__)
        || !pin_send(&evt.debev, sizeof(evt.debev), __FUNCTION__) )
        break;
      DEBUG(2, "PACKET %d: sent event: %x (ea=%p, tid=%d/%d)\n", int(pkt.data),
            evt.debev.eid, pvoid(evt.debev.ea), evt.tid_local, evt.debev.tid);
      return true;
    }
  }
  last_retrieved_ev.debev.eid = NO_EVENT;
  return false;
}

//--------------------------------------------------------------------------
inline void ev_queue_t::add_symbol(const std::string &name, ea_t ea)
{
  janitor_for_pinlock_t ql_guard(&lock);
  symbols.resize(symbols.size() + 1);
  pin_symdef_t &sym = symbols.back();
  sym.set(name, ea);
  sym_size += sym.size();
}

//--------------------------------------------------------------------------
// return value should be freed
inline char *ev_queue_t::export_symbols(int *bufsize)
{
  janitor_for_pinlock_t ql_guard(&lock);
  char *buf = (char *)malloc(sym_size);
  if ( buf == NULL )
  {
    *bufsize = 0;
    return NULL;
  }
  char *ptr = buf;
  for ( size_t i = 0; i < symbols.size(); ++i )
    ptr = symbols[i].store(ptr);
  *bufsize = sym_size;
  sym_size = 0;
  symbols.clear();
  return buf;
}

//--------------------------------------------------------------------------
bool bpt_mgr_t::control_enabled = false;
//--------------------------------------------------------------------------
bpt_mgr_t::bpt_mgr_t()
{
  cleanup();
}

//--------------------------------------------------------------------------
bpt_mgr_t::~bpt_mgr_t()
{
  cleanup();
}

//--------------------------------------------------------------------------
void bpt_mgr_t::cleanup()
{
  bpts.clear();
  pending_bpts.clear();
  stepping_thread = INVALID_THREADID;
  need_reinst = false;
  PIN_InitLock(&bpt_lock);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::add_soft_bpt(ADDRINT at)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  addrset_t::iterator p = bpts.find(at);
  if ( p != bpts.end() )
    return;
  addrset_t::iterator pp = pending_bpts.find(at);
  if ( pp == pending_bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::add_soft_bpt(%p)\n", pvoid(at));
    pending_bpts.insert(at);
    need_reinst = true;
  }
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::del_soft_bpt(ADDRINT at)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  addrset_t::iterator p = bpts.find(at);
  if ( p != bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::del_soft_bpt(%p, installed)\n", pvoid(at));
    bpts.erase(p);
    need_reinst = true;
    return;
  }
  addrset_t::iterator pp = pending_bpts.find(at);
  if ( pp != pending_bpts.end() )
  {
    DEBUG(2, "bpt_mgr_t::del_soft_bpt(%p, pending)\n", pvoid(at));
    pending_bpts.erase(pp);
    need_reinst = true;
  }
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::have_bpt_at(ADDRINT addr)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  return have_bpt_at_nolock(addr);
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::have_bpt_at_nolock(ADDRINT addr)
{
  addrset_t::iterator p = bpts.find(addr);
  return p != bpts.end();
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::set_step(THREADID stepping_tid)
{
  janitor_for_pinlock_t plj(&bpt_lock);
  DEBUG(2, "bpt_mgr_t::set_step(tid=%d)\n", int(stepping_tid));
  stepping_thread = stepping_tid;
}

//--------------------------------------------------------------------------
bool bpt_mgr_t::prepare_resume()
{
  janitor_for_pinlock_t plj(&bpt_lock);
  update_ctrl_flag();
  bool ret = need_reinst;
  need_reinst = false;
  DEBUG(2, "bpt_mgr_t::prepare_resume -> (control_enabled=%d) %d\n",
                                              control_enabled, ret);
  return ret;
}

//--------------------------------------------------------------------------
inline bool bpt_mgr_t::need_control_cb() const
{
  return stepping_thread != INVALID_THREADID
      || break_at_next_inst
      || thread_data_t::have_suspended_threads()
      || !pending_bpts.empty();
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::update_ctrl_flag() const
{
  control_enabled = need_control_cb();
}

//--------------------------------------------------------------------------
// prepare suspend (don't acquire process_state_lock, it must be done by caller)
void bpt_mgr_t::prepare_suspend()
{
  if ( process_detached() || process_exiting() )
  {
    DEBUG(2, "bpt_mgr_t::prepare_suspend: detached/exiting - don't suspend\n");
  }
  else
  {
    DEBUG(2, "bpt_mgr_t::prepare_suspend\n");
    janitor_for_pinlock_t plj(&bpt_lock);
    control_enabled = true;
  }
}

//--------------------------------------------------------------------------
// The order of the analysis routines is VERY IMPORTANT: ctrl_rtn should
// be called before any other routine (IARG_CALL_ORDER = CALL_ORDER_FIRST),
// the second priority has bpt_rtn (CALL_ORDER_FIRST + 1) and all tracing
// routines have the lowest priority (CALL_ORDER_LAST)
//lint -e{1746} parameter 'ins' could be made const reference
void bpt_mgr_t::add_rtns(INS ins, ADDRINT ins_addr)
{
  DEBUG(3, "bpt_mgr_t::add_rtns (%p) -> %d\n", pvoid(ins_addr), int(control_enabled));
  // add the real instruction instrumentation
  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ctrl_rtn_enabled,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_CALL_ORDER, CALL_ORDER_FIRST,
                   IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ctrl_rtn,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_CALL_ORDER, CALL_ORDER_FIRST,
                   IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);

  janitor_for_pinlock_t plj(&bpt_lock);
  bool have_bpt;
  if ( stepping_thread != INVALID_THREADID
    || thread_data_t::have_suspended_threads()
    || !instrumenter_t::instr_state_ok() )
  {
    // reinstrumenter did not start really or
    // ctrl_rtn is active anyway so we will process pending breakpoints here
    addrset_t::iterator p = pending_bpts.find(ins_addr);
    if ( p != pending_bpts.end() )
    {
      pending_bpts.erase(p);
      bpts.insert(ins_addr);
      have_bpt = true;
      update_ctrl_flag();
      DEBUG(2, "Inject pending bpt at (%p), npending=%d, ctrl_clag=%d\n",
               pvoid(ins_addr), int(pending_bpts.size()), control_enabled);
    }
    else
    {
      have_bpt = have_bpt_at_nolock(ins_addr);
    }
  }
  else
  {
    // we are called, instrumenter state is Ok, so can assume jit cache has been
    // already cleaned and we can remove (move to permanent set) pending bpts
    // and recalculate ctrl_flag to deactivate ctrl_rtn as soon as possible
    addrset_t::iterator p = pending_bpts.begin();
    if ( p != pending_bpts.end() )
    {
      DEBUG(2, "Move %d pending breakpoints to permanent set\n",
                                      int(pending_bpts.size()));
      for ( ; p != pending_bpts.end(); ++p )
        bpts.insert(*p);
      pending_bpts.clear();
      update_ctrl_flag();
    }
    have_bpt = have_bpt_at_nolock(ins_addr);
  }
  if ( have_bpt )
  {
    DEBUG(2, "bpt_mgr_t::add_bpt_rtn (%p)\n", pvoid(ins_addr));
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bpt_rtn,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_CALL_ORDER, CALL_ORDER_FIRST + 1,
                     IARG_INST_PTR, IARG_CONST_CONTEXT, IARG_END);
  }
}

//--------------------------------------------------------------------------
ADDRINT bpt_mgr_t::ctrl_rtn_enabled()
{
  return control_enabled;
}

//--------------------------------------------------------------------------
void PIN_FAST_ANALYSIS_CALL bpt_mgr_t::ctrl_rtn(ADDRINT addr, const CONTEXT *ctx)
{
  breakpoints.do_ctrl(addr, ctx);
}

//--------------------------------------------------------------------------
inline void emit_thread_start_ev(THREADID tid, thread_data_t *tdata)
{
  pin_local_event_t ev(THREAD_START, tid, get_ctx_ip(tdata->get_ctx()));
  DEBUG(2, "THREAD START: %d AT %p\n", tid, pvoid(ev.debev.ea));
  tdata->set_started();
  do_suspend(ev);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::do_ctrl(ADDRINT addr, const CONTEXT *ctx)
{
  if ( process_exiting() )
    return;

  THREADID tid_local = thread_data_t::get_thread_id();
  DEBUG(3, "bpt_mgr_t::do_ctrl at %p (thread %d)\n", pvoid(addr), int(tid_local));

  thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);

  // save the current thread's context if the process is to be suspended
  if ( tdata->save_curr_thread_ctx(ctx) && !tdata->is_started() )
    emit_thread_start_ev(tid_local, tdata);

  // now process forthcoming stepping/pause if any
  // do nothing if the listener thread is not started yet
  ev_id_t eid = EV_NO_EVENT;
  {
    janitor_for_pinlock_t plj(&bpt_lock);
    if ( pending_bpts.find(addr) != pending_bpts.end() )
    {
      eid = EV_BPT;
      DEBUG(2, "Pending bpt at %p (thread %d)\n", pvoid(addr), int(tid_local));
    }
    else
    {
      if ( stepping_thread == tid_local )
      {
        DEBUG(2, "do_ctrl: SINGLE STEP %p (thread %d)\n", pvoid(addr), int(tid_local));
        if ( !have_bpt_at_nolock(addr) )
          eid = EV_SINGLE_STEP;
      }
      else
      {
        if ( break_at_next_inst )
        {
          // emit event only if there is no bpt at this address, otherwise
          // bpreakpoint will be emited by bpt_rtn
          if ( !have_bpt_at_nolock(addr) )
            eid = EV_INITIAL_STOP;
        }
      }
    }
  }

  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);

    if ( eid == EV_NO_EVENT && process_pause() )
      eid = EV_PAUSED;

    if ( eid != EV_NO_EVENT && tdata->can_break(addr) )
    {
      if ( !tdata->is_started() )
        emit_thread_start_ev(tid_local, tdata);
      emit_event(eid, addr, tid_local);
    }
  }

  // suspend thread if needed
  tdata->wait();
  app_wait(&run_app_sem);
  tdata->continue_execution(thread_data_t::RESTART_FROM_CTRL);
}

//--------------------------------------------------------------------------
void PIN_FAST_ANALYSIS_CALL bpt_mgr_t::bpt_rtn(ADDRINT addr, const CONTEXT *ctx)
{
  breakpoints.do_bpt(addr, ctx);
}

//--------------------------------------------------------------------------
inline void bpt_mgr_t::do_bpt(ADDRINT addr, const CONTEXT *ctx)
{
  if ( process_exiting() )
    return;

  THREADID tid_local = thread_data_t::get_thread_id();
  thread_data_t *tdata = thread_data_t::get_thread_data(tid_local);

  DEBUG(2, "do_bpt at %p (thread %d)\n", pvoid(addr), int(tid_local));

  // save the current thread's context if the process is to be suspended
  if ( tdata->save_curr_thread_ctx(ctx) && !tdata->is_started() )
    emit_thread_start_ev(tid_local, tdata);

  if ( tdata->can_break(addr) )
  {
    // now process the breakpoint if it really exists
    {
      janitor_for_pinlock_t process_state_guard(&process_state_lock);
      if ( have_bpt_at(addr) )
      {
        if ( tdata->save_curr_thread_ctx(ctx) && !tdata->is_started() )
          emit_thread_start_ev(tid_local, tdata);
        emit_event(EV_BPT, addr, tid_local);
      }
    }
  }
  else
  {
    DEBUG(2, "do_bpt: skip already handled instruction at %p\n", pvoid(addr));
  }

  // suspend thread if needed
  tdata->wait();
  app_wait(&run_app_sem);
  tdata->continue_execution(thread_data_t::RESTART_FROM_BPT|thread_data_t::RESTART_FROM_CTRL);
}

//--------------------------------------------------------------------------
// caller should acquire process_state_lock when calling this function
void bpt_mgr_t::emit_event(ev_id_t eid, ADDRINT addr, THREADID tid)
{
  struct bpt_ev_t
  {
    const char *name;
    pin_event_id_t id;
  };
  static const bpt_ev_t bpt_evs[] =
  {
    { "Paused",        PROCESS_SUSPEND },
    { "Single step",   STEP },
    { "Breakpoint",    BREAKPOINT },
    { "Initial break", PROCESS_ATTACH }
  };
  if ( eid != EV_NO_EVENT && !process_detached() && !process_exiting() )
  {
    {
      janitor_for_pinlock_t plj(&bpt_lock);
      break_at_next_inst = false;
      stepping_thread = INVALID_THREADID;
    }
    pin_thid ext_tid = thread_data_t::get_ext_thread_id(tid);
    MSG("%s at %p (thread %d/%d)\n", bpt_evs[eid].name, pvoid(addr), int(ext_tid), int(tid));

    pin_local_event_t ev(bpt_evs[eid].id, tid, addr);
    ev.debev.bpt.hea = BADADDR;
    ev.debev.bpt.kea = BADADDR;
    if ( ev.debev.eid == PROCESS_ATTACH )
      ev.debev.modinfo = start_ev.debev.modinfo;
    do_suspend(ev);
  }
}

//--------------------------------------------------------------------------
// different trace modes (used by IF-routines)
bool instrumenter_t::tracing_instruction = true;
bool instrumenter_t::tracing_bblock      = false;
bool instrumenter_t::tracing_routine     = false;
bool instrumenter_t::tracing_registers   = false;
bool instrumenter_t::log_ret_isns        = true;

instrumenter_t::instr_state_t
instrumenter_t::state = instrumenter_t::INSTR_STATE_INITIAL;

// already enabled instrumentations (TF_TRACE_... flags)
uchar instrumenter_t::instrumentations = 0;

// trace buffer
PIN_LOCK instrumenter_t::tracebuf_lock;
instrumenter_t::trc_deque_t instrumenter_t::trace_addrs;
PIN_SEMAPHORE instrumenter_t::tracebuf_sem;
// already recorded instructions
instrumenter_t::addr_deque_t instrumenter_t::all_addrs;
// limits
bool instrumenter_t::only_new_instructions = false;
instrumenter_t::ea_checker_t instrumenter_t::ea_checker;
uint32 instrumenter_t::enqueue_limit = 1000000;
const uint32 instrumenter_t::skip_limit = 1000000;
string instrumenter_t::image_name;

// flag: reinstrumenter thread actually started
bool instrumenter_t::reinstr_started = false;

#ifdef SEPARATE_THREAD_FOR_REINSTR
PIN_SEMAPHORE instrumenter_t::reinstr_sem;
PIN_THREAD_UID instrumenter_t::reinstr_uid;
#endif

//--------------------------------------------------------------------------
bool instrumenter_t::init()
{
#ifdef SEPARATE_THREAD_FOR_REINSTR
  // PIN_RemoveInstrumentation acquires vm lock - calling it when
  // a callback or analysis routine is suspended can cause deadlock
  // so create a separate thread for that
  PIN_SemaphoreInit(&reinstr_sem);
  sema_clear(&reinstr_sem);
  THREADID tid = PIN_SpawnInternalThread(reinstrumenter, NULL, 0, &reinstr_uid);
  if ( tid == INVALID_THREADID )
  {
    MSG("PIN_SpawnInternalThread(RemoveInstrumentation thread) failed\n");
    return false;
  }
#endif
  // Initialize the trace buffer semaphore
  PIN_SemaphoreInit(&tracebuf_sem);
  // And immediately set it
  sema_set(&tracebuf_sem);
  // Initialize the trace events list lock
  PIN_InitLock(&tracebuf_lock);
  ea_checker.trace_everything = false;
  return true;
}

//--------------------------------------------------------------------------
bool instrumenter_t::finish()
{
#ifdef SEPARATE_THREAD_FOR_REINSTR
  // terminate internal thread
  sema_set(&reinstr_sem);
#endif
  return true;
}

//--------------------------------------------------------------------------
bool instrumenter_t::wait_termination()
{
#ifdef SEPARATE_THREAD_FOR_REINSTR
  // wait for internal thread
  return reinstr_uid == INVALID_PIN_THREAD_UID
      || wait_for_thread_termination(reinstr_uid);
#else
  return true;
#endif
}

//--------------------------------------------------------------------------
void instrumenter_t::init_instrumentations()
{
  if ( !tracing_instruction && !tracing_bblock && !tracing_routine )
  {
    MSG("NOTICE: No tracing method selected, nothing will be recorded until some tracing method is selected.\n");
  }

  bool control_cb_enabled = breakpoints.need_control_cb();
  MSG("Init tracing "
      "%croutine%s, %cbblk, %cinstruction%s, %cregs, %cflow\n",
      tracing_routine       ? '+' : '-',
        (tracing_routine && log_ret_isns) ? "+retns" : "",
      tracing_bblock        ? '+' : '-',
      tracing_instruction   ? '+' : '-',
        (tracing_instruction && only_new_instructions) ? "/new only" : "",
      tracing_registers     ? '+' : '-',
      control_cb_enabled    ? '+' : '-');

  add_instrumentation(TF_TRACE_INSN);
  if ( tracing_bblock )
    add_instrumentation(TF_TRACE_BBLOCK);
  if ( tracing_routine )
    add_instrumentation(TF_TRACE_ROUTINE);
}

//--------------------------------------------------------------------------
void instrumenter_t::update_instrumentation(uint32 trace_types)
{
  bool do_reinit = (trace_types & ~TF_REGISTERS) != curr_trace_types();

  tracing_instruction = (trace_types & TF_TRACE_INSN) != 0;
  tracing_bblock = (trace_types & TF_TRACE_BBLOCK) != 0;
  tracing_routine = (trace_types & TF_TRACE_ROUTINE) != 0;
  tracing_registers = (trace_types & TF_REGISTERS) != 0;
  log_ret_isns = (trace_types & TF_LOG_RET) != 0;
  only_new_instructions = (trace_types & TF_ONLY_NEW_ISNS) != 0;
  ea_checker.trace_everything = (trace_types & TF_TRACE_EVERYTHING) != 0;
  if ( debug_level <= 1 )
    debug_level = ((trace_types & TF_LOGGING) != 0) ? 1 : 0;

  if ( do_reinit )
    reinit_instrumentations();
  else
    init_instrumentations();

  MSG("%sabling register values tracing...\n", tracing_registers ? "En" : "Dis");
}

//--------------------------------------------------------------------------
inline void instrumenter_t::reinit_instrumentations()
{
  MSG("Reinit instrumentations\n");

  if ( state != INSTR_STATE_INITIAL )
  {
    state = INSTR_STATE_NEED_REINIT;
#ifdef SEPARATE_THREAD_FOR_REINSTR
    if ( reinstr_started )
      sema_set(&reinstr_sem);
#else
    remove_instrumentations();
#endif
  }
  else
  {
    // first call: don't need reinistrumenting
    state = INSTR_STATE_OK;
  }
  init_instrumentations();
}

//--------------------------------------------------------------------------
inline void instrumenter_t::remove_instrumentations()
{
  state = INSTR_STATE_REINIT_STARTED;
  DEBUG(3, "PIN_RemoveInstrumentation called\n");
  PIN_RemoveInstrumentation();
  DEBUG(3, "PIN_RemoveInstrumentation ended\n");
  state = INSTR_STATE_OK;
  DEBUG(2, "JIT cache cleaned\n");
}

#ifdef SEPARATE_THREAD_FOR_REINSTR
//--------------------------------------------------------------------------
VOID instrumenter_t::reinstrumenter(VOID *)
{
  MSG("Reinstrumenter started (thread = %d)\n", thread_data_t::get_thread_id());

  reinstr_started = true;
#ifdef TRY_TO_SUPPORT_REATTACH
  while ( !process_exiting() )
#else
  while ( !(process_exiting() || process_detached()) )
#endif
  {
    if ( PIN_SemaphoreTimedWait(&reinstr_sem, 100) )
    {
      if ( !(process_exiting() || process_detached()) )
      {
        DEBUG(3, "GetVmLock\n");
        GetVmLock();
        remove_instrumentations();
        ReleaseVmLock();
        sema_clear(&reinstr_sem);
      }
    }
  }
  MSG("Reinstrumenter exited\n");
  reinstr_uid = INVALID_PIN_THREAD_UID;
}
#endif

//--------------------------------------------------------------------------
void instrumenter_t::add_instrumentation(trace_flags_t inst)
{
  if ( (instrumentations & inst) == 0 )
  {
    switch ( inst )
    {
      case TF_TRACE_INSN:
        // Register instruction_cb to be called to instrument instructions
        MSG("Adding instruction level instrumentation...\n");
        INS_AddInstrumentFunction(instruction_cb, 0);
        break;
      case TF_TRACE_BBLOCK:
        // Register trace_cb to be called to instrument basic blocks
        MSG("Adding trace level instrumentation...\n");
        TRACE_AddInstrumentFunction(trace_cb, 0);
        break;
      case TF_TRACE_ROUTINE:
        // Register routine_cb to be called to instrument routines
        MSG("Adding routine level instrumentation...\n");
        TRACE_AddInstrumentFunction(routine_cb, 0);
        break;
      default:
        MSG("Unknown instrumentation type %d!\n", inst);
        abort();
    }

    instrumentations |= inst;
  }
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new instruction is encountered
//lint -e{1746} parameter 'ins' could be made const reference
VOID instrumenter_t::instruction_cb(INS ins, VOID *)
{
  ADDRINT addr = INS_Address(ins);

  if ( tracing_instruction && check_address(addr) )
  {
    // Insert a call to ins_logic_cb before every instruction
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_enabled,
              IARG_FAST_ANALYSIS_CALL,
              IARG_CALL_ORDER, CALL_ORDER_LAST,
              IARG_INST_PTR, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_logic_cb,
              IARG_FAST_ANALYSIS_CALL,
              IARG_CALL_ORDER, CALL_ORDER_LAST,
              IARG_CONST_CONTEXT, IARG_INST_PTR,
              IARG_UINT32, tev_insn, IARG_END);
  }

  breakpoints.add_rtns(ins, addr);
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new basic block is encountered.
VOID instrumenter_t::trace_cb(TRACE trace, VOID *)
{
  // Visit every basic block in the trace
  for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) )
  {
    bool first = true;
    for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins) )
    {
      ADDRINT addr = INS_Address(ins);
      if ( check_address(addr) && add_bbl_logic_cb(ins, first) )
        first = false;
    }
  }
}

//--------------------------------------------------------------------------
// Pin calls this function when precompiles an application code
// every time a new basic block is encountered *BUT*
// we will use this callback for instrumenting routines instead of using the
// routine instrumentation API offered by the toolkit
VOID instrumenter_t::routine_cb(TRACE trace, VOID *)
{
  // Visit every basic block in the trace
  for ( BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl) )
  {
    for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins) )
      add_rtn_logic_cb(ins);
  }
}

//--------------------------------------------------------------------------
//lint -e{1746} parameter 'ins' could be made const reference
bool instrumenter_t::add_rtn_logic_cb(INS ins)
{
  if ( tracing_routine )
  {
    // handle both calls and push + ret like in the following example:
    //
    // push offset some_func
    // retn
    //
    if ( INS_IsCall(ins) || INS_IsRet(ins) )
    {
      // add the real instruction instrumentation
      INS_InsertIfCall(ins, IPOINT_TAKEN_BRANCH,
                       (AFUNPTR)rtn_enabled, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_TAKEN_BRANCH,
                       (AFUNPTR)rtn_logic_cb, IARG_FAST_ANALYSIS_CALL,
                       IARG_ADDRINT, INS_Address(ins),
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_BOOL, !INS_IsDirectCall(ins),
                       IARG_BOOL, INS_IsRet(ins),
                       IARG_END);
      return true;
    }
  }
  return false;
}

//--------------------------------------------------------------------------
// Insert a call to ins_logic_cb for every instruction which is either
// a call, branch, ret, syscall or invalid (i.e., UD2) and, also, to the
// 1st instruction in the basic block
//lint -e{1746} parameter 'ins' could be made const reference
bool instrumenter_t::add_bbl_logic_cb(INS ins, bool first)
{
  if ( tracing_bblock )
  {
    if ( (first || INS_IsBranchOrCall(ins) || INS_IsRet(ins) || INS_IsSyscall(ins) || !ins.is_valid()) )
    {
      pin_tev_type_t tev_type = tev_insn;
      if ( INS_IsCall(ins) )
        tev_type = tev_call;
      else if ( INS_IsRet(ins) )
        tev_type = tev_ret;

      // add the real instruction instrumentation
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)trc_enabled, IARG_INST_PTR, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_logic_cb, IARG_FAST_ANALYSIS_CALL,
              IARG_CONST_CONTEXT, IARG_INST_PTR, IARG_UINT32, (uint32)tev_type, IARG_END);
    }
    return true;
  }
  return false;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::ins_enabled(VOID *)
{
  return tracing_instruction;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::trc_enabled(VOID *)
{
  return tracing_bblock;
}

//--------------------------------------------------------------------------
ADDRINT instrumenter_t::rtn_enabled(VOID *)
{
  return tracing_routine;
}

//--------------------------------------------------------------------------
// This function is called before an instruction is executed
// (used for both instruction and bbl tracing modes)
VOID PIN_FAST_ANALYSIS_CALL instrumenter_t::ins_logic_cb(
        const CONTEXT *ctx,
        VOID *ip,
        pin_tev_type_t tev_type)
{
  if ( check_address((ADDRINT)ip, tev_type) )
    add_to_trace(ctx, (ADDRINT)ip, tev_type);
}

//--------------------------------------------------------------------------
// This function is called for every call/return instruction, here
// ins_ip    - address of instruction itself
// target_ip - address of target instruction our instruction passes control to
VOID PIN_FAST_ANALYSIS_CALL instrumenter_t::rtn_logic_cb(
        ADDRINT ins_ip,
        ADDRINT target_ip,
        BOOL /* is_indirect */,
        BOOL is_ret)
{
  if ( check_address(ins_ip) )
  {
    if ( is_ret )
    {
      if ( log_ret_isns )
        add_to_trace(ins_ip, tev_ret);
    }
    else
    {
      add_to_trace(ins_ip, tev_call);
    }
  }
  if ( !is_ret && check_address(target_ip, tev_insn) )
  {
    // record targets for call instructions. We should do this as they are
    // used by IDA for graph views. The optimal way would be to record only
    // indirect targets (is_indirect == TRUE) and instructions referenced
    // from outside (check_address(ins_ip) == FALSE)
    add_to_trace(target_ip, tev_insn);
  }
}

//--------------------------------------------------------------------------
uint32 instrumenter_t::curr_trace_types()
{
  uint32 types = 0;
  if ( tracing_instruction )
    types |= TF_TRACE_INSN;
  if ( tracing_bblock )
    types |= TF_TRACE_BBLOCK;
  if ( tracing_routine )
    types |= TF_TRACE_ROUTINE;
  return types;
}

//--------------------------------------------------------------------------
inline void instrumenter_t::add_to_trace(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type)
{
  DEBUG(3, "add_to_trace1: Adding instruction at %p\n", pvoid(ea));
  store_trace_entry(ctx, ea, tev_type);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::add_to_trace(ADDRINT ea, pin_tev_type_t tev_type)
{
  DEBUG(3, "add_to_trace2: Adding instruction at %p\n", pvoid(ea));

  store_trace_entry(NULL, ea, tev_type);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::store_trace_entry(
        const CONTEXT *ctx,
        ADDRINT ea,
        pin_tev_type_t tev_type)
{
  // wait until the tracebuf is read if it's full
  app_wait(&tracebuf_sem);

  if ( tracebuf_is_full() )
    prepare_and_wait_trace_flush();

  trc_element_t trc(PIN_GetTid(), ea, tev_type);
  if ( instrumenter_t::tracing_registers && ctx != NULL )
    get_context_regs(ctx, &trc.regs);

  janitor_for_pinlock_t plj(&tracebuf_lock);
  if ( only_new_instructions )
    register_recorded_insn(ea);
  trace_addrs.push_back(trc);
}

//--------------------------------------------------------------------------
inline size_t instrumenter_t::tracebuf_size()
{
  janitor_for_pinlock_t plj(&tracebuf_lock);
  return trace_addrs.size();
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::tracebuf_is_full()
{
  return tracebuf_size() >= enqueue_limit;
}

//--------------------------------------------------------------------------
// this funcion should be called by an application thread
// when the trace buffer becomes full
inline void instrumenter_t::prepare_and_wait_trace_flush()
{
  {
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    if ( process_state == APP_STATE_RUNNING )
    {
      DEBUG(2, "prepare_and_wait_trace_flush: generate TRACE_FULL event (trace size=%d)\n", int(trace_addrs.size()));
      pin_local_event_t event;
      event.debev.eid = TRACE_FULL;
      events.push_front(event);
      process_state = APP_STATE_WAIT_FLUSH;
      sema_clear(&tracebuf_sem);
    }
  }

  // pause the app until the trace is read -
  // client should send "RESUME" request then
  app_wait(&tracebuf_sem);
  DEBUG(2, "trce flush ended\n");
}

//--------------------------------------------------------------------------
int instrumenter_t::get_trace_events(idatrace_events_t *out_trc_events)
{
  out_trc_events->size = 0;
  janitor_for_pinlock_t plj(&tracebuf_lock);
  do
  {
    if ( trace_addrs.empty() )
      break;

    trc_element_t trc = trace_addrs.front();
    trace_addrs.pop_front();
    out_trc_events->trace[out_trc_events->size].tid = trc.tid;
    out_trc_events->trace[out_trc_events->size].ea = trc.ea;
    out_trc_events->trace[out_trc_events->size].type = trc.type;
    out_trc_events->trace[out_trc_events->size].registers = trc.regs;
  } while ( ++out_trc_events->size < TRACE_EVENTS_SIZE );
  return out_trc_events->size;
}

//--------------------------------------------------------------------------
inline void instrumenter_t::resume()
{
  sema_set(&tracebuf_sem);
}

//--------------------------------------------------------------------------
inline void instrumenter_t::clear_trace()
{
  janitor_for_pinlock_t plj(&tracebuf_lock);
  trace_addrs.clear();
}

//--------------------------------------------------------------------------
inline void instrumenter_t::register_recorded_insn(ADDRINT addr)
{
  all_addrs.push_front(addr);

  // just resize an array when memory limit is reached
  if ( all_addrs.size() >= skip_limit )
    all_addrs.resize(skip_limit);
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::insn_is_registered(ADDRINT addr)
{
  return std::find(all_addrs.begin(), all_addrs.end(), addr) != all_addrs.end();
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::check_address(ADDRINT addr)
{
  if ( break_at_next_inst )
    return true;

  return ea_checker.trace_everything || addrok(addr);
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::addrok(ADDRINT ea)
{
  if ( ea_checker.intervals.size() == 0 )
    return true;
  if ( ea > ea_checker.curr_iv->start )
  {
    if ( ea < ea_checker.curr_iv->end )
      return true;
    intvlist_t::const_iterator p = ea_checker.curr_iv;
    ++p;
    while ( p != ea_checker.intervals.end() && p->start <= ea )
    {
      if ( ea < p->end )
      {
        ea_checker.curr_iv = p;
        return true;
      }
      ++p;
    }
  }
  else
  {
    for ( intvlist_t::const_iterator p = ea_checker.intervals.begin();
          p->start <= ea;
          ++p )
    {
      if ( ea < p->end )
      {
        ea_checker.curr_iv = p;
        return true;
      }
    }
  }
  return false;
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::check_address(ADDRINT addr, pin_tev_type_t type)
{
  if ( !check_address(addr) )
    return false;
  return type != tev_insn || !only_new_instructions || !insn_is_registered(addr);
}

//--------------------------------------------------------------------------
bool instrumenter_t::set_limits(
        bool only_new,
        uint32 enq_size,
        const char *imgname)
{
  only_new_instructions = only_new;
  enqueue_limit = enq_size;
  MSG("Setting maximum enqueue limit to %d, "
      "tracing image '%s', new instructions only %d\n",
       enqueue_limit, imgname, only_new_instructions);
  if ( image_name.empty() || image_name != imgname )
  {
    image_name = imgname;
    ea_checker.trace_everything = image_name == "*";
    if ( ea_checker.trace_everything )
      MSG("Image name set to '*', tracing everything!\n");
  }
  MSG("Correct configuration received\n");
  return true;
}

//--------------------------------------------------------------------------
void instrumenter_t::process_image(const IMG &img, bool as_default)
{
  // by default, we set the limits of the trace to the main binary
  mem_interval_t iv;
  iv.startea = IMG_LowAddress(img);
  iv.endea = IMG_HighAddress(img);

  static ADDRINT min_address = BADADDR;
  static ADDRINT max_address = BADADDR;
  if ( min_address != iv.startea || max_address != iv.endea )
  {
    string base_head  = pin_basename(IMG_Name(img).c_str());
    string base_image = pin_basename(image_name.c_str());
    transform(base_head.begin(), base_head.end(), base_head.begin(), ::tolower);
    transform(base_image.begin(), base_image.end(), base_image.begin(), ::tolower);
    if ( (as_default && image_name.empty()) || base_head == base_image )
    {
      min_address = iv.startea;
      max_address = iv.endea;
      if ( pin_client_version <= 2 )
      {
        add_trace_intervals(1, &iv);
      }
      else if ( ea_checker.intervals.size() == 0 )
      {
        // add empty interval
        iv.endea = iv.startea = BADADDR;
        add_trace_intervals(1, &iv);
      }
      MSG("Image boundaries: Min EA %p Max EA %p\n", pvoid(min_address), pvoid(max_address));
    }
  }
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::instr_state_ok()
{
  return state == INSTR_STATE_OK;
}

//--------------------------------------------------------------------------
inline void instrumenter_t::add_trace_intervals(int cnt, const mem_interval_t *ivs)
{
  ea_checker.intervals.resize(0);
  if ( cnt == 0 )
  {
    ea_checker.intervals.push_back(intv_t(0, BADADDR));
  }
  else
  {
    for ( int i = 0; i < cnt; ++i, ++ivs )
      ea_checker.intervals.push_back(intv_t(ivs->startea, ivs->endea));
    MSG("add trace intervals(%d):", int(ea_checker.intervals.size()));
    if ( !ea_checker.intervals.empty() )
    {
      for ( size_t i = 0; i < ea_checker.intervals.size(); ++i )
        MSG(" (%p-%p)", pvoid(ea_checker.intervals[i].start), pvoid(ea_checker.intervals[i].end));
    }
    MSG("\n");
  }
  ea_checker.curr_iv = ea_checker.intervals.begin();
}

//--------------------------------------------------------------------------
inline REG regidx_pintool2pin(pin_regid_t pintool_reg)
{
  switch ( pintool_reg )
  {
    case PINREG_ST0 : return REG_ST0;
    case PINREG_ST1 : return REG_ST1;
    case PINREG_ST2 : return REG_ST2;
    case PINREG_ST3 : return REG_ST3;
    case PINREG_ST4 : return REG_ST4;
    case PINREG_ST5 : return REG_ST5;
    case PINREG_ST6 : return REG_ST6;
    case PINREG_ST7 : return REG_ST7;
    case PINREG_CTRL: return REG_FPCW;
    case PINREG_STAT: return REG_FPSW;
    case PINREG_TAGS: return REG_FPTAG_FULL;
    // segment registers
    case PINREG_CS: return REG_SEG_CS;
    case PINREG_DS: return REG_SEG_DS;
    case PINREG_ES: return REG_SEG_ES;
    case PINREG_FS: return REG_SEG_FS;
    case PINREG_GS: return REG_SEG_GS;
    case PINREG_SS: return REG_SEG_SS;
    // general registers
    case PINREG_EAX: return REG_GAX;
    case PINREG_EBX: return REG_GBX;
    case PINREG_ECX: return REG_GCX;
    case PINREG_EDX: return REG_GDX;
    case PINREG_ESI: return REG_GSI;
    case PINREG_EDI: return REG_GDI;
    case PINREG_EBP: return REG_GBP;
    case PINREG_ESP: return REG_STACK_PTR;
    case PINREG_EIP: return REG_INST_PTR;
#ifdef PIN_64
    case PINREG64_R8 : return REG_R8;
    case PINREG64_R9 : return REG_R9;
    case PINREG64_R10: return REG_R10;
    case PINREG64_R11: return REG_R11;
    case PINREG64_R12: return REG_R12;
    case PINREG64_R13: return REG_R13;
    case PINREG64_R14: return REG_R14;
    case PINREG64_R15: return REG_R15;

    case PINREG_EFLAGS: return REG_RFLAGS;
#else
    case PINREG_EFLAGS: return REG_EFLAGS;
#endif
    // xmm registers
    case PINREG_MXCSR: return REG_MXCSR;
    case PINREG_XMM0: return REG_XMM0;
    case PINREG_XMM1: return REG_XMM1;
    case PINREG_XMM2: return REG_XMM2;
    case PINREG_XMM3: return REG_XMM3;
    case PINREG_XMM4: return REG_XMM4;
    case PINREG_XMM5: return REG_XMM5;
    case PINREG_XMM6: return REG_XMM6;
    case PINREG_XMM7: return REG_XMM7;

#ifdef PIN_64
    case PINREG_XMM8 : return REG_XMM8;
    case PINREG_XMM9 : return REG_XMM9;
    case PINREG_XMM10: return REG_XMM10;
    case PINREG_XMM11: return REG_XMM11;
    case PINREG_XMM12: return REG_XMM12;
    case PINREG_XMM13: return REG_XMM13;
    case PINREG_XMM14: return REG_XMM14;
    case PINREG_XMM15: return REG_XMM15;
#endif
    // mmx registers
    case PINREG_MMX0: return REG_MM0;
    case PINREG_MMX1: return REG_MM1;
    case PINREG_MMX2: return REG_MM2;
    case PINREG_MMX3: return REG_MM3;
    case PINREG_MMX4: return REG_MM4;
    case PINREG_MMX5: return REG_MM5;
    case PINREG_MMX6: return REG_MM6;
    case PINREG_MMX7: return REG_MM7;
    default:
      return REG_LAST;
  }
}

//--------------------------------------------------------------------------
inline const char *regname_by_idx(pin_regid_t pintool_reg)
{
  switch ( pintool_reg )
  {
    case PINREG_ST0 : return "REG_ST0";
    case PINREG_ST1 : return "REG_ST1";
    case PINREG_ST2 : return "REG_ST2";
    case PINREG_ST3 : return "REG_ST3";
    case PINREG_ST4 : return "REG_ST4";
    case PINREG_ST5 : return "REG_ST5";
    case PINREG_ST6 : return "REG_ST6";
    case PINREG_ST7 : return "REG_ST7";
    case PINREG_CTRL: return "REG_CTRL";
    case PINREG_STAT: return "REG_STAT";
    case PINREG_TAGS: return "REG_TAGS";
    // segment registers
    case PINREG_CS: return "REG_SEG_CS";
    case PINREG_DS: return "REG_SEG_DS";
    case PINREG_ES: return "REG_SEG_ES";
    case PINREG_FS: return "REG_SEG_FS";
    case PINREG_GS: return "REG_SEG_GS";
    case PINREG_SS: return "REG_SEG_SS";
    // general registers
    case PINREG_EAX: return "REG_GAX";
    case PINREG_EBX: return "REG_GBX";
    case PINREG_ECX: return "REG_GCX";
    case PINREG_EDX: return "REG_GDX";
    case PINREG_ESI: return "REG_GSI";
    case PINREG_EDI: return "REG_GDI";
    case PINREG_EBP: return "REG_GBP";
    case PINREG_ESP: return "REG_STACK_PTR";
    case PINREG_EIP: return "REG_INST_PTR";
#ifdef PIN_64
    case PINREG64_R8 : return "REG_R8";
    case PINREG64_R9 : return "REG_R9";
    case PINREG64_R10: return "REG_R10";
    case PINREG64_R11: return "REG_R11";
    case PINREG64_R12: return "REG_R12";
    case PINREG64_R13: return "REG_R13";
    case PINREG64_R14: return "REG_R14";
    case PINREG64_R15: return "REG_R15";
#endif
    case PINREG_EFLAGS: return "REG_EFLAGS";
    // xmm registers
    case PINREG_MXCSR: return "REG_MXCSR";
    case PINREG_XMM0: return "REG_XMM0";
    case PINREG_XMM1: return "REG_XMM1";
    case PINREG_XMM2: return "REG_XMM2";
    case PINREG_XMM3: return "REG_XMM3";
    case PINREG_XMM4: return "REG_XMM4";
    case PINREG_XMM5: return "REG_XMM5";
    case PINREG_XMM6: return "REG_XMM6";
    case PINREG_XMM7: return "REG_XMM7";

#ifdef PIN_64
    case PINREG_XMM8 : return "REG_XMM8";
    case PINREG_XMM9 : return "REG_XMM9";
    case PINREG_XMM10: return "REG_XMM10";
    case PINREG_XMM11: return "REG_XMM11";
    case PINREG_XMM12: return "REG_XMM12";
    case PINREG_XMM13: return "REG_XMM13";
    case PINREG_XMM14: return "REG_XMM14";
    case PINREG_XMM15: return "REG_XMM15";
#endif
    // mmx registers
    case PINREG_MMX0: return "REG_MMX0";
    case PINREG_MMX1: return "REG_MMX1";
    case PINREG_MMX2: return "REG_MMX2";
    case PINREG_MMX3: return "REG_MMX3";
    case PINREG_MMX4: return "REG_MMX4";
    case PINREG_MMX5: return "REG_MMX5";
    case PINREG_MMX6: return "REG_MMX6";
    case PINREG_MMX7: return "REG_MMX7";
    default:
      return "REG_UNKNOWN";
  }
}

//--------------------------------------------------------------------------
inline bool instrumenter_t::write_regs(pin_thid tid, int cnt, const pin_regval_t *values)
{
  THREADID local_tid = thread_data_t::get_local_thread_id(tid);
  thread_data_t *tdata = thread_data_t::find_thread_data(local_tid);
  if ( tdata == NULL )
    return false;
  for ( int i = 0; i < cnt; ++i )
  {
    const pin_regval_t &v = values[i];
    pin_regid_t idx = pin_regid_t(v.regidx);
    REG pinreg = regidx_pintool2pin(idx);
    if ( pinreg != REG_LAST )
    {
      MSG("Write register %s: %s\n", regname_by_idx(idx), hexval((void *)v.regval, REG_Size(pinreg)));
      if ( !tdata->change_regval(pinreg, (const UINT8 *)v.regval) )
        return false;
    }
  }
  return true;
}

//--------------------------------------------------------------------------
suspender_t::suspender_t()
  : thread_uid(0), next_process_state(APP_STATE_NONE), state(IDLE)
{
  PIN_InitLock(&lock);
  PIN_SemaphoreInit(&sem);
}

//--------------------------------------------------------------------------
bool suspender_t::start()
{
  janitor_for_pinlock_t susp_lock_guard(&lock);
  if ( state != IDLE )
    return false;
  THREADID tid = PIN_SpawnInternalThread(thread_hnd, this, 0, &thread_uid);
  if ( tid == INVALID_THREADID )
  {
    MSG("PIN_SpawnInternalThread(suspender) failed\n");
    return false;
  }
  state = RUNNING;
  sema_clear(&sem);
  return true;
}

//--------------------------------------------------------------------------
bool suspender_t::finish()
{
  DEBUG(2, "suspender_t::finish\n");
  {
    janitor_for_pinlock_t susp_lock_guard(&lock);
    if ( state == IDLE )
      return false;
    state = EXITING;
    DEBUG(3, "suspender_t::finish: set semaphore\n");
    sema_set(&sem);
  }
  return true;
}

//--------------------------------------------------------------------------
bool suspender_t::wait_termination()
{
  bool ok = thread_uid == INVALID_PIN_THREAD_UID
         || wait_for_thread_termination(thread_uid);
  DEBUG(2, "suspender_t: terminated\n");
  state = IDLE;
  return ok;
}

//--------------------------------------------------------------------------
inline void suspender_t::stop_threads(const pin_local_event_t &ev)
{
  suspend_threads(STOPPING, ev);
  // not so necessary to wake up the suspender here - it will be done when the
  // control will reach one of the analysis routines (see continue_execution)
  // but doing this here can speed up the execution (see can_stop_app_threads)
  wakeup();
}

//--------------------------------------------------------------------------
inline void suspender_t::pause_threads()
{
  pin_local_event_t ev(PROCESS_SUSPEND);
  suspend_threads(PAUSING, ev);
  // wake up the suspender thread here: otherwise the program can be sleeping
  // somewhere inside a syscall and the control will not reach in the near
  // future an analysis routine which would wakeup the suspender
  wakeup();
}

//--------------------------------------------------------------------------
void suspender_t::suspend_threads(state_t new_susp_state, const pin_local_event_t &ev)
{
  janitor_for_pinlock_t susp_lock_guard(&lock);
  if ( state == STOPPED || state == RESUMING )
  {
    MSG("ERROR: suspend_threads: unexpected state: %d\n", state);
    // should we enqueue the event here?
    return;
  }
  thread_data_t::restart_threads_for_suspend();
  next_process_state = APP_STATE_SUSPENDED;
  state = new_susp_state;
  add_pending_event(ev);
}

//--------------------------------------------------------------------------
inline void suspender_t::wakeup()
{
  sema_set(&sem);
}

//--------------------------------------------------------------------------
inline void suspender_t::add_pending_event(const pin_local_event_t &ev)
{
  pending_events.push_back(ev);
}

//--------------------------------------------------------------------------
bool suspender_t::resume_threads()
{
  janitor_for_pinlock_t susp_lock_guard(&lock);
  state = state == STOPPED ? RESUMING : RUNNING;
  sema_set(&sem);
  thread_data_t::resume_threads_after_suspend();
  DEBUG(2, "resume_threads ended, state = %d\n", state);
  return true;
}

//--------------------------------------------------------------------------
// separate internal thread for application suspending
VOID suspender_t::thread_hnd(VOID *ud)
{
  suspender_t *susp = (suspender_t *)ud;
  susp->thread_worker();
}

//--------------------------------------------------------------------------
// separate internal thread for application suspending
void suspender_t::thread_worker()
{
  THREADID sus_tid = thread_data_t::get_thread_id();
  MSG("Suspender started (thread = %d)\n", sus_tid);
  while ( true )
  {
    DEBUG(3, "Suspender: wait\n");
    sema_wait(&sem);
    DEBUG(3, "Suspender: wait ended, get lock\n");
    bool should_stop;
    {
      janitor_for_pinlock_t susp_lock_guard(&lock);
      DEBUG(3, "Suspender: wait Ok: state = %d\n", state);
      sema_clear(&sem);
      should_stop = state == STOPPING || state == PAUSING;
      if ( should_stop && !can_stop_app_threads() )
        continue;
    }
    if ( thread_data_t::n_active_threads() == 0 || PIN_IsProcessExiting() )
    {
      MSG("Suspender: the program seems to be exiting, exit from the thread\n");
      copy_pending_events(INVALID_THREADID);
      break;
    }
    if ( should_stop )
    {
      int curr_thr_age = thr_age;
      DEBUG(3, "Suspender: call PIN_StopApplicationThreads, age = %d\n", curr_thr_age);
      if ( PIN_StopApplicationThreads(sus_tid) )
      {
        DEBUG(3, "Suspender: after PIN_StopApplicationThreads %d\n", state);
        int t_count = PIN_GetStoppedThreadCount();
        DEBUG(2, "Suspender: %d application threads stopped\n", t_count);
        contexts.resize(t_count, NULL);
        janitor_for_pinlock_t process_state_guard(&process_state_lock);
        janitor_for_pinlock_t susp_lock_guard(&lock);
        if ( thr_age != curr_thr_age )
        {
          // avoid PIN bug: a crash when a new thread is created after
          // PIN_StopApplicationThreads and before PIN_GetStoppedThreadId
          DEBUG(2, "Suspender: Thread age changed: %d --> %d\n", curr_thr_age, thr_age);
          curr_thr_age = thr_age;
          PIN_ResumeApplicationThreads(sus_tid);
          continue;
        }
        ADDRINT curr_addr = BADADDR;
        THREADID curr_tid = INVALID_THREADID;
        for ( int i = 0; i < t_count; ++i )
        {
          THREADID tid = PIN_GetStoppedThreadId(i);
          if ( tid != INVALID_THREADID )
          {
            DEBUG(2, "Suspender: read context for thread %d\n", tid);
            CONTEXT *ctx = PIN_GetStoppedThreadWriteableContext(tid);
            if ( ctx != NULL )
            {
              thread_data_t *tdata = thread_data_t::find_thread_data(tid);
              if ( tdata != NULL )
              {
                tdata->save_ctx(ctx);
                contexts[i] = ctx;
              }
              if ( (signed)curr_addr == BADADDR )
              {
                curr_addr = get_ctx_ip(ctx);
                curr_tid = tid;
              }
            }
          }
        }
        if ( (state == STOPPING || state == PAUSING)
          && (signed)curr_addr != BADADDR )
        {
          process_state = next_process_state;
          state = STOPPED;
          MSG("Suspender: stopped at %p (thread %d)\n", pvoid(curr_addr), int(curr_tid));
          // move all events to listener queue
          copy_pending_events_nolock(curr_tid);
        }
        else
        { // can't stop, do resume
          MSG("ERROR: Suspender: could not stop (state=%d, addr=%p)\n", state, pvoid(curr_addr));
          state = RESUMING;
        }
      }
      else
      {
        MSG("ERROR: Suspender: PIN_StopApplicationThreads failed\n");
      }
    }
    janitor_for_pinlock_t process_state_guard(&process_state_lock);
    janitor_for_pinlock_t susp_lock_guard(&lock);
    if ( state == RESUMING || (state == EXITING && !contexts.empty()) )
    {
      if ( !pending_events.empty() && state != EXITING )
      {
        MSG("ERROR: Suspender: resume request when have pending events\n");
      }
      int t_count = PIN_GetStoppedThreadCount();
      if ( t_count != int(contexts.size()) )
      {
        MSG("ERROR: Suspender: wrong number of stopped threads: %d "
            "(expected %d)\n", t_count, int(contexts.size()));
      }
      else
      {
        // modify changed contexts
        for ( int i = 0; i < t_count; ++i )
        {
          if ( contexts[i] != NULL )
          {
            THREADID tid = PIN_GetStoppedThreadId(i);
            if ( tid != INVALID_THREADID )
            {
              thread_data_t *tdata = thread_data_t::find_thread_data(tid);
              if ( tdata != NULL && tdata->is_ctx_changed() )
              {
                DEBUG(2, "%d: registers changed: modify thread context\n", tid);
                PIN_SaveContext(tdata->get_ctx(), contexts[i]);
                tdata->set_restart_ctx(tdata->get_ctx());
              }
              tdata->discard_ctx();
            }
          }
        }
      }
      PIN_ResumeApplicationThreads(sus_tid);
      DEBUG(2, "Suspender: application threads resumed\n");
      state = RUNNING;
      process_state = APP_STATE_RUNNING;
      contexts.clear();
    }
    if ( state == EXITING )
    {
      state = IDLE;
      break;
    }
  }
  MSG("Suspender exited\n");
  thread_uid = INVALID_PIN_THREAD_UID;
}

//--------------------------------------------------------------------------
// PIN_StopApplicationThreads can not be invoked (hangs) if there is no working
// thread. Check that one of the following conditions is true:
// 1. At least one thread is suspended inside an analysis routine of bpt_mgr_t
// 2. There is a substantial pending event (e.g. BREAKPOINT, STEP). This
//    checking is added just to speed up the execution by mininizing number of
//    ExecuteAt() calls. (It's not quite necessary because such events sooner
//    or later lead to suspending in the analysis routines).
// 3. A pause request has been issued. This does not guarantee the existing of
//    an active thread and there is a risk of hang when a pause request is
//    issued just before the program termination (but otherwise we will not be
//    able to pause programs waiting on blocking syscalls)
// Note there is a thread_data_t::n_active_threads() function but we can't fully
// rely on it because there is no way to avoid a race condition: a thread
// can exit between n_active_threads() and PIN_StopApplicationThreads() calls
inline bool suspender_t::can_stop_app_threads() const
{
  if ( pending_events.empty() )
  {
    MSG("ERROR: Suspender: empty queue of pending events!\n");
    return false;
  }
  if ( state == PAUSING )
    return true;            // a pause request has been issued
  if ( thread_data_t::has_stoppable_threads() )
    return true;            // a thread is suspended inside an analysis routine
  event_list_t::const_iterator p;
  for ( p = pending_events.begin(); p != pending_events.end(); ++p )
    if ( p->debev.eid == BREAKPOINT || p->debev.eid == STEP )
      return true;          // there is a substantial pending event
  DEBUG(2, "Suspender: no substantial events - do not stop!\n");
  return false;
}

//--------------------------------------------------------------------------
inline void suspender_t::copy_pending_events(THREADID curr_tid)
{
  janitor_for_pinlock_t susp_lock_guard(&lock);
  return copy_pending_events_nolock(curr_tid);
}

//--------------------------------------------------------------------------
void suspender_t::copy_pending_events_nolock(THREADID curr_tid)
{
  while ( !pending_events.empty() )
  {
    pin_local_event_t &ev = pending_events.front();
    DEBUG(2, "Suspender: copy pending event(%x)\n", ev.debev.eid);
    if ( ev.tid_local == INVALID_THREADID )
      ev.tid_local = curr_tid;
    thread_data_t *td = thread_data_t::find_thread_data(ev.tid_local);
    if ( td != NULL )
    {
      ADDRINT ea = get_ctx_ip(td->get_ctx());
      if ( ADDRINT(ev.debev.ea) == ADDRINT(BADADDR) )
      {
        if ( ev.debev.eid != PROCESS_SUSPEND )
        {
          if ( ev.debev.eid != LIBRARY_UNLOAD
            && ev.debev.eid != THREAD_EXIT )
          {
            if ( curr_tid == INVALID_THREADID )
            {
              pending_events.pop_front();
              continue;
            }
            MSG("ERROR: Suspender: event(%x) - undefined EA "
                   "at addr %p\n", ev.debev.eid, pvoid(ea));
          }
        }
        ev.debev.ea = ea;
      }
      else
      {
        if ( ev.debev.ea != ea
          && ev.debev.eid != LIBRARY_LOAD
          && ev.debev.eid != LIBRARY_UNLOAD
          && ev.debev.eid != THREAD_EXIT )
        {
          if ( curr_tid == INVALID_THREADID )
          {
            pending_events.pop_front();
            continue;
          }
          MSG("ERROR: Suspender: bad event(%x) addr %p (expected %p)\n",
                         ev.debev.eid, pvoid(ev.debev.ea), pvoid(ea));
        }
      }
    }
    else
    {
      if ( ev.debev.eid != THREAD_EXIT )
      {
        if ( curr_tid == INVALID_THREADID )
        {
          pending_events.pop_front();
          continue;
        }
        MSG("ERROR: Suspender: no stopped thread for event(%x,%d,%p)\n",
                       ev.debev.eid, ev.tid_local, pvoid(ev.debev.ea));
      }
    }
    enqueue_event(ev);
    pending_events.pop_front();
  }
}

#if 0
//--------------------------------------------------------------------------
static void dump_sizes(void)
{
  MSG("Sizeof pin_module_info_t %d\n", sizeof(pin_module_info_t));
  MSG("Sizeof pin_e_breakpoint_t %d\n", sizeof(pin_e_breakpoint_t));
  MSG("Sizeof pin_e_exception_t %d\n", sizeof(pin_e_exception_t));
  MSG("Sizeof pin_local_event_t %d\n", sizeof(pin_local_event_t));
  MSG("Sizeof idapin_packet_t %d\n", sizeof(idapin_packet_t));
  MSG("Sizeof memimages_pkt_t %d\n", sizeof(memimages_pkt_t));
  MSG("Sizeof pin_memory_info_t %d\n", sizeof(pin_memory_info_t));
  MSG("Sizeof idamem_packet_t %d\n", sizeof(idamem_packet_t));
  MSG("Sizeof idamem_response_pkt_t %d\n", sizeof(idamem_response_pkt_t));
  MSG("Sizeof idapin_registers_t %d\n", sizeof(idapin_registers_t));
  MSG("Sizeof idatrace_data_t %d\n", sizeof(idatrace_data_t));
  MSG("Sizeof idatrace_events_t %d\n", sizeof(idatrace_events_t));
  MSG("Sizeof idabpt_packet_t %d\n", sizeof(idabpt_packet_t);
  MSG("Sizeof idalimits_packet_t %d\n", sizeof(idalimits_packet_t));
}
#endif
