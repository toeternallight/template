#ifndef DLTRACE_PLT_HOOK_HPP
#define DLTRACE_PLT_HOOK_HPP
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <stack>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include "elf_load.hpp"
#include "libdltrace/filter.hpp"
#include "log.hpp"
#include "thread_local.hpp"
#include "tracer.hpp"
extern "C" uint64_t plthook_return(void);
extern "C" void plt_hooker(void);
uint64_t get_plthook_return();
uint64_t get_plt_hooker();
extern uint64_t g_plthook_resolver_addr;
class PLThooker : public TraceProvider {
#ifdef CNPERF_UNIT_TEST
 public:  // NOLINT
#endif
  // thread-safe flag
  std::vector<std::atomic_flag> m_flags;
  // plthook data for a moudle
  struct hook_data 

{     uint64_t* got_tab;     uint64_t plt_addr;     uint64_t sym_size;     uint64_t sym_offset;     // the start of the relro     uint64_t relro_start;     // the end of the relro     uint64_t relro_size;     bool has_plt_sec;     void align();   }

;
  // hook data
  std::map<link_map *, hook_data> m_hook_datas;
  // vector of lib ingored
  std::vector<std::string> m_skip_libs;
  // set of func ingored
  std::set<std::string> m_skip_funcs;
  // save the addr of every symbol order by symbol_index
  std::vector<uint64_t> m_addr_vec;
  // save param and ret value type of the function by symbol_index
  std::vector<std::vector<TypeId>> m_filter_args_type;
  // map the moudle's baseaddr to the trace_filter for the moudle
  std::map<uint64_t, trace_filter> m_lib_addr_table;
  bool isSkipLib(const std::string &name);

 public:
  uint64_t getAddr(uint64_t &symbol_index, uint64_t func_index, link_map *l_map);
  // hook funcin
  uint64_t hookIn(uint64_t *ret_addr, uint64_t func_index, link_map *l_map, struct mcount_regs *argss);
  // hook funcout
  uint64_t hookOut(uint64_t *retval);
  void startHook();
  void stopHook();
  ~PLThooker();
  PLThooker();
};

extern PLThooker *hook;

bool initPLThook();
bool startPLThook();
void stopPLThook();
extern "C" uint64_t PLThookEntry(uint64_t *ret_addr, uint64_t func_index, link_map *l_map, struct mcount_regs *argss);
extern "C" uint64_t PLThookExit(uint64_t *retval);
#endif  // DLTRACE_PLT_HOOK_HPP
