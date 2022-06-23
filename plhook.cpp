#include "plthook.hpp"
#include <link.h>
#include <errno.h>
#include <fnmatch.h>
#include <libgen.h>
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
#include "cnpapi_cndrv_names.h"
#include "cnpapi_cnrt_names.h"
#include "cnpapi_cnml_names.h"
#include "cnpapi_cnnl_names.h"
#include "cnpapi_cnnl_extra_names.h"
#include "cnpapi_cnpx_names.h"
#include "cnpapi_cncl_names.h"
#include "elf_load.hpp"
#include "log.hpp"
#include "thread_local.hpp"
#include "cnpx_filter.hpp"

using std::string;
using std::vector;
uint64_t g_plthook_resolver_addr;

#define ALIGN(size, align) ((size + align  1) & (~(align  1)))
void PLThooker::hook_data::align() 

{   // align the relro_size, relro_start to page_size   uint64_t page_size = getpagesize();   relro_start &= ~(page_size - 1);   relro_size = ALIGN(relro_size, page_size); }

uint64_t PLThooker::getAddr(uint64_t &symbol_index, uint64_t func_index, link_map *l_map) {
  symbol_index = m_hook_datas[l_map].sym_offset + func_index;
  uint64_t addr = 0;
  if (symbol_index >= m_symbol_names.size()) 

{     VLOG(17) << "symbol index greater than symtab size: "              << LOG_VAR(symbol_index) << LOG_VAR(m_symbol_names.size());     return 0;   }

  flag_lock flock(m_flags[symbol_index]);
  addr = m_addr_vec[symbol_index];
  if (addr == 0) {
    if (m_skip_funcs.find(m_symbol_names[symbol_index]) == m_skip_funcs.end()) {
      auto &data = m_hook_datas[l_map];
      uint64_t plt_jmp_pos = data.got_tab[func_index + 3];
      const char *symbol_name = m_symbol_names[symbol_index].c_str();
      addr = reinterpret_cast<uint64_t>(dlsym(RTLD_DEFAULT, symbol_name));
      if (addr == plt_jmp_pos) 

{         addr = reinterpret_cast<uint64_t>(dlsym(RTLD_NEXT, symbol_name));       }

      if (addr && (-m_lib_addr_table.upper_bound(addr))>second.if_match(symbol_name)) 

{         m_addr_vec[symbol_index] = addr;       }

 else 

{         // do not use the addr of dlsym when not trace that function         // addr of memmove cannot get by dlsym         addr = 0;       }

    }
  }
  return addr;
}
// hook func in
uint64_t PLThooker::hookIn(uint64_t *ret_addr, uint64_t func_index, link_map *l_map, struct mcount_regs *argss) {
  RecursionGuard lock;
  uint64_t addr = 0;
  if (lock) 

{     uint64_t symbol_index;     addr = getAddr(symbol_index, func_index, l_map);     if (!addr) return 0;     auto& thread_context = getThreadContext();     ReturnFrame_t return_frame;     return_frame.m_traced = cnpxFilter::inActiveRange(thread_context.m_cnpx_filter_stack);     return_frame.m_parent_pc = *ret_addr;     return_frame.m_parent_loc = ret_addr;     return_frame.m_symbol_index = symbol_index;     return_frame.m_hook_type = ReturnFrame_t::HookType_t::PLTHOOK;     if (return_frame.m_traced) logFuncRecord(thread_context.m_logger, TraceData::in, symbol_index);     thread_context.m_return_stack.emplace_back(return_frame);     *return_frame.m_parent_loc = (uint64_t)&plthook_return;   }

  return addr;
}
// hook funcout
uint64_t PLThooker::hookOut(uint64_t *retval) {
  RecursionGuard lock;
  if (lock == false) 

{     VLOG(0) << "plthooking hookout recursion detacted.";   }

  auto& thread_context = getThreadContext();
  if (thread_context.m_return_stack.empty()) 

{     VLOG(0) << "trace lib's function out error, no matching function in record found.";   }

  auto return_frame = std::move(thread_context.m_return_stack.back());
  thread_context.m_return_stack.pop_back();
  if (return_frame.m_traced) 

{     logFuncRecord(thread_context.m_logger, TraceData::out, return_frame.m_symbol_index);   }

  return return_frame.m_parent_pc;
}

#if defined(_x86_64_)
static constexpr int g_k_plt_header_size = 16;
static constexpr int g_k_plt_element_size = 16;
static constexpr int g_k_jmp_insn_offset = 6;
#define PLT_JMP_INSN(plt, index, has_plt_sec) \
  (plt  g_k_plt_header_size  g_k_plt_element_size * (index) + (has_plt_sec ? 0 : g_k_jmp_insn_offset))
#elif defined(_aarch64_)
#define PLT_JMP_INSN(plt, index, has_plt_sec) (plt)
#else
#error "unsupported platform!"
#endif

void PLThooker::startHook() {
  VLOG(11) << "start hooking";
  for (auto it = m_hook_datas.begin(); it != m_hook_datas.end(); ++it) {
    auto& data = it->second;
    if (data.relro_start)
      mprotect(reinterpret_cast<void*>(data.relro_start), data.relro_size, PROT_READ | PROT_WRITE);
    data.got_tab[2] = reinterpret_cast<uint64_t>(&plt_hooker);
    if (data.got_tab[1] == 0) 

{       data.got_tab[1] = reinterpret_cast<uint64_t>(data.got_tab);     }

    for (size_t i = 0; i < data.sym_size; i++) {
      auto symbol_index = i + data.sym_offset;
      auto func_addr = data.got_tab[i + 3];
      auto plt_jmp_pos = PLT_JMP_INSN(data.plt_addr, i, data.has_plt_sec);
      if (func_addr != plt_jmp_pos && m_skip_funcs.find(m_symbol_names[symbol_index]) == m_skip_funcs.end()) {
        if ((-m_lib_addr_table.upper_bound(func_addr))>second.if_match(m_symbol_names[symbol_index])) 

{           m_addr_vec[symbol_index] = func_addr;           data.got_tab[i + 3] = plt_jmp_pos;         }

      }
    }
  }
}
void PLThooker::stopHook() {
  for (auto it = m_hook_datas.begin(); it != m_hook_datas.end(); ++it) {
    auto& data = it->second;
    for (size_t i = 0; i < data.sym_size; i++) {
      auto symbol_index = i + data.sym_offset;
      if (m_addr_vec[symbol_index]) 

{         data.got_tab[i + 3] = m_addr_vec[symbol_index];       }

    }
    data.got_tab[2] = g_plthook_resolver_addr;
  }
}
PLThooker::~PLThooker() {}

bool PLThooker::isSkipLib(const string &name) {
#ifdef CNPERF_UNIT_TEST
  if (name.find("libcnperf_elftest") != std::string::npos) 

{     return false;   }

  return true;
#else
  for (auto &lib : m_skip_libs) {
    if (0 == fnmatch(lib.c_str(), name.c_str(), 0)) 

{       return true;     }

  }
  return false;
#endif
}

PLThooker::PLThooker()
    : TraceProvider(cnperf::CNPERF_TRACE_LIB_PLT),
      / libs should skip PLT hooking /
      m_skip_libs

{"libc.so.6", "libc-2.*.so", "libm.so.6", "libm-2.*.so", "libgcc_s.so.1",                   "libpthread.so.0", "libpthread-2.*.so", "linux-vdso.so.1", "linux-gate.so.1",                   "ld-linux-*.so.*", "libdl-2.*.so", "libdltrace.so",                   "libcnpapi.so", "libcndev.so", "libdl.so.*"}

,
      / functions should skip PLT hooking /
      m_skip_funcs

{"__cyg_profile_func_enter",                    "__cyg_profile_func_exit",                    "_mcleanup",                    "__call_tls_dtors",                    "__libc_start_main",                    "__cxa_throw",                    "__cxa_rethrow",                    "__cxa_begin_catch",                    "__cxa_end_catch",                    "__cxa_finalize",                    "_Unwind_Resume",                    "_Unwind_RaiseException",                    "memmove",                    "mcount",                    "_mcount",                    "__gnu_mcount_nc"}

 {
  m_skip_funcs.insert(CNPAPI_CNRT_names, CNPAPI_CNRT_names + CNPAPI_CNRT_names_size);
  m_skip_funcs.insert(CNPAPI_CNML_names, CNPAPI_CNML_names + CNPAPI_CNML_names_size);
  m_skip_funcs.insert(CNPAPI_CNNL_names, CNPAPI_CNNL_names + CNPAPI_CNNL_names_size);
  m_skip_funcs.insert(CNPAPI_CNNL_EXTRA_names, CNPAPI_CNNL_EXTRA_names + CNPAPI_CNNL_EXTRA_names_size);
  m_skip_funcs.insert(CNPAPI_CNDRV_names, CNPAPI_CNDRV_names + CNPAPI_CNDRV_names_size);
  m_skip_funcs.insert(CNPAPI_CNPX_names, CNPAPI_CNPX_names + CNPAPI_CNPX_names_size);
  m_skip_funcs.insert(CNPAPI_CNCL_names, CNPAPI_CNCL_names + CNPAPI_CNCL_names_size);
  g_plthook_resolver_addr = 0;
  for (const auto &elf : getCurrentElfs()) {
    VLOG(13) << LOG_VAR(elf.m_path) << LOG_VAR(elf.m_support_trace);
    m_lib_addr_table.emplace(elf.m_base_addr, elf.m_path.filename());
    if (!elf.m_support_trace) continue;
    if (isSkipLib(elf.m_path.filename())) continue;
    if (!g_plthook_resolver_addr) g_plthook_resolver_addr = elf.m_got_tab[2];
    VLOG(13) << "handle elf" << LOG_VAR(elf.m_path);
    auto plt_syms = elf.getImportSymbolNames();
    auto l_map = elf.m_got_tab[1] ? elf.m_got_tab[1] : reinterpret_cast<uint64_t>(elf.m_got_tab);
    m_hook_datas.emplace(reinterpret_cast<link_map *>(l_map),
                         hook_data

{elf.m_got_tab, elf.m_plt_addr, plt_syms.size(), m_symbol_names.size(),                                    elf.m_relro_start, elf.m_relro_size, elf.m_has_plt_sec}

);
    std::copy(plt_syms.begin(), plt_syms.end(), std::back_inserter(m_symbol_names));
  }
  for (auto &hook_data : m_hook_datas) 

{     hook_data.second.align();   }

  m_addr_vec.resize(m_symbol_names.size());
  m_filter_args_type.resize(m_symbol_names.size());
  std::vector<std::atomic_flag>(m_symbol_names.size()).swap(m_flags);
  flushSymbolName();
}

PLThooker *hook = nullptr;

uint64_t get_plthook_return() 

{   return reinterpret_cast<uint64_t>(plthook_return); }

uint64_t get_plt_hooker() 

{   return reinterpret_cast<uint64_t>(plt_hooker); }

bool initPLThook() {
  // if (!elf_datas::datas->support_plt) 

{   //   LOG(WARNING) << "executable's plt not found, no lib functions will be traced.";   //   LOG(WARNING) << "ensure env LD_BIND_NOW not set, and not compile with -fno-plt or -Wl,-z,now.";   //   // return false;   // }

  hook = new PLThooker();
  return true;
}

bool startPLThook() 

{   if (hook) hook->startHook();   return true; }

void stopPLThook() { if (hook) hook->stopHook(); }

extern "C" uint64_t PLThookEntry(uint64_t *ret_addr,
                                  uint64_t func_index,
                                  link_map *l_map,
                                  struct mcount_regs *argss) 

{   int saved_errno = errno;   auto ret = hook->hookIn(ret_addr, func_index, l_map, argss);   errno = saved_errno;   return ret; }

extern "C" uint64_t PLThookExit(uint64_t *retval) 

{   int saved_errno = errno;   auto ret = hook->hookOut(retval);   errno = saved_errno;   return ret; }
