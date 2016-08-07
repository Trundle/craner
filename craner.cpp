/**
 * Dump a docker container's incoming network traffic.
 *
 * Written 2016 by Andreas Stührk.
 */

//
// Parts of this file are copied or inspired from strace, which is released
// under the following license:
//
// Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
// Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
// Copyright (c) 1993 Ulrich Pegelow <pegelow@moorea.uni-muenster.de>
// Copyright (c) 1995, 1996 Michael Elizabeth Chastain <mec@duracef.shout.net>
// Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
// Copyright (C) 1998-2001 Wichert Akkerman <wakkerma@deephackmode.org>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

#include <boost/range/adaptor/map.hpp>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

#ifndef __x86_64__
#error "Craner only works under x86_64"
#endif

#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

#ifdef PTRACE_EVENT_STOP
/* Linux 3.1 - 3.3 releases had a broken value.  It was fixed in 3.4.  */
# if PTRACE_EVENT_STOP == 7
#  undef PTRACE_EVENT_STOP
# endif
#endif
#ifndef PTRACE_EVENT_STOP
# define PTRACE_EVENT_STOP	128
#endif

volatile sig_atomic_t interrupted;
sigset_t blocked_set;

const size_t max_syscall_args = 6;

struct i386_user_regs_struct {
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
};

union x86_regs_union {
	user_regs_struct      x86_64_r;
	i386_user_regs_struct i386_r;
};

const unsigned int SYSCALL_TRAP_SIG = SIGTRAP | 0x80;
const size_t DEFAULT_BUFFER_SIZE = 128 * 1024;

enum tracee_state {
  ATTACHED          = 0x01,
  TRACEE_IN_SYSCALL = 0x02
};

struct tracee_info {
  pid_t pid;
  int state;
  long syscall_number;
  long syscall_arg[max_syscall_args];
  std::vector<char> buffer;
  std::map<int, int> log_files;

  tracee_info(pid_t);
  ~tracee_info();
  /** Whether the tracee is entering a syscall. */
  bool entering() const;
  int get_or_open_log(const int, const int);
  void close_log(const int);
};

tracee_info::tracee_info(pid_t pid_)
  : pid(pid_), state(0), syscall_number(0), buffer(DEFAULT_BUFFER_SIZE),
    log_files() { }

tracee_info::~tracee_info() {
  for (auto&& fd : log_files | boost::adaptors::map_values) {
    if (fd >= 0) {
      close(fd);
    }
  }
}

bool tracee_info::entering() const {
  return (state & TRACEE_IN_SYSCALL) == 0;
}

int tracee_info::get_or_open_log(const int log_dir_fd, const int fd) {
  auto log_fd_iter = log_files.find(fd);
  if (log_fd_iter == log_files.end()) {
    timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    const long time = static_cast<long>(t.tv_sec) * 1000 + t.tv_nsec / 100000;
    std::stringstream log_path;
    log_path << pid << '_' << fd << '_' << time;
    const int log_fd = openat(log_dir_fd, log_path.str().c_str(),
                              O_APPEND | O_CREAT | O_WRONLY);
    if (log_fd >= 0) {
      log_files.emplace(fd, log_fd);
    } else {
      std::cerr << "WARN: Could not open log file for FD " << fd << ": "
                << strerror(errno) << std::endl;
    }
    return log_fd;
  }
  return log_fd_iter->second;
}

void tracee_info::close_log(const int fd) {
  const auto log_fd_iter = log_files.find(fd);
  if (log_fd_iter != log_files.end()) {
    close(log_fd_iter->second);
    log_files.erase(log_fd_iter);
  }
}

struct craner_state {
  std::map<pid_t, tracee_info> tracees;
  x86_regs_union x86_regs;
  iovec x86_io;
  const int log_dir_fd;

  craner_state(const int);
  tracee_info* lookup_tracee(const pid_t);
  tracee_info* add_tracee(const pid_t);
  tracee_info* add_tracee_if_required(const pid_t, const int status);
};

craner_state::craner_state(const int log_dir_fd_)
  : tracees(), x86_regs(), x86_io(), log_dir_fd(log_dir_fd_) {
  x86_io.iov_base = &x86_regs;
}

tracee_info* craner_state::lookup_tracee(const pid_t pid) {
  auto tracee = tracees.find(pid);
  if (tracee != tracees.end()) {
    return &tracee->second;
  }
  return 0;
}

tracee_info* craner_state::add_tracee(const pid_t pid) {
  return &tracees.emplace(pid, tracee_info(pid)).first->second;
}

tracee_info* craner_state::add_tracee_if_required(const pid_t pid, const int status) {
  // We don't follow children yet
  return 0;
}

void interrupt(int sig) {
	interrupted = sig;
}

pid_t to_pid(const char* input) {
  errno = 0;
  char* end;
  const unsigned long int pid_long = strtoul(input, &end, 10);
  const pid_t pid = pid_long;
  if (errno || static_cast<unsigned long int>(pid) != pid_long
      || static_cast<size_t>(end - input) != strlen(input)) {
    return 0;
  } else {
    return pid;
  }
}

pid_t wait_and_ignore_intr(const pid_t pid, int* status) {
  pid_t retval;
  do {
    retval = waitpid(pid, status, 0);
  } while (retval < 0 && errno == EINTR);
  return retval;
}

bool seize(craner_state& state, const pid_t pid) {
  if (ptrace(PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACESYSGOOD) < 0) {
    std::cerr << "Could not seize PID " << pid << ": " << strerror(errno) << std::endl;
    return false;
  }
  if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0) {
    std::cerr << "Could not interrupt: " << strerror(errno) << std::endl;
    return false;
  }
  state.add_tracee(pid);
  return true;
}

bool attach_to_pid(craner_state& state, const pid_t pid) {
  if (!seize(state, pid)) {
    return false;
  }

  // Attach to other threads as well
  std::stringstream proc_dir;
  proc_dir << "/proc/" << pid << "/task";
  DIR* dir = opendir(proc_dir.str().c_str());
  if (dir != NULL) {
    dirent* de;
    while ((de = readdir(dir)) != NULL) {
      if (de->d_fileno == 0) {
        continue;
      }

      pid_t thread_id = to_pid(de->d_name);
      if (thread_id > 0 && thread_id != pid) {
        seize(state, thread_id);
      }
    }
  }
  closedir(dir);

  return true;
}

bool get_regset(iovec& io, const pid_t pid) {
  io.iov_len = sizeof(x86_regs_union);
  return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io) >= 0;
}

bool restart_tracee(const pid_t pid, int signal) {
  if (ptrace(PTRACE_SYSCALL, pid, NULL, static_cast<long>(signal)) < 0) {
    std::cerr << "Could not continue tracee " << pid << ": " << strerror(errno) << std::endl;
    return false;
  }
  return true;
}

bool restart_tracee(const pid_t pid) {
  return restart_tracee(pid, 0);
}

long get_syscall_number(iovec& io) {
  const x86_regs_union* const regs = static_cast<const x86_regs_union* const>(io.iov_base);
  if (io.iov_len == sizeof(i386_user_regs_struct)) {
    return regs->i386_r.eax;
  } else {
    long syscall_number = regs->x86_64_r.orig_rax;
    if (syscall_number & __X32_SYSCALL_BIT) {
      if (static_cast<long long>(syscall_number) != -1) {
        syscall_number -= __X32_SYSCALL_BIT;
      }
    }
    return syscall_number;
  }
}

void get_syscall_args(tracee_info& tracee, iovec& io) {
  const x86_regs_union* const regs = static_cast<const x86_regs_union* const>(io.iov_base);
  if (io.iov_len != sizeof(i386_user_regs_struct)) {
		tracee.syscall_arg[0] = regs->x86_64_r.rdi;
		tracee.syscall_arg[1] = regs->x86_64_r.rsi;
		tracee.syscall_arg[2] = regs->x86_64_r.rdx;
		tracee.syscall_arg[3] = regs->x86_64_r.r10;
		tracee.syscall_arg[4] = regs->x86_64_r.r8;
		tracee.syscall_arg[5] = regs->x86_64_r.r9;
	} else {
		tracee.syscall_arg[0] = regs->i386_r.ebx;
		tracee.syscall_arg[1] = regs->i386_r.ecx;
		tracee.syscall_arg[2] = regs->i386_r.edx;
		tracee.syscall_arg[3] = regs->i386_r.esi;
		tracee.syscall_arg[4] = regs->i386_r.edi;
		tracee.syscall_arg[5] = regs->i386_r.ebp;
	}
}

long get_syscall_result(iovec& io) {
  const x86_regs_union* const regs = static_cast<const x86_regs_union* const>(io.iov_base);
  if (io.iov_len != sizeof(i386_user_regs_struct)) {
    return regs->x86_64_r.rax;
  } else {
    return regs->i386_r.eax;
  }
}

void handle_read_result(craner_state& state, tracee_info& tracee, long result) {
  if (result > 0) {
    const int fd = tracee.syscall_arg[0];
    if (tracee.buffer.capacity() < static_cast<size_t>(result)) {
      tracee.buffer.reserve(result);
    }
    char* data = &*tracee.buffer.begin();
    const iovec local = {
      data, static_cast<size_t>(result)
    };
    const iovec remote = {
      reinterpret_cast<void *>(tracee.syscall_arg[1]),
      static_cast<size_t>(result)
    };
    ssize_t bytes_read = process_vm_readv(tracee.pid, &local, 1, &remote, 1, 0);
    if (bytes_read < 0) {
      std::cerr << "WARN: process_vm_readv returned " << strerror(errno)
                << ", skipping some data for FD " << fd << std::endl;
      return;
    }
    const int log_fd = tracee.get_or_open_log(state.log_dir_fd, fd);
    if (log_fd >= 0) {
      write(log_fd, data, bytes_read);
    }
  }
}

void handle_close(tracee_info& tracee) {
  tracee.close_log(tracee.syscall_arg[0]);
}

bool trace_syscall(craner_state& state, tracee_info& tracee) {
  if (tracee.entering()) {
    tracee.syscall_number = get_syscall_number(state.x86_io);
    get_syscall_args(tracee, state.x86_io);
    tracee.state |= TRACEE_IN_SYSCALL;
    return restart_tracee(tracee.pid);
  } else {
    if (tracee.syscall_number == SYS_read) {
      handle_read_result(state, tracee, get_syscall_result(state.x86_io));
    } else if (tracee.syscall_number == SYS_close) {
      handle_close(tracee);
    }
    tracee.state &= ~TRACEE_IN_SYSCALL;
    return restart_tracee(tracee.pid);
  }
  return true;
}

bool trace_step(craner_state& state) {
  if (interrupted) {
    return false;
  }

  int status;
  pid_t pid = waitpid(-1, &status, __WALL);
  if (pid < 0 && errno == EINTR) {
    return true;
  }
  tracee_info* tracee = state.lookup_tracee(pid);
  if (!tracee) {
    tracee = state.add_tracee_if_required(pid, status);
    if (!tracee) {
      return true;
    }
  }
  if (WIFSTOPPED(status)) {
    const int sig = WSTOPSIG(status);
    const unsigned int event = static_cast<unsigned int>(status >> 16);
    if (event != 0) {
      return restart_tracee(pid);
    }
    if (sig != SYSCALL_TRAP_SIG) {
      siginfo_t sig_info;
      const bool stopped = ptrace(PTRACE_GETSIGINFO, pid, 0, &sig_info) < 0;
      if (!stopped) {
        // Signal-delivery stop. Inject!
        return restart_tracee(pid, sig);
      }
    } else {
      if (interrupted) {
        return false;
      }
      // Syscall entry or exit stop
      if (!get_regset(state.x86_io, pid)) {
        return false;
      }
      return trace_syscall(state, *tracee);
    }
  }
  return true;
}

void clean_up(craner_state& state) {
  for (auto&& tracee : state.tracees | boost::adaptors::map_values) {
    if (ptrace(PTRACE_INTERRUPT, tracee.pid, NULL, NULL) < 0) {
      return;
    }
    int status;
    if (waitpid(tracee.pid, &status, __WALL) < 0) {
      if (errno != EINTR) {
        std::cerr << "Error while detaching: waitpid returned " << strerror(errno) << std::endl;
        return;
      }
    } else if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      const unsigned event = static_cast<unsigned>(status >> 16);
      if (event == PTRACE_EVENT_STOP) {
        sig = 0;
      } else if (sig == SYSCALL_TRAP_SIG) {
        sig = 0;
      }
      ptrace(PTRACE_DETACH, tracee.pid, NULL, sig);
    }
  }
}

void setup_signals() {
  struct sigaction sa;
  sigemptyset(&blocked_set);
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaddset(&blocked_set, SIGHUP);
  sigaddset(&blocked_set, SIGINT);
  sigaddset(&blocked_set, SIGQUIT);
  sigaddset(&blocked_set, SIGPIPE);
  sigaddset(&blocked_set, SIGTERM);
  sa.sa_handler = interrupt;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
}

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: craner <log directory> <PID>" << std::endl;
    return 1;
  }

  const pid_t pid = to_pid(argv[2]);
  if (pid == 0) {
    std::cerr << "Invalid PID: " << argv[2] << std::endl;
    return 1;
  }

  setup_signals();

  const int log_dir_fd = open(argv[1], O_DIRECTORY);
  if (log_dir_fd < 0) {
    std::cerr << "Invalid log directory: " << strerror(errno) << std::endl;
    return 1;
  }
  craner_state state(log_dir_fd);
  if (!attach_to_pid(state, pid)) {
    close(log_dir_fd);
    return 1;
  }
  std::cout << "Attached to " << pid << std::endl;

  while (trace_step(state))
    // nothing
    ;

  std::cout << "Cleaning up" << std::endl;
  clean_up(state);
  close(log_dir_fd);
  return 0;
}
