
[![Build Status](https://travis-ci.org/namhyung/uftrace.svg?branch=master)](https://travis-ci.org/namhyung/uftrace)
[![Coverity scan](https://scan.coverity.com/projects/12421/badge.svg)](https://scan.coverity.com/projects/namhyung-uftrace)

uftrace
=======

The uftrace tool is to trace and analyze execution of a program
written in C/C++.  It was heavily inspired by the ftrace framework
of the Linux kernel (especially function graph tracer) and supports
userspace programs.  It supports various kind of commands and filters
to help analysis of the program execution and performance.

One limitation of the original uftrace project is that it does not allow you to connect to a running process and insert dynamic probes. This fork was created to overcome those limitations.

**Please read carefully this file before using this fork.**

**Disclaimer :** This fork was created with the intention of doing research and experiments. Some of the original features may not work properly. There is **ABSOLUTELY NO WARRANTY** on this project, to the extent permitted by applicable laws. You should evaluate for yourself before using this project in production.


Features
========

It traces each function in the executable and shows time duration.  It
can also trace external library calls - but only entry and exit are
supported and cannot trace internal function calls in the library call
unless the library itself built with profiling enabled.

It can show detailed execution flow at function level, and report which
function has the highest overhead.  And it also shows various information
related the execution environment.

You can setup filters to exclude or include specific functions when tracing.
In addition, it can save and show function arguments and return value.
It supports multiprocess and/or multi-threaded applications.  

This fork allows you to attach to a running process and start the tracing dynamically without rebuilding the executable and without any compilation flags.
It supports dynamic tracing with the [fast-tp library](https://github.com/AnsBal/fasttp-library)

How to use uftrace
==================
__Target Process__
The target proccess needs to load the libloader/libloader.so library. It could
either be injected at runtime or preloaded.
Example of preloading libloader:

    $ LD_PRELOAD=libloader/libloader.so tests/t-abc
    libloader: accepting socket : /tmp/libloader/29960
Once the libloader is loaded in the process, the pid is going to be printed in the terminal (29960 in the example above).
For injecting libloader, a tool like [linux-inject tool](https://github.com/gaffe23/linux-inject) could be used. 

  __Uftrace__
The uftrace command has following subcommands:

 * `record` : runs a program and saves the trace data
 * `replay` : shows program execution in the trace data
 * `report` : shows performance statistics in the trace data
 * `info`   : shows system and program info in the trace data
 * `dump`   : shows low-level trace data
 * `graph`  : shows function call graph in the trace data


For recording, the executable can be compiled with `-pg`
(or `-finstrument-functions`) option which generates profiling code
(calling mcount or __cyg_profile_func_enter/exit) for each function.
The `record` command requires you to provide a valid pid of the process to 
which you want to attach(using `-p` option). Only the `record` command has been 
patched and tested in this fork. Other commands like `live` and `recv` may not work properly.

    $ uftrace record -p 23109 -d /tmp/uftrace.data tests/t-abc
    $ uftrace replay -d /tmp/uftrace.data
    # DURATION    TID     FUNCTION
      16.134 us [ 1892] | __monstartup();
     223.736 us [ 1892] | __cxa_atexit();
                [ 1892] | main() {
                [ 1892] |   a() {
                [ 1892] |     b() {
                [ 1892] |       c() {
       2.579 us [ 1892] |         getpid();
       3.739 us [ 1892] |       } /* c */
       4.376 us [ 1892] |     } /* b */
       4.962 us [ 1892] |   } /* a */
       5.769 us [ 1892] | } /* main */

It'll create uftrace.data directory that contains trace data files.
Other analysis commands expect the directory exists in the current directory,
but one can use another using `-d` option.
The `replay` command shows execution information like above.  As you can see,
the t-abc is a very simple program merely calls a, b and c functions.
In the c function it called getpid() which is a library function implemented
in the C library (glibc) on normal systems - the same goes to __cxa_atexit().

Uftrace support dynamic tracing by compiling the target with the -mnop-mcount option.
This option adds NOPs instructions at the very beginning of a function. The NOPs are 
later patched to insert a trampoline.
An alternative to this is fastp-tp library. It does not need any compilation flag. It adds 
the tracepoint dynamically during the execution time (see [fast-tp library](https://github.com/AnsBal/fasttp-library) for more details).
To use fast-tp library, use the `--fast-tp` option combined with `--patch=FUNC`. Where `FUNC` 
is the name of the function you want to trace. To instrument all the symbols in the 
executable, use `--patch=.`.

Unless uftrace and the target executable are in the same folder, the `-d` option 
should be used to indicate where the traces will be saved.

Example of uftrace usage with fast-tp library:

    $ uftrace record -p 23109 -d /tmp/uftrace.data --fast-tp -P a -P b -P c tests/t-abc
    $ uftrace replay -d /tmp/uftrace.data

Example of uftrace usage with -pg or -finstrument-functions:

    $ uftrace record -p 23109 -d /tmp/uftrace.data tests/t-abc
    $ uftrace replay -d /tmp/uftrace.data

Users can use various filter options to limit functions it records/prints.
The depth filter (`-D` option) is to omit functions under the given call depth.
The time filter (`-t` option) is to omit functions running less than the given
time. And the function filters (`-F` and `-N` options) are to show/hide functions
under the given function.

The `report` command lets you know which function spends the longest time
including its children (total time).

    $ uftrace report -d /tmp/uftrace.data
      Total time   Self time       Calls  Function
      ==========  ==========  ==========  ====================================
       25.024 us    2.718 us           1  main
       19.600 us   19.600 us           9  fib
        2.853 us    2.853 us           1  __monstartup
        2.706 us    2.706 us           1  atoi
        2.194 us    2.194 us           1  __cxa_atexit


The `graph` command shows function call graph of given function.  In the above
example, function graph of function 'main' looks like below:

    $ uftrace graph -d /tmp/uftrace.data main 
    # Function Call Graph for 'main' (session: 073f1e84aa8b09d3)
    =============== BACKTRACE ===============
     backtrace #0: hit 1, time  25.024 us
       [0] main (0x40066b)
    
    ========== FUNCTION CALL GRAPH ==========
      25.024 us : (1) main
       2.706 us :  +-(1) atoi
                :  | 
      19.600 us :  +-(1) fib
      16.683 us :    (2) fib
      12.773 us :    (4) fib
       7.892 us :    (2) fib


The `dump` command shows raw output of each trace record.  You can see the result
in the chrome browser, once the data is processed with `uftrace dump --chrome`.
Below is a trace of clang (LLVM) compiling a small C++ template metaprogram.

![uftrace-chrome-dump](doc/uftrace-chrome.png)

The `info` command shows system and program information when recorded.

    $ uftrace info
    # system information
    # ==================
    # program version     : uftrace v0.8.1
    # recorded on         : Tue May 24 11:21:59 2016
    # cmdline             : uftrace record tests/t-abc 
    # cpu info            : Intel(R) Core(TM) i7-3930K CPU @ 3.20GHz
    # number of cpus      : 12 / 12 (online / possible)
    # memory info         : 20.1 / 23.5 GB (free / total)
    # system load         : 0.00 / 0.06 / 0.06 (1 / 5 / 15 min)
    # kernel version      : Linux 4.5.4-1-ARCH
    # hostname            : sejong
    # distro              : "Arch Linux"
    #
    # process information
    # ===================
    # number of tasks     : 1
    # task list           : 5098
    # exe image           : /home/namhyung/project/uftrace/tests/t-abc
    # build id            : a3c50d25f7dd98dab68e94ef0f215edb06e98434
    # exit status         : exited with code: 0
    # elapsed time        : 0.003219479 sec
    # cpu time            : 0.000 / 0.003 sec (sys / user)
    # context switch      : 1 / 1 (voluntary / involuntary)
    # max rss             : 3072 KB
    # page fault          : 0 / 172 (major / minor)
    # disk iops           : 0 / 24 (read / write)


How to install uftrace
======================

__Fork dependencies__

To install and use this uftrace fork, you need to install [fast-tp library](https://github.com/AnsBal/fasttp-library).

The uftrace is written in C and tried to minimize external dependencies.
Currently it does not require any of them but there're some optional
dependencies to enable advanced features.

Once you installed required software(s) on your system, it can be built and
installed like following:

    $ make
    $ sudo make install

For more advanced setup, please refer
[INSTALL.md](INSTALL.md) file.


Limitations
===========
- It can trace a native C/C++ application on Linux.
- It *cannot* be used for system-wide tracing.
- It supports x86_64 for now.
- It needs to attach to a running process.


License
=======
The uftrace program is released under GPL v2.  See [COPYING file](COPYING) for details.

