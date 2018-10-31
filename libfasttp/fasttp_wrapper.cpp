#include "fasttp_wrapper.h"
#include "./../libfasttp/include/dyntrace/fasttp/common.hpp"
#include "./../libfasttp/include/dyntrace/fasttp/fasttp.hpp"


#define new extern_new
#define class extern_class
extern "C" {
    #include "internal.h"
    #include "mcount.h"    
    }
#undef  new
#undef  extern_class

#include <stdlib.h> 
//#include <thread>

using namespace dyntrace;

#ifdef __cplusplus
extern "C" {
#endif

    fasttp::tracepoint* new_tracepoint(void* address) {
        fasttp::options ops{};
        ops.x86.disable_thread_safe = true;
        auto enter_handler = [](const void *caller, const arch::regs& r)
        {
            //cygprof_entry((unsigned long)const_cast<void*>(caller),(unsigned long)const_cast<void*>(caller));            
            using arch::arg;
            printf("Enter %p a=%d\n", caller, arg<int>(r, 0));
        };
        auto exit_handler = [](const void* caller, const arch::regs& r)
        {
            //cygprof_exit((unsigned long)const_cast<void*>(caller),(unsigned long)const_cast<void*>(caller));            
            using arch::ret;
            printf("Exit  %p r=%lu\n", caller, ret(r));
        };
        return new fasttp::tracepoint{address, fasttp::entry_exit_handler{enter_handler, exit_handler}, ops};
    }

    void* delete_tracepoint(fasttp::tracepoint* tp){
        delete tp;
    }

    void tracepoint_disable(fasttp::tracepoint* tp){
        tp->disable();
    }

    void tracepoint_enable(fasttp::tracepoint* tp){
        tp->enable();
    }

    bool tracepoint_is_enabled(fasttp::tracepoint* tp){
        return tp->enabled();
    }


#ifdef __cplusplus
} 
#endif

