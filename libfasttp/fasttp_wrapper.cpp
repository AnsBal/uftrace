#include "fasttp_wrapper.h"
#include "./../libfasttp/include/dyntrace/fasttp/common.hpp"
#include "./../libfasttp/include/dyntrace/fasttp/fasttp.hpp"
#include "./../libfasttp/include/dyntrace/fasttp/error.hpp"


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

    fasttp::options ops{};
    
    fasttp::tracepoint* new_tracepoint(void* address) {
         try {
            ops.x86.disable_thread_safe = false;
            auto enter_handler = [](const void *caller, const arch::regs& r, const void *return_address)
            {
                fasttp_entry((unsigned long)const_cast<void*>(return_address),(unsigned long)const_cast<void*>(caller));            
            };
            auto exit_handler = [](const void* caller, const arch::regs& r, const void *return_address)
            {
                fasttp_exit((unsigned long)const_cast<void*>(return_address),(unsigned long)const_cast<void*>(caller));            
            };
            return new fasttp::tracepoint{address, fasttp::entry_exit_handler{enter_handler, exit_handler}, ops};
       
        } catch(const dyntrace::fasttp::fasttp_error& e) {
            return NULL;
        } catch(const std::exception& e) {
            return NULL;
        }
        
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

