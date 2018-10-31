#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
namespace dyntrace::fasttp
    {
#endif
        typedef struct tracepoint tracepoint;

        tracepoint* new_tracepoint(void* address);

        void* delete_tracepoint(tracepoint* tp);

        void tracepoint_disable(tracepoint* tp);

        void tracepoint_enable(tracepoint* tp);

        bool tracepoint_is_enabled(tracepoint* tp);

#ifdef __cplusplus    
    }
} 
#endif

