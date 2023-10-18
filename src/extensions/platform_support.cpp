#include "stream_inc/stream_base.h"

#include <unistd.h>
#include <sys/syscall.h>

#include "sapp_declaration.h"

thread_local int local_worker_thread_id=-2;
int get_current_worker_thread_id()
{
    if (local_worker_thread_id == -2)
    {
        pid_t my_pid = syscall(SYS_gettid);
        for (int i = 0; i < g_packet_io_thread_num; i++)
        {
            if (my_pid == sapp_global_val->individual_fixed.thread_tid[i])
            {
                local_worker_thread_id = i;
                return local_worker_thread_id;
            }
        }
		local_worker_thread_id=-1;
    }
    return local_worker_thread_id;
}