#include "breakpad.h"

#include <MESA/MESA_handle_logger.h>

int main()
{
    void *logger = MESA_create_runtime_log_handle("./log/breakpad_log", 10);
    struct breakpad_instance *g_breakpad = breakpad_init("./breakpad.ini", "breakpad", logger);
    breakpad_segv_generate();
    return 0;
}
