#include "breakpad.h"

#include <sys/stat.h>
#include <libgen.h>

/* Breakpad */
#include <client/linux/handler/exception_handler.h>
#include <common/linux/http_upload.h>

#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#define likely(expr) __builtin_expect((expr), 1)
#define unlikely(expr) __builtin_expect((expr), 0)

#define LOGGER_MODULE "breakpad"

struct breakpad_instance
{
    unsigned int en_breakpad;
    char minidump_dir_prefix[4096];
    google_breakpad::ExceptionHandler *exceptionHandler;

    /* Upload to crash server */
    unsigned int en_breakpad_upload;
    char minidump_sentry_upload_url[4096];

    /* Upload tools name */
    char upload_tools_filename[4096];

    /* Upload tools exec command */
    char *upload_tools_exec_argv[64];
    char *minidump_filename;
};

void breakpad_segv_generate()
{
    volatile char *_NULLPTR = nullptr;
    (*_NULLPTR) = 0;
}

static void _mkdir(const char *dir)
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    }
    mkdir(tmp, S_IRWXU);
}

static bool breakpad_dump_to_file(const google_breakpad::MinidumpDescriptor &descriptor,
                                      void *context, bool succeeded)
{
    fprintf(stderr, "Crash happened, minidump path:  %s\n", descriptor.path());
    return succeeded;
}

static bool breakpad_dump_and_report(const google_breakpad::MinidumpDescriptor &descriptor,
                                         void *context, bool succeeded)
{
    struct breakpad_instance *instance = (struct breakpad_instance *)context;
    int ret = 0;

    strncpy(instance->minidump_filename, descriptor.path(), PATH_MAX - 1);
    fprintf(stderr, "Crash happened, prepare upload the minidump file:  %s\n", descriptor.path());

    ret = access(instance->minidump_filename, F_OK | R_OK);
    if (ret < 0)
    {
        fprintf(stderr, "minidump file is not existed, cannot upload minidump file");
        return succeeded;
    }

    /* Firstly, fork an child process */
    pid_t exec_child_pid = fork();
    if (exec_child_pid == 0)
    {
        /* As a child, exec minidump upload tools */
        ret = execv(instance->upload_tools_filename, instance->upload_tools_exec_argv);
        if (ret < 0)
        {
            fprintf(stderr, "Failed at exec the upload program %s: %s\n",
                    instance->upload_tools_filename, strerror(errno));
        }

        exit(EXIT_FAILURE);
    }
    else if (exec_child_pid > 0)
    {
        fprintf(stderr, "Starting upload minidump, PID = %d. \n", exec_child_pid);
        return succeeded;
    }
    else
    {
        /* failed at fork, cannot upload the minidump */
        fprintf(stderr, "Failed at fork(), cannot upload minidump file. :  %s\n", strerror(errno));
        return succeeded;
    }
}

//functioned as strdup, for dictator compatible.
static char *_strdup(const char *s)
{
    char *d = NULL;
    if (s == NULL)
    {
        return NULL;
    }

    d = (char *)malloc(strlen(s) + 1);
    memcpy(d, s, strlen(s) + 1);
    return d;
}

static int breakpad_init_minidump_upload(struct breakpad_instance *instance, const char *profile, const char *module, void *logger)
{
    int ret = 0;
    char execpath[PATH_MAX] = {};
    char *execdirname = NULL;
    char *execname = NULL;

    ret = MESA_load_profile_string_nodef(profile, module, "breakpad_upload_url",
                                         instance->minidump_sentry_upload_url, sizeof(instance->minidump_sentry_upload_url));

    if (unlikely(ret < 0))
    {
        MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "breakpad_upload_url is necessary, failed. ");
        goto errout;
    }

    ret = readlink("/proc/self/exe", execpath, sizeof(execpath));
    if (unlikely(ret < 0))
        {
            printf("Failed at readlink /proc/self/exec: %s", strerror(errno));
            goto errout;
        }

    execdirname = dirname(execpath);
    snprintf(instance->upload_tools_filename, sizeof(instance->upload_tools_filename) - 1,
             "%s/%s", execdirname, "minidump_upload");

    /* Execfile */
    instance->upload_tools_exec_argv[0] = _strdup(instance->upload_tools_filename);

    execname = basename(execpath);

    /* Firstly, Product Name and Product Version */
    instance->upload_tools_exec_argv[1] = _strdup("-p");
    instance->upload_tools_exec_argv[2] = _strdup(execname);
    instance->upload_tools_exec_argv[3] = _strdup("-v");
    instance->upload_tools_exec_argv[4] = _strdup("v1");

    /* Minidump file location, now we don't know it */
    instance->minidump_filename = (char *)calloc(sizeof(char), PATH_MAX);
    instance->upload_tools_exec_argv[5] = instance->minidump_filename;

    /* Minidup upload url */
    instance->upload_tools_exec_argv[6] = _strdup(instance->minidump_sentry_upload_url);
    instance->upload_tools_exec_argv[7] = NULL;
    return 0;

errout:
    return -1;
}

struct breakpad_instance *breakpad_init(const char *profile, const char *module, void *logger)
{
    struct breakpad_instance *instance = (struct breakpad_instance *)calloc(sizeof(struct breakpad_instance), 1);
    assert(instance != nullptr);

    int ret = 0;
    unsigned int disable_coredump = 1;
    MESA_load_profile_uint_def(profile, module, "disable_coredump", &disable_coredump, 1);

    if (disable_coredump > 0)
    {
        const struct rlimit __rlimit_vars = {.rlim_cur = 0, .rlim_max = 0};
        ret = setrlimit(RLIMIT_CORE, &__rlimit_vars);
        if (ret < 0)
        {
            MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
        }
    }

    MESA_load_profile_uint_def(profile, module, "enable_breakpad", &instance->en_breakpad, 1);
    if (instance->en_breakpad <= 0)
    {
        MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "Breakpad Crash Reporting System is disabled. ");
        return instance;
    }
    MESA_load_profile_string_def(profile, module, "breakpad_minidump_dir",
                                 instance->minidump_dir_prefix, sizeof(instance->minidump_dir_prefix), "/tmp/crashreport");

    /* Create the minidump dir if it is not existed */
    _mkdir(instance->minidump_dir_prefix);

    MESA_load_profile_uint_def(profile, module, "enable_breakpad_upload",&instance->en_breakpad_upload, 0);
    if (instance->en_breakpad_upload)
    {
        /* Try to init the breakpad upload */
        ret = breakpad_init_minidump_upload(instance, profile, module,logger);
        if (ret < 0)
        {
            MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "Breakpad upload init failed, using local breakpad dumpfile");
            instance->en_breakpad_upload = 0;
        }

        /* When we use breakpad, do not generate any coredump file */
        const struct rlimit __rlimit_vars = {.rlim_cur = 0, .rlim_max = 0};
        ret = setrlimit(RLIMIT_CORE, &__rlimit_vars);
        if (ret < 0)
        {
            MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "setrlimit(RLIMIT_CORE, 0) failed: %s", strerror(errno));
        }
    }

    if (instance->en_breakpad_upload)
    {
        instance->exceptionHandler = new google_breakpad::ExceptionHandler(
            google_breakpad::MinidumpDescriptor(instance->minidump_dir_prefix), NULL,
            breakpad_dump_and_report, instance, true, -1);
    }
    else
    {
        instance->exceptionHandler = new google_breakpad::ExceptionHandler(
            google_breakpad::MinidumpDescriptor(instance->minidump_dir_prefix), NULL,
            breakpad_dump_to_file, NULL, true, -1);
    }

    MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "Breakpad Crash Report is enable. ");
    MESA_handle_runtime_log(logger, RLOG_LV_INFO, LOGGER_MODULE, "Minidump Dir: %s", instance->minidump_dir_prefix);
    return instance;
}
