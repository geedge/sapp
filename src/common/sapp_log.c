#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/tomlc99_wrap.h"


void sapp_printf(const char *fmt, ...)
{
	va_list ap;
	
	if(sapp_global_val->cla.slient_mode != 0){
		return;
	}

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    return;
}


void sapp_printf_colorful(int level, const char *format, ...)
{
    va_list ap;
    char local_log_content_buff[XATTR_SIZE_MAX];
    const char *log_color_start = "";
    const char *log_color_end = "";
    FILE *out_fp = stdout;
	
    va_start(ap, format);
    vsnprintf(local_log_content_buff, sizeof(local_log_content_buff), format, ap);
    va_end(ap);

    switch(level)
    { 
        case RLOG_LV_DEBUG:
            log_color_start = "\033[33m";
            log_color_end = "\033[0m";
        break;
        
        case RLOG_LV_INFO:
            log_color_start = "\033[1;33m";
            log_color_end = "\033[0m";
        break;
        
        case RLOG_LV_FATAL:
            log_color_start = "\033[1;31;40m[Error]";
            log_color_end = "\033[0m";
            out_fp = stderr;
        break;
        
        default:
        break;
    }

    fprintf(out_fp, "%s%s%s", log_color_start, local_log_content_buff, log_color_end);

    return;
}


/*
	print_sw, file_sw: 
		0:不输出; 
		10,20,30:按level等级比较是否输出;  
		~0: 强制输出, 不管当前全局log_level是多少.
*/
void sapp_log(int level, int print_sw, int file_sw, const char *format, ...)
{
    va_list ap;
    char local_log_content_buff[XATTR_SIZE_MAX];
    const char *log_color_start = "";
    const char *log_color_end = "";
    FILE *out_fp = stdout;

	if(sapp_global_val->cla.slient_mode != 0){
		print_sw = 0;
	}

    if(level < ABBR_SAPP_LOG_LEVEL){
    	if((print_sw != ~0) && (file_sw != ~0)){
        	return;
        }
    }

    if((0 == print_sw) && (0 == file_sw)){
        return;
    }
	
    va_start(ap, format);
    vsnprintf(local_log_content_buff, sizeof(local_log_content_buff), format, ap);
    va_end(ap);

    switch(level)
    { 
        case RLOG_LV_DEBUG:
            //log_color_start = "\033[41m";
            //log_color_end = "\033[0m";
        break;
        
        case RLOG_LV_INFO:
            log_color_start = "\033[32m";
            log_color_end = "\033[0m";
        break;
        
        case RLOG_LV_FATAL:
            log_color_start = "\033[1;31;40m[Error]";
            log_color_end = "\033[0m";
            out_fp = stderr;
        break;
        
        default:
        break;
    }

    if((~0 == file_sw) || (level >= ABBR_SAPP_LOG_LEVEL)){
        MESA_handle_runtime_log(sapp_global_val->individual_fixed.log_handle, level, (char *)"sapp", "%s", local_log_content_buff);
    }

    if((~0 == print_sw) || (level >= ABBR_SAPP_LOG_LEVEL)){
        fprintf(out_fp, "%s%s%s\n", log_color_start, local_log_content_buff, log_color_end);
    }

    return;
}

#ifdef __cplusplus
}
#endif


