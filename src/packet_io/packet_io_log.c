#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

extern void gdev_keepalive_log(void);
extern void queue_full_detect(FILE *queue_log_fp);
extern void pcap_detect_error(FILE *pcap_err_fp);

#if 0
#define MESA_MKDIR(_dir,_mode) do{\
         if(0 == is_dir_exist(_dir)) {\
             if(mkdir(_dir,_mode) != 0) {\
                 return -1;}\
             }\
         } while(0)

/*
   判断文件夹是否存在.
   return value:
   	 0: not exist
   	 1: exist
  	-1: error
 */
static int is_dir_exist(const char *dir)
{
    struct stat file_stat;

    if(0 != stat(dir, &file_stat)) 
    {
        if(ENOENT == errno)  /* not exist */
        {   
            return 0;
        } 
        else 
        {
            return -1;
        }
    }
	
    return 1;
}

static char *safe_strncpy(char *dest, const char *src, size_t n)
{
    if(NULL == dest || NULL == src)
    {
		return NULL;
    }

    if(strlen(src) >= n) 
    {
        return NULL;
    }
    
    return strncpy(dest,src, n);
}

static int __MESA_mkdir_r(const char *dir, mode_t mode, int n)
{
    char tmp[PATH_MAX]={};
    char *pre, *next ;
    int i;
    
    if(NULL == safe_strncpy(tmp, dir, PATH_MAX)) 
    {
        return -1;
    }

    pre = tmp;
    for(i = 0; i < n; i++) 
    {
        if(NULL == (next = (char *)memchr(pre, '/', PATH_MAX))) 
        {
            if(*pre != '\0') 
            {
                MESA_MKDIR(tmp, mode); /* the last sub-dir */ 
            }
            return 0;
        }
        pre = next + 1;
        if(*pre == '/')  /* too continuous '/' treat as one '/' */
        {   
            pre++;
        }
    }

    *pre = '\0';
    MESA_MKDIR(tmp, mode);

    return __MESA_mkdir_r(dir, mode, n+1);

}


/* 可递归建立多层文件夹，功能同shell命令: mkdir -p a/b/c/d */
int MESA_mkdir_p(const char *pathname, mode_t mode)
{
    char *p;
    char tmp[PATH_MAX] = {};
    int count = 1;

    if(NULL == pathname)
    {
		return -1;
    }

    if('/' == *pathname)  /* absolute path */
    {   
        if(NULL == safe_strncpy(tmp, pathname, PATH_MAX)) 
        {
            return -1;
        }
        p  = (char *)memchr(tmp+1, '/', PATH_MAX);    
        *p = '\0';
        MESA_MKDIR(tmp, mode);
        count++; 
    }

    return __MESA_mkdir_r(pathname, mode, count);
}
#else
int MESA_mkdir_p(const char *pathname, mode_t mode)
{
        char tmp[PATH_MAX];
        char *p = NULL;
        size_t len;
        int ret;

	if(strncasecmp(pathname, "./", 2) == 0){
		pathname += 2;
	}
	
        snprintf(tmp, PATH_MAX-1, "%s", pathname);
        len = strlen(tmp);
        if(tmp[len - 1] == '/'){
                tmp[len - 1] = 0;
        }
        for(p = tmp + 1; *p; p++){
                if(*p == '/') {
                        *p = 0;
                        ret = mkdir(tmp, mode);
                        if((ret < 0) && (errno != EEXIST)){
					return -1;
                        }
                        *p = '/';
                }
        }      
        
        ret = mkdir(tmp, mode);
        if((ret < 0) && (errno != EEXIST)){
		return -1;
        }

        return 0;
}
#endif

/*
    convert time_t to time string like "YY-MM-DD HH:MM:SS".
*/
char *timet_to_str(time_t timet, char *time_str, int time_str_len)
{
    struct tm *now;

    if(NULL == time_str || time_str_len <= (int)strlen("YY-MM-DD HH:MM:SS"))
    {
        return (char *)"1970-01-01 error"; /* error! */
    }	

    now = localtime(&timet);
    strftime(time_str, time_str_len, "%Y-%m-%d %H:%M:%S", now);

    return time_str;
}



/* 每天以当天日期建立文件夹，存储日志文件 */
static int packet_io_log_path_update(char *log_path, int path_len)
{
#define PACKET_IO_LOG_PREFIX	"log/packet_io"	
	struct tm *now;
	char date_now[16];

	if(path_len <= (int)strlen(PACKET_IO_LOG_PREFIX) + (int)strlen("1970-01-01") + 1)
	{
		return -1;
	}

	now = localtime(&g_CurrentTime);
	strftime(date_now, 16, "%Y-%m-%d", now);

	snprintf(log_path, path_len, "%s/%s", PACKET_IO_LOG_PREFIX, date_now);
	
	return 0;
}


/*
	打开日志文件，返回文件句柄;
	此函数与标准fopen()区别是，传入文件名，自动判断日期，并用当天日期建立文件夹，
	然后在此文件夹内存储日志文件， 方便管理与查看.
	
	warning: 调用此函数后，需要fclose()文件句柄!
*/
FILE *packet_io_open_log_file(const char *log_file_name, const char *mode)
{
	FILE *fp;
	
	char packet_io_log_path[PATH_MAX];
	char packet_io_log_name[PATH_MAX];
	
	if(packet_io_log_path_update(packet_io_log_path, PATH_MAX) < 0)
	{
		return NULL;
	}

	if(MESA_mkdir_p(packet_io_log_path, 0755) < 0)
	{
		return NULL;
	}

	snprintf(packet_io_log_name, PATH_MAX, "%s/%s", packet_io_log_path,log_file_name);

	fp = fopen(packet_io_log_name, mode);
	
	return fp;
}


/* 2012-09-13 LiJia add, 用于检测和记录底层捕包、发包相关状态信息线程， 
   如丢包计数、线程队列满日志、与特殊设备的保活连接日志等等.
*/
void *packet_io_stats_thread(void *arg)
{
	
	while(1)
	{
		// to do !

		//记录每种捕包库的丢包、发包、信息
		
		//gdev_keepalive_log();

		/* others ? */

		sleep(5);
	}

	return NULL;
}

#ifdef __cplusplus
}
#endif
