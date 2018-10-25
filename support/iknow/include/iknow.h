#ifndef _IKNOW_H_
#define _IKNOW_H_

#ifdef __cplusplus
extern "C"
{
#endif


#define IDEBUG      (0) /* for debug */ 
#if IDEBUG
#define IPRINT(fmt, args...) printf(fmt, ##args)
#else
#define IPRINT(fmt, args...) 
#endif

#define IKONW_MODULE_STR_LEN			(16)
#define IKNOW_MON_FD_MAX				(128)
#define IKNOW_CMD_BUF_LEN			(1024)

#define IKNOW_WORK_THREAD_AEXIT		(5)
#define IKNOW_WORK_THREAD_MAX		(100)

#define IKNOW_GLOB_FD_ALIAS			(0x20140723)

/* IKnow所有的相关操作都需要此句柄，通过接口iknow_create()接口获取。*/
typedef void * iknow_handle;

/*
	因为同一个服务器同时会有多个客户端连接，每个连接的moduel, level等参数设置不同,
	需要用此句柄保存相关信息用于区别。
	此句柄做为回调函数、及iprintf()的参数，调用者不用主动获取，透传即可。
*/
typedef void * iknow_conn;


/* signal handler */
typedef void(*SIG_HANDLE_T)(int);

typedef enum{  
	ILOG_LEVEL_DEBUG		= 0,      /* debug-level messages */
	ILOG_LEVEL_INFO		= 1,      /* informational */
	ILOG_LEVEL_NOTICE	= 2,      /* normal but significant condition */
	ILOG_LEVEL_WARNING	= 3,      /* warning conditions */
	ILOG_LEVEL_ERR		= 4,      /* error conditions */
	ILOG_LEVEL_CRIT		= 5,      /* critical conditions */
	ILOG_LEVEL_ALERT		= 6,      /* action must be taken immediately */
	ILOG_LEVEL_EMERG		= 7,      /* system is unusable */
	__ILOG_LEVEL_MAX		= 8,      
}iknow_log_level_t;


typedef enum{  
	IKNOW_RET_SUCC				=  0,
	IKNOW_ERR_INVALID_CMD_TYPE	= -1,
	IKNOW_ERR_INVALID_LEN			= -2,
	IKNOW_ERR_DUPLICATE_CMD		= -3,
	IKNOW_ERR_INVALID_CMD		= -4,
}iknow_errno_t;


typedef struct{
	unsigned short listen_port_host_order;  /* 监听端口, 主机序 */
	int max_users;  /*  支持最大并发连接数, 范围[1, 100] */
}iknow_create_args_t;


iknow_handle iknow_create(const iknow_create_args_t *args, int args_len);

/*
	创建、注册完所有命令后，调用此接口，启动IKnow后台服务器线程，开始监听端口等待客户端连接。
*/
void iknow_run(iknow_handle apihandle);

/*
	参数说明:
		ihandle			: IKnow句柄;
		iconn			: IKnow连接句柄；
		format及后续不定项参数，与标准库printf(3)相同。

	由注册的回调函数调用，用于输出相关的信息。
*/
int iprintf(iknow_handle ihandle, iknow_conn iconn, const char *format, ...);

/*
	保留类似runtime_log功能, 向所有活动的客户端发送当前系统写到runtimelog的日志,
	便于实时查看, 且可以用grep搜索过滤, 还不会狂刷硬盘影响性能.
*/
int ibroadcast(iknow_handle ihandle, int log_level, const char *module, const char *format, ...);

/*
	回调函数定义:
		ihandle			: IKnow句柄;
		iconn			: IKnow连接句柄;
		cb_private_arg	: 回调函数自定义私有参数; 
		user_cmd_args		: 用户输入的命令参数;
*/
typedef long (*iknow_cmd_cb_t)(iknow_handle ihandle, iknow_conn iconn, const void *cb_private_arg, const char *user_cmd_args);

/*
	参数说明:
		Ihandle			: IKnow句柄;
		raw_cmd_str		:命令行对应的字符串;
		cmd_introduce		:命令对应的简单描述，告之使用者此命令功能;
		cmd_cb			:命令对应的回调函数;
		cmd_cb_arg		:回调函数的内部参数, 可用于调用者识别回调函数;
		have_cmd_arg		:命令是否有参数, 0:无参数; 1:有参数;
		arg_introduce		:参数的简单描述，告之使用者如何使用
*/
int iknow_register_cmd(iknow_handle apihandle, const char *raw_cmd_str, 
			const char *cmd_introduce, iknow_cmd_cb_t cmd_cb, const void *cb_private_arg, 
			int have_cmd_arg, const char *arg_introduce);

/* 仅用于提供帮助信息, 显示当前可用的模块名称 */
int iknow_register_module_for_help(iknow_handle ihandle, const char *module_name);


#ifdef __cplusplus
}
#endif

#endif

