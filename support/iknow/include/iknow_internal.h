#ifndef _IKNOW_INTERNAL_H_
#define _IKNOW_INTERNAL_H_
#include <pthread.h>
#include "iknow.h"
#include "MESA_list.h"


typedef enum{
	CMD_TYPE_USER			= 0, /* 用户手输的命令 */
	CMD_TYPE_RESERVE		= 1, /* 内部保留命令 */
	CMD_TYPE_CTRL			= 2, /* 不可见特殊控制字符, 如tab, 退格, 上下箭头等 */
}cmd_type_t;

typedef enum {
	IKNOW_THREAD_STATE_INIT	= 0,  /* 还未初始化的, 即线程还未真正创建 */
	IKNOW_THREAD_STATE_IDLE	= 1,  /* 线程已创建, 空闲 */
	IKNOW_THREAD_STATE_REDY	= 2,  /* 有新的客户端连接, 可以准备接收并执行cmd */
	IKNOW_THREAD_STATE_BUSY	= 3,  /* 命令执行中 */
}state_t;

enum{
	TRANSF_OPT_TYPE_CMD		= 1, /* 客户端完整命令 */
	TRANSF_OPT_TYPE_CMD_RES,	 /* 命令返回结果 */
	TRANSF_OPT_TYPE_EXPECT_COMPLETE_CMD, /* 客户端命令补全 */
	TRANSF_OPT_TYPE_CANDIDATE_CMD, /* 补全候选命令集合, 可能有多个,如果只有一个的话, Iclient可以直接填充到命令行缓存, 按回车可立即执行 */
};

typedef enum{	
	NON_CTRL_CMD						= 0, /* defalult */
	CTRL_CMD_AUTO_COMPLETE 			= 1,/* 命令补全, 如"show http ?" */
	CTRL_CMD_AUTO_CLOSE				= 2, /* 命令结束后, 自动关闭socket */
	CTRL_CMD_MAX						= 4,
}cltl_cmd_type_t; /* 按位与或操作 */

typedef struct {
	int is_valid; /* 是否有效, 支持"module del xxx"删除操作 */
	int module_str_len; /* 字符串实际长度, 不含末尾'\0' */
	const char *module_str;
}iknow_string_t;

typedef struct{
	const char *full_cmd_string;	/* 命令的全部组成字符串, 即用户输入的原始字符串 */
	char *this_level_section; /* 当前层级的字符, 即将full_cmd_string切分后的分段, 如"show http pps"的第二级section为"http" */
	const char *cmd_introduce; /* 命令的作用介绍 */
	const char *arg_introduce; /* 参数的介绍 */
	iknow_cmd_cb_t cmd_cb_fun;
	const void *cmd_cb_fun_arg; /* 回调函数的自定义参数, 与用户的命令行参数无关 */
	int follow_arg; /* 表示此命令必须跟参数, 如set xxx, level xxx等. */
}cmd_info_t;

typedef struct{

}ctrl_cmd_info_t; /* 特殊控制类命令, 如'?', '!'等 */

typedef struct cmd_tree{
	cmd_info_t cmd_info;
	cltl_cmd_type_t ctrl_cmd_info; /* 控制命令类型 */
	struct cmd_tree *father; /* 上级父命令 */
	struct cmd_tree *brother_next; /* 同级命令, 用于输入了几个首字母但不带空格的tab帮助 */
	struct cmd_tree *child_next;    /* 下一级子命令, 用于带空格的tab帮助 */
}cmd_tree_t;


#define IKNOW_MODULE_MAX_NUM		(32)

#define CLIENT_HELLO_MESSAGE			"\a\bIclient\t\n"    /* 用于表示Iclient的通告信息, 夹在了控制字符, 防止与nc, telnet等混淆 */
#define CLIENT_TYPE_IKNOW		(1)
#define CLITNE_TYPE_NC_CLASS	(0)
typedef struct{
	int connfd;  /* 与client连接的socket-fd */
	int conn_type; /* 当前连接的客户端类型, 1:iclient; 0:通用客户端, 如nc, telnet等工具 */
	int global_flush_flag; /* 当前连接的全局打印开关 */
	int log_level;  /* 当前连接的日志等级 */
	int module_array_num;
	iknow_string_t module_array[IKNOW_MODULE_MAX_NUM]; /* 所有模块名称的数组, 可动态增长, 删除, realloc */
}iknow_client_state_t; /* 当前客户端连接的状态信息 */

typedef struct{
	pthread_t pid;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int thread_state;  /* 当前线程状态, state_t */
	void *phandle; /* 指向当前所属的ihandle */
	iknow_client_state_t *client_info; /* 与每个客户端的当前连接相关信息 */
}iknow_work_thread_t;

typedef struct{
	int listen_fd;
	int max_users;
	int work_thread_num; /* Iknow 内部工作线程数 */
	int max_thread_count; /* 线程数总数, 用于分别获取每个处理线程的信息 */
	cmd_tree_t cmd_root; /* 命令树根节点 */
	//MESA_list_t cmd_history; /* 历史命令记录, 上下箭头时可以快速执行最近曾执行过的命令 */
	iknow_work_thread_t *work_thread_array;
}inner_iknow_t;




typedef struct{
	unsigned int opt_type;
	unsigned int opt_len;
	//char opt_val[];
}ik_transfer_opt_t;


extern const char *Iknow_Version;
extern const char *Ikonw_Prompt;

void ik_cmd_list_free(cmd_tree_t *cmd_list_head);
cmd_tree_t *ik_cmd_list_create(const char *raw_cmd_str, const char *raw_cmd_introduce, 
		iknow_cmd_cb_t cmd_cb, const void *cmd_cb_arg, int follow_arg, const char *raw_arg_introduce);
int ik_cmd_string_equal(const char *cmd_str1, const char *cmd_str2);
int ik_set_worker_state(iknow_work_thread_t *pme, state_t thread_state);

#endif

