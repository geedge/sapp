
/*
	iknow_print()增加level, module参数, 像MESA_runtime_log一样, 
	方便控制日志等级和分模块处理.

	日志显示分为等级和模块分类, 
	首次登陆时, 默认显示所有等级和所有模块, 可通过set level, set module 设置.

	安全性:
		根据本地.password.key文件, 控制客户端是否需要输入密码.
		密码采用MD5后再移位, 异或后的密文传输.

		iknow_keygen -k 123456 -w .password.key, 用于生成密码文件.

	客户端支持退格, 上箭头键表示曾使用的历史命令, 自动补全到当前命令缓存中, 并显示到屏幕,
	nc,telnet等不支持, 
	

	命令使用树结构索引, 方便使用table键帮助提示,

	注册命令时分为三级,
	一级命令为show, set, help, exit等;
	二级命令为模块名、协议名、等, 如tcp, http, 或全局性参数, 如bps, pps等;
	三级命令为模块内部参数, 如url, syn-cnt, rst-cnt等;


	命令后跟';'表示命令结束后, TCP连接也立即关闭, 方便管道重定向, 如:
	iknow -i 127.0.0.1 -p 14723 show bps > xxx.log
	基于密码验证方式:
	iknow -i 127.0.0.1 -p 14723 -k 123456 show bps > xxx.log

	命令未输完时, 按tab键, 自动查询已输入的字母开头所有的命令;
	命令已输完且有空格, 按tab键, 自动查询本命令下一级可用命令或参数, 或者提示无此命令.

	命令后追加';'表示命令结束后连接立即结束, 方便非交互式应用;
	命令后追加'#n'表示此命令自动每隔n秒刷新一次, (此时立即命令变成verbose类型)仅用于一次性立即命令.

	打开全局刷屏后, 
	终端的ctrl+c 信号被捕获, 表示全局刷屏时停止, 不在表示退出终端的意思, 智能靠exit退出.
	在信号处理函数中, 自动发送off命令给服务器端.
	也可以手动输入"off", 关闭全局打印开关.

	关于帮助信息:
	module ?
	即可以直接输入模块名, 如http,
	也可以输入下一级命令, add, del等.
	显示成这样:
	#module ?
	args:
		xxx	set this module name
	sub cmd:
		add	add module name
		del	del module name
*/
#include "iknow.h"
#include "iknow_internal.h"
#include "dynamic_array.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <arpa/inet.h>
#ifdef __cplusplus
extern "C"
{
#endif

/* 
	IClient连接成功后, 先发送magic, 告诉服务器端是自定义客户端, 

	以后所有的命令前必须都带有opt_t;
	
	主要用于命令自动补全, 及历史命令快速查询.
	客户端输入tab后, 自动发送消息:

	OPT_TYPE=expect_complete_cmd, OPT_VALUE="show http b",
	服务器收到后,

	IClient存储一个环形链表, 存储最近几次的命令, 上箭头为最新的命令, 下箭头为最久的命令.
	
*/
static const char IK_CLIENT_MAGIC[] = 
{
	0xFF, '^', 'I', 'K', 'n', 'o', 'w', '-', 
	'C', 'l', 'i', 'e', 'n', 't', '$', 0xFF,
};

const int FD_BROADCAST	= 0x7FFFFFFF;

//#define CMD_TERMINATE_SIGN	'!' /* 命令终结符 */
#define CMD_TERMINATE_SIGN	'$' /* 命令终结符 */
#define CMD_DELIM_SIGN		';' /* 多个命令之间的分隔符 */
#define CMD_HELP_SIGN			'?' /* 命令帮助, 显示匹配当前前缀的所有命令 */
#define CMD_AUTO_COMPLETE	'\t' /* 命令自动补全, 仅客户端使用, 到服务器端转换成'?', 如果前缀有多条匹配, 则显示多条 */


int Iknow_server_version_VERSION_20160930;				  
const char *Iknow_Version = "Alpha-0.1 (2016-09-30)";
const char *Ikonw_Prompt  = "I#";
const char *Imodule = "IKNOW";


extern void ik_terminate_connection(iknow_work_thread_t *pme);
#if 0				  
/* Iknow模块内置一级命令 */
	"?",	/* 帮助, 补全 */
	"help",
	"exit",
	"quit",
	"bye"

	"q",	/* 这不是一个命令, 而是简写, 自动从当前级别所有命令中查找能匹配的命令, 如果只有一个则执行; 如果有多个, 提示"incomplete cmd!" */
	"show"
	"set"
	"level"
	"module"
	"on"  /* 全局打印开关 */
	"off" /* 全局打印开关, 如果刷屏过快, 也可以用ctrl+c关闭 */

/* Iknow模块内置二级命令 */

	"level 3"
	"module xxx" /* 只设置一个, 如果之前有其他的, 则全覆盖之 */
	"show module"
	"show level"
	"module add xxxx" /* 追加 */
	"module del xxxx"  /* 删除 */

#endif

#if 0
static const cmd_info_t iknow_reserve_cmd[] = 
{
	/* level one */
	{(char *)"?",		(char *)"get usage",				0,	NULL,	CMD_TYPE_RESERVED,	iknow_cmd_l1_cb_help,0},
	{(char *)"help",	(char *)"get usage",				0,	NULL,	CMD_TYPE_RESERVED,	iknow_cmd_l1_cb_help,0},
	{(char *)"exit",	(char *)"exit Iknow",			0,	NULL,	CMD_TYPE_RESERVED,	iknow_cmd_l1_cb_exit,0},
	{(char *)"quit",	(char *)"exit Iknow",			0,	NULL,	CMD_TYPE_RESERVED,	iknow_cmd_l1_cb_exit,0},
	{(char *)"bye",	(char *)"exit Iknow",			0,	NULL,	CMD_TYPE_RESERVED,	iknow_cmd_l1_cb_exit,0},
	//{(char *)"show",	(char *)"show something",		0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	//{(char *)"set",		(char *)"set attribute",			0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{(char *)"level",	(char *)"set log level",			1,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	//{(char *)"module",	(char *)"set module name",		0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{(char *)"on",		(char *)"global flush switch on",	0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},	
	{(char *)"off",		(char *)"global flush switch off",	0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},	

	/* level two */
	{(char *)"show module",(char *)"display current module enable",0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},	
	{(char *)"show level", (char *)"display current log level",		0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{(char *)"module add", (char *)"add a new module",		1,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{(char *)"module del", (char *)"del a current module",		1,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{(char *)"module set", (char *)"set module to single module",	1,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
	{NULL,				NULL,						0,	NULL,	CMD_TYPE_RESERVED,	NULL,0},
};


static void iknow_cmd_l1_cb_welcome(inner_iknow_t *ihandle, const char *args, int new_fd)
{
	ibroadcast(ihandle, new_fd, __LOG_LEVEL_MAX, Imodule, "Welcome to Iknow, version:%s!\n", Iknow_Version);	
	ibroadcast(ihandle, new_fd, __LOG_LEVEL_MAX, Imodule, "%s", Ikonw_Prompt);
}

static void iknow_cmd_l1_cb_help(iknow_handle apihandle, const char *args, int fd)
{
	int i;
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;

	/* to do:

		遍历一级命令树。
	*/
	ibroadcast(apihandle, fd, __LOG_LEVEL_MAX, Imodule, "Usage:\n");

	return;
}

static void iknow_cmd_l1_cb_exit(iknow_handle ihandle, const char *args, int fd)
{
	close(fd);
}

static void __iknow_set_global_switch(iknow_handle apihandle, int connfd, int flag)
{
	int i;
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	
	for(i = 0; i < ihandle->max_users; i++){
		pthread_mutex_lock(&ihandle->work_thread_array[i].mutex);
		if((IKNOW_THREAD_STATE_BUSY == ihandle->work_thread_array[i].thread_state)
		  &&(connfd == ihandle->work_thread_array[i].connfd)){
			/* to do:
				设置全局打印开关
			*/
			pthread_mutex_unlock(&ihandle->work_thread_array[i].mutex);
			break;
		}
		pthread_mutex_unlock(&ihandle->work_thread_array[i].mutex);
	}

	return;
}

static void iknow_cmd_l1_cb_on(iknow_handle ihandle, const char *args, int fd)
{
	ibroadcast(ihandle, fd, __LOG_LEVEL_MAX, Imodule,  "Global flush switch is on!\n");
}

static void iknow_cmd_l1_cb_off(iknow_handle ihandle, const char *args, int fd)
{
	ibroadcast(ihandle, fd, __LOG_LEVEL_MAX, Imodule, "Global flush switch is off!\n");
}


static int iknow_if_reserve_cmd(const char *cmd_str)
{
	int i;

	for(i = 0; iknow_reserve_cmd[i].cmd_string != NULL; i++){
		if(strcasecmp(cmd_str, iknow_reserve_cmd[i].cmd_string) == 0){
			return 1;
		}
	}

	return 0;
}


static int __iknow_build_reserve_cmd(inner_iknow_t *ihandle)
{
	int i, ret;

	for(i = 0; iknow_reserve_cmd[i].cmd_string != NULL; i++){
		ret = __do_iknow_register_cmd(ihandle, 
						  iknow_reserve_cmd[i].cmd_string,
						  iknow_reserve_cmd[i].cmd_introduce,
						  iknow_reserve_cmd[i].external_cmd_cb,
						  iknow_reserve_cmd[i].follow_arg,
						  iknow_reserve_cmd[i].arg_introduce,
						  CMD_TYPE_RESERVED);
		if(ret < 0){
			IPRINT("iknow_register_cmd '%s' error!\n", iknow_reserve_cmd[i].cmd_string);
		}
	}

	return 0;
}
#endif

static int del_last_char(char *data, int max_len, char del_char)
{
    int i, actual_len = 0;

	actual_len = strlen(data);
	
    for(i = actual_len-1; i >= 0; i--){
        if(del_char == data[i]){
            data[i] = '\0';
        }else{
		return 0;
        }
    }

    return 0;
}

#if 0
static int del_first_char(char *data, int max_len, char del_char)
{
    int i, actual_len = 0;

	actual_len = strlen(data);
	
    for(i = 0; i < actual_len; i++){
        if(del_char == data[i]){
            data[i] = '\0';
        }else{
		return 0;
        }
    }

    return 0;
}
#endif

 /* 删除末尾的换行符"\r\n" */
static void ik_del_last_rn(char *data, int max_len)
{
	del_last_char(data, max_len, '\r');
	del_last_char(data, max_len, '\n');

    return;
}

static void ik_del_last_blank(char *data, int max_len)
{
	while(1 == del_last_char(data, max_len, ' '));
	while(1 == del_last_char(data, max_len, '\t'));

    return;
}
#if 0
static void ik_del_first_blank(char *data, int max_len)
{
	while(1 == del_first_char(data, max_len, ' '));
	while(1 == del_first_char(data, max_len, '\t'));

    return;
}
#endif
#if 1

/*
	保留类似runtime_log功能, 向所有活动的客户端发送当前系统写到runtimelog的日志,
	便于实时查看, 且可以用grep搜索过滤, 还不会狂刷硬盘影响性能.
	因可能打开DEBUG级别, 造成网络拥塞, 此函数应使用非阻塞写!
*/
int iprintf(iknow_handle apihandle, iknow_conn iconn, const char *format, ...)
{
	va_list ap;
	int ret;
	char print_buf[IKNOW_CMD_BUF_LEN];
	//inner_iknow_t *ihandle;
	iknow_client_state_t *client_state;

	if(NULL == iconn || NULL == format || NULL == apihandle){
		return 0;
	}

	//ihandle = (inner_iknow_t *)apihandle;
	client_state = (iknow_client_state_t *)iconn;
	
	memset(print_buf,0,sizeof(print_buf));

	va_start(ap, format);
	ret = vsnprintf(print_buf, sizeof(print_buf), format, ap);
	va_end(ap);

	/* 单一目标 */
	ret = write(client_state->connfd, print_buf, ret);
	
	return ret;
}
#endif

extern int ik_inner_module_array_search(const char *module_name, int module_name_len, iknow_client_state_t *client_state);

static int ik_broadcast_switch(const iknow_work_thread_t *work_thread_info, 
		iknow_client_state_t *client_state, int log_level, const char *module_name)
{
	if(IKNOW_THREAD_STATE_BUSY == work_thread_info->thread_state
	  || IKNOW_THREAD_STATE_REDY == work_thread_info->thread_state){
	  	if((client_state->global_flush_flag != 0) 
	  	 && (log_level >= client_state->log_level)
	  	 &&(ik_inner_module_array_search(module_name, strlen(module_name), client_state) >= 0)){
			return 1;
		}
	}

	return 0;
}

int ibroadcast(iknow_handle apihandle, int log_level, const char *module, const char *format, ...)
{
	va_list ap;
	int i, ret;
	char print_buf[IKNOW_CMD_BUF_LEN];
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state;

	if(NULL == format || NULL == apihandle || ihandle->work_thread_num <= 0){
		return 0;
	}
	
	memset(print_buf,0,sizeof(print_buf));
	va_start(ap, format);
	ret = vsnprintf(print_buf, sizeof(print_buf), format, ap);
	va_end(ap);
	
	for(i = 0; i < ihandle->work_thread_num; i++){
		pthread_mutex_lock(&ihandle->work_thread_array[i].mutex);
		client_state =  ihandle->work_thread_array[i].client_info; 
		if(ik_broadcast_switch(&ihandle->work_thread_array[i], client_state, log_level, module) != 0){
			write(client_state->connfd, print_buf, ret);
		}
		pthread_mutex_unlock(&ihandle->work_thread_array[i].mutex);		
	}

	return ret;
}
 
#if 0
/* 工作线程, 所有相关工作均由此线程完成 */
static void *iknow_work_thread(void *arg)
{
	iknow_work_thread_t *pme = (iknow_work_thread_t *)arg;

	/* 新线程被系统调度运行后, 先将状态由INIT改为IDLE, 即可接收任务态 */
	pthread_mutex_lock(&pme->mutex);
	pme->thread_state = IKNOW_THREAD_STATE_IDLE;
	pthread_mutex_unlock(&pme->mutex);

	while(1){
		pthread_mutex_lock(&pme->mutex);
		if(IKNOW_THREAD_STATE_REDY == pme->thread_state){ /* 收到新任务 */
			pthread_mutex_unlock(&pme->mutex);
			goto task_run;
		}
		pthread_mutex_unlock(&pme->mutex);
		usleep(1000);
		continue;

task_run:
		pthread_mutex_lock(&pme->mutex);
		pme->thread_state = IKNOW_THREAD_STATE_BUSY;
		pthread_mutex_unlock(&pme->mutex);

		/* 任务运行时, 无需mutex的保护 */
		if(pme->cmd_info && pme->cmd_info->cmd_cb){
			pme->cmd_info->cmd_cb(pme->phandle, pme->connfd);
		}

		/* 任务运行结束, 将状态改为IDLE */
		pthread_mutex_lock(&pme->mutex);
		pme->thread_state = IKNOW_THREAD_STATE_IDLE;
		pme->cmd_info = NULL;
		pme->connfd = -1;
		pthread_mutex_unlock(&pme->mutex);
	}

	return NULL;
}

#endif





#if 0
/* 在新线程中执行不退出或长时间不能返回的命令 */
static int iknow_cmd_run_verb(inner_iknow_t *ihandle, cmd_info_t *cmd_info, int connfd)
{
	int ret;
	iknow_work_thread_t *new_idle_worker = NULL;
	
	new_idle_worker = __iknow_search_idle_work_thread(ihandle);
	if(NULL == new_idle_worker){
		iknow_print(ihandle, connfd, __LOG_LEVEL_MAX, Imodule, 
					"Too many users, no enough resource to run '%s'.\r\n", cmd_info->cmd_str);
		iknow_print(ihandle, connfd, __LOG_LEVEL_MAX, Imodule, "%s", prompt);
		return -1;
	}
	
	__iknow_push_cmd_task(ihandle, new_idle_worker, cmd_info, connfd);

	return 0;
}



static cmd_tree_t *ik_cmd_search(inner_iknow_t *ihandle, 
			cmd_tree_t *parent, cmd_tree_t *new_cmd_list)
{
	cmd_tree_t *match_cmd_node;

	match_cmd_node = ik_cmd_tree_iterate(ihandle->cmd_root.child_next, new_cmd_list);
	if(NULL == match_cmd_node){
		return NULL;
	}
	
	return match_cmd_node;
}


/* 
	TODO:
		简写命令, 如"sh ht b", 如果每层只命中一个命令, 则实际执行"show http bps";
		只命中了一半, 如"show http", 并不是一个完整命令, 提示"uncomplete cmd";
		

*/
cmd_tree_t *ik_cmd_match(inner_iknow_t *ihandle, const char *raw_cmd_str)
{
	cmd_tree_t *cmd_tree_root = &ihandle->cmd_root;
	cmd_tree_t *cmd_list_head, *user_cmd_node;
	//int ret = IKNOW_RET_SUCC;

	cmd_list_head = ik_cmd_list_create(raw_cmd_str, NULL, NULL, NULL, 0, NULL);
	if(NULL == cmd_list_head){
		//ret = IKNOW_ERR_INVALID_CMD;
		goto err1;
	}

	user_cmd_node = ik_cmd_search(ihandle, cmd_tree_root, cmd_list_head);
	if(NULL == user_cmd_node){
		//ret = IKNOW_ERR_INVALID_CMD;
		goto err2;

	}

	ik_cmd_list_free(cmd_list_head);

	return user_cmd_node;

err2:
	ik_cmd_list_free(cmd_list_head);
err1:
	return NULL;	
}
#endif

static void ik_build_previous_cmd(const cmd_tree_t *cmd_root, const cmd_tree_t *cur_cmd, char *cmd_buf, int *buf_len)
{
	int ret;
	
	if(NULL == cur_cmd || cmd_root == cur_cmd){
		return; 
	}

	ik_build_previous_cmd(cmd_root, cur_cmd->father, cmd_buf, buf_len);

	ret = snprintf(cmd_buf+*buf_len, IKNOW_CMD_BUF_LEN-*buf_len, "%s ", cur_cmd->cmd_info.this_level_section);
	*buf_len += ret;

	return;
}

static void ik_build_subsequent_cmd(const cmd_tree_t *cur_cmd, char *cmd_buf, int *buf_len)
{
	int ret;
	
	if(NULL == cur_cmd){
		return; 
	}

	ik_build_subsequent_cmd(cur_cmd->child_next, cmd_buf, buf_len);

	if(0 == *buf_len){
		ret = snprintf(cmd_buf+*buf_len, IKNOW_CMD_BUF_LEN-*buf_len, "%s", cur_cmd->cmd_info.this_level_section);/* 第一条顶头写 */
	}else{
		ret = snprintf(cmd_buf+*buf_len, IKNOW_CMD_BUF_LEN-*buf_len, " %s", cur_cmd->cmd_info.this_level_section);/* 后续的留空格 */
	}
	
	*buf_len += ret;

	return;
}


static int ik_exec_ctrl_uncomplete_cmd(inner_iknow_t *ihandle, iknow_client_state_t *client_state,
		const cmd_tree_t *brother_head, cmd_tree_t *client_cmd, const char *previous_cmd)
{
	//char valid_cmd[IKNOW_CMD_BUF_LEN];
	const cmd_tree_t *tmp = brother_head;

	if(NULL == tmp){
		iprintf(ihandle, client_state, "<CR>"); /* 命令已终结 */
		return 0;
	}

	while(tmp){
		if(strncasecmp(tmp->cmd_info.this_level_section, client_cmd->cmd_info.this_level_section, strlen(client_cmd->cmd_info.this_level_section)) == 0){
			iprintf(ihandle, client_state,"%s %s\n", previous_cmd, tmp->cmd_info.this_level_section);
		}
		tmp = tmp->brother_next;
	}

	return 0;
}

/*
	return value:
		1 : 执行类命令, 如'?'
		0 : 辅助非执行类命令, 如'!', 需要执行后续命令.
*/
static int ik_exec_ctrl_cmd(inner_iknow_t *ihandle, iknow_client_state_t *client_state,
						cmd_tree_t *brother_head, cmd_tree_t *client_cmd)
{
	int ret = 0;
	char previous_cmd[IKNOW_CMD_BUF_LEN];
	char uncompleted_cmd[IKNOW_CMD_BUF_LEN];
	int tot_cmd_len = 0;

	memset(previous_cmd, 0, IKNOW_CMD_BUF_LEN);
	memset(uncompleted_cmd, 0, IKNOW_CMD_BUF_LEN);
	
	switch(client_cmd->ctrl_cmd_info){
		case CTRL_CMD_AUTO_COMPLETE:
			if(brother_head){
				ik_build_previous_cmd(&ihandle->cmd_root, brother_head->father, previous_cmd, &tot_cmd_len);
			}
			ik_exec_ctrl_uncomplete_cmd(ihandle, client_state, brother_head, client_cmd, previous_cmd);
			ret = 1;
		break;

		case CTRL_CMD_AUTO_CLOSE:
			/* 辅助控制类命令, 无需真正执行 */
		break;

		default:
		break;
	}

	return ret;
}

static cmd_tree_t *ik_cmd_tree_iterate(inner_iknow_t *ihandle,iknow_work_thread_t *pme, 
	iknow_client_state_t *client_state,cmd_tree_t *brother_head, cmd_tree_t *new_cmd_list)
{
	cmd_tree_t *final_cmd = NULL;
	cmd_tree_t *tmp, *next;

	char subsequent_cmd_str[IKNOW_CMD_BUF_LEN];
	int tot_cmd_len;
	int terminate_flag = 0;
	
	if(NULL == brother_head || NULL == new_cmd_list){
		return NULL;
	}

	tmp = brother_head;

	while(tmp != NULL){
		next = tmp->brother_next;

		if((new_cmd_list->cmd_info.this_level_section[0] == '\0') 
		 && (new_cmd_list->ctrl_cmd_info != NON_CTRL_CMD)){
		 	if(CTRL_CMD_AUTO_COMPLETE == new_cmd_list->ctrl_cmd_info){
				ik_exec_ctrl_cmd(ihandle, client_state, brother_head, new_cmd_list);
		 	}else if(CTRL_CMD_AUTO_CLOSE == new_cmd_list->ctrl_cmd_info){
				terminate_flag = 1;
		 	}
		 	goto done;
		}
		if(ik_cmd_string_equal(tmp->cmd_info.this_level_section, new_cmd_list->cmd_info.this_level_section)){
			final_cmd = tmp;
			break;
		}

		tmp = next;
	}

	if(NULL == final_cmd){
		iprintf(ihandle, client_state, "Command Not found!\n");
		return NULL;
	}

	if(new_cmd_list->ctrl_cmd_info & CTRL_CMD_AUTO_CLOSE){
		terminate_flag = 1;
	}
		
	if(NULL == new_cmd_list->child_next || NULL == final_cmd->child_next){ 
		if((NULL == final_cmd->child_next) && (new_cmd_list->child_next!= NULL)){ /* 已到叶子节点, 但还有后续字符 */
			if(final_cmd->cmd_info.follow_arg != 0){
				tot_cmd_len = 0;
				memset(subsequent_cmd_str, 0, IKNOW_CMD_BUF_LEN);
				ik_build_subsequent_cmd(new_cmd_list->child_next, subsequent_cmd_str, &tot_cmd_len);
				(*final_cmd->cmd_info.cmd_cb_fun)(ihandle, (void *)client_state, final_cmd->cmd_info.cmd_cb_fun_arg,subsequent_cmd_str);
				if(new_cmd_list->ctrl_cmd_info & CTRL_CMD_AUTO_CLOSE
				|| new_cmd_list->child_next->ctrl_cmd_info & CTRL_CMD_AUTO_CLOSE){
					terminate_flag = 1;
				}
				goto done;
			}else{
				if(new_cmd_list->child_next->ctrl_cmd_info == CTRL_CMD_AUTO_CLOSE){
					(*final_cmd->cmd_info.cmd_cb_fun)(ihandle, (void *)client_state, final_cmd->cmd_info.cmd_cb_fun_arg, NULL);
					terminate_flag = 1;
					goto done;
				}			
				if(new_cmd_list->child_next->ctrl_cmd_info != NON_CTRL_CMD){
					ik_exec_ctrl_cmd(ihandle, client_state, final_cmd->child_next, new_cmd_list->child_next);
				}else{
					iprintf(ihandle, client_state, "Unknown command!\n");
				}	
			}
		}else if((NULL == new_cmd_list->child_next) && (final_cmd->child_next!= NULL)){/* 命令未终结到叶子节点, 不完全命令 */
			if(new_cmd_list->ctrl_cmd_info != NON_CTRL_CMD){
				ik_exec_ctrl_cmd(ihandle, client_state, final_cmd, new_cmd_list);
			}else{
				iprintf(ihandle, client_state, "Uncompleted command!\n");
			}
		}else{	
			/* TODO, 命令行参数未解析 */
			(*final_cmd->cmd_info.cmd_cb_fun)(ihandle, (void *)client_state, final_cmd->cmd_info.cmd_cb_fun_arg, NULL);
			if(new_cmd_list->ctrl_cmd_info & CTRL_CMD_AUTO_CLOSE){
				terminate_flag = 1;
			}			
			goto done;
		}
	}else{
		ik_cmd_tree_iterate(ihandle, pme, client_state, final_cmd->child_next, new_cmd_list->child_next);
	}
	
done:
	if(terminate_flag){
		ik_terminate_connection(pme);
	}

	return final_cmd;
}

static cmd_tree_t *ik_cmd_search(inner_iknow_t *ihandle, iknow_work_thread_t *pme,
		iknow_client_state_t *client_state, cmd_tree_t *parent, cmd_tree_t *new_cmd_list)
{
	cmd_tree_t *match_cmd_node;

	match_cmd_node = ik_cmd_tree_iterate(ihandle, pme, client_state, ihandle->cmd_root.child_next, new_cmd_list);
	if(NULL == match_cmd_node){
		return NULL;
	}
	
	return match_cmd_node;
}
 
int ik_cmd_parse(inner_iknow_t *ihandle, iknow_work_thread_t *pme,
						iknow_client_state_t *client_state, const char *raw_cmd_str)
{
	cmd_tree_t *cmd_list_head;
	int ret = IKNOW_RET_SUCC;

	cmd_list_head = ik_cmd_list_create(raw_cmd_str, NULL, NULL, NULL, 0, NULL);
	if(NULL == cmd_list_head){
		ret = IKNOW_ERR_INVALID_CMD;
		goto err1;
	}

	ik_cmd_search(ihandle, pme, client_state, &ihandle->cmd_root, cmd_list_head);

	ik_cmd_list_free(cmd_list_head);

	return ret;

err1:
	return ret;		
}
#if 0
static int ik_search_terminate_flag(char *cmd_buf)
{
	int cmd_str_len;

	cmd_str_len = strlen(cmd_buf);
	if(CMD_TERMINATE_SIGN == cmd_buf[cmd_str_len-1]){
		cmd_buf[cmd_str_len-1] = '\0';
		return 1;
	}

	return 0;
}
#endif
/*
    读取一行数据, 包含末尾的"\n"符, 
    但为了调用者处理方便, 直接把'\n'改成了'\0', 可直接按字符串操作.
    
    return value:
    >0: line length;
    -1: not found '\r\n'
    -2: line_buf_len is not enough
*/
int ik_string_readline(const char *raw_data, int raw_data_len, 
							 char *line_buf, int line_buf_len)
{
    char *line_end_ptr;
    int line_len;

    line_end_ptr = (char *)memmem((const void *)raw_data, (size_t)raw_data_len, (const void *)"\n", (size_t)1);
    if(NULL == line_end_ptr){
        return -1;
    }
    
    line_len = line_end_ptr - raw_data + 1; /* include "\n"*/
    if(line_buf_len < line_len){
        return -2;
    }

    memcpy(line_buf, raw_data, line_len);
    line_buf[line_len-1] = '\0'; /* modify '\n' to EOF */

    return line_len;
}

/* reliable read */
static inline ssize_t Rread(int fd, void *buf, size_t expect_count)
{
	ssize_t ret;
	void *save_ptr = buf;
	size_t left_count = expect_count;
	
	while(left_count > 0){
retry:
		ret = read(fd, save_ptr, left_count);
		if(ret < 0){
			switch(errno){
				case EAGAIN:
					usleep(1);
					/* no break here!!! */
				case EINTR:
					goto retry;
				break;

				default:
					printf("Read error:%s, ptr=%p, expect_count=%lu, left_count=%lu\n", 
						  strerror(errno), save_ptr, expect_count, left_count);
				goto err;
			}
		}else if(0 == ret){
			return 0; /* peer close */
		}else{
			save_ptr = (char *)save_ptr + ret;
			left_count -= ret;
		}
	}

	return expect_count - left_count;
err:
	return -1;
}

/*  
	从网络中获取一段完整的命令字符, 即末尾包含"\n"的, 
	因为客户端可能用telnet工具连接, 每输入一个字符都会立即传回到服务器, 必须积攒到输入回车为止!
*/
static int ik_get_complete_cmd(char *cmd_buf, int max_buf_len, int fd)
{
	int tot_len = 0, read_len;

	while(tot_len <= max_buf_len){
		read_len = Rread(fd, cmd_buf+tot_len, 1); /* 仿照telnet协议, 每次处理1个字节 */
		if(0 == read_len){
			IPRINT("peer closed, fd=%d!\n", fd);
			goto err;
		}else if(read_len < 0){
			IPRINT("read fd:%d error:%s\n", fd, strerror(errno));
			goto err;
		}
		if('\n' == cmd_buf[tot_len]){ /* 为了同时兼容unix, windows, dos下的文件, 以'\n'为换行符号, '\r'忽略 */
			tot_len += read_len;
			break; /* 读到回车换行符, 表示获取了一段完整的命令 */
		}

		tot_len += read_len;
	}

	return tot_len;

err:
	return -1;
}

void ik_terminate_connection(iknow_work_thread_t *pme)
{
	int i;
	iknow_client_state_t *client_state = pme->client_info;

	if(client_state->connfd > 0){
		close(client_state->connfd);
		client_state->connfd = -1;
	}
	
	for(i = 0; i < IKNOW_MODULE_MAX_NUM; i++){
		if(client_state->module_array[i].module_str){
			free((void *)client_state->module_array[i].module_str);
			client_state->module_array[i].module_str = NULL;
		}
	}

	memset(client_state, 0, sizeof(iknow_client_state_t));
	ik_set_worker_state(pme, IKNOW_THREAD_STATE_IDLE);
}

#if 0
static int ik_exec_cmd(iknow_work_thread_t *pme, iknow_client_state_t *client_state, const cmd_tree_t *match_cmd_node)
{
	if(NULL == match_cmd_node->cmd_info.cmd_cb_fun){
		iprintf(pme->phandle, client_state, "Invalid command.\nI#");
		return -1;
	}
	
	(*match_cmd_node->cmd_info.cmd_cb_fun)(pme->phandle, (void *)client_state, NULL);
	
	return 0;
}
#endif
static int ik_is_command_valid_character(int letter)
{
	int ret = 0;
	
	if(isalnum(letter)){
		return 1;
	}

	/* 非字母数字的控制类字符 */
	switch(letter){
		case ' ':
		case ';':
		case '?':
		case '$':
		case '\t':
		case '\r':
		case '\n':
			ret = 1;
		break;

		default:
			ret = 0;
	}

	return ret;
}

#define CMD_SECTION_STATE_NOT_BEGIN		(1) /* 命令还未开始 */
#define CMD_SECTION_STATE_FIRST_CMD		(2) /* 已收到命令第一个字符 */
#define CMD_SECTION_STATE_CTRL_CMD		(3) /* 收到控制类字符, 如'$', ';', '?' */
static int ik_client_cmd_syntax_check(const char *raw_cmd_str)
{
	int res = 0;
	int i;
	int cmd_state = CMD_SECTION_STATE_NOT_BEGIN;
	char cur_letter;
	int ctrl_cmd_flag = 0;

	for(i = 0; raw_cmd_str[i] != '\0'; i++){
		cur_letter = raw_cmd_str[i];
		if(ik_is_command_valid_character(cur_letter) == 0){
			goto err;
		}
		switch(cmd_state){
			case CMD_SECTION_STATE_NOT_BEGIN:
			{
				if(ctrl_cmd_flag != 0){
					goto err;
				}		
				if(' ' == cur_letter || '\t' == cur_letter){
					// OK
				}else if(isalnum(cur_letter)){
					//OK
					cmd_state = CMD_SECTION_STATE_FIRST_CMD;
				}else if('?' == cur_letter || ';' == cur_letter || '$' == cur_letter){
					ctrl_cmd_flag = 1;
					cmd_state = CMD_SECTION_STATE_CTRL_CMD;
				}else{
					goto err;
				}
			}
			break;

			case CMD_SECTION_STATE_FIRST_CMD:
			{
				if(ctrl_cmd_flag != 0){
					goto err;
				}				
				if(isalnum(cur_letter)){
					//OK
				}else if(' ' == cur_letter || '\t' == cur_letter){
					//OK
					cmd_state = CMD_SECTION_STATE_NOT_BEGIN;
				}else if('?' == cur_letter || ';' == cur_letter || '$' == cur_letter){
					ctrl_cmd_flag = 1;
					cmd_state = CMD_SECTION_STATE_CTRL_CMD;
				}else{
					goto err;
				}
			}
			break;

			case CMD_SECTION_STATE_CTRL_CMD:
			{
				if('?' == cur_letter || ';' == cur_letter || '$' == cur_letter){
					//OK
				}else{
					goto err;
				}
			}
			break;

		}
	}

	return res;

err:
	return -1;
}

/* 
	将用';'连接的命令分割开, 单独处理.
*/
static int ik_split_continuous_cmd(iknow_work_thread_t *pme, iknow_client_state_t *client_state, char *client_input_cmd, int cmd_len)
{
	const char *delim = ";"; /* 连续多条命令分隔符 */
	char *save_ptr;
	char *cmd_start_ptr;
	char *cmd_buf = client_input_cmd;
	int ret;
	
	ik_del_last_rn(cmd_buf, cmd_len);
	
	while((cmd_start_ptr = strtok_r(cmd_buf, delim, &save_ptr)) != NULL){
		IPRINT("Server: get cmd '%s'\n", cmd_start_ptr);

		if(ik_client_cmd_syntax_check(cmd_start_ptr) < 0){
			iprintf(pme->phandle, client_state, "\ncommand: '%s' syntax invalid!\nI#", cmd_start_ptr);
			break;
		}

		//ik_del_first_blank(cmd_start_ptr, strlen(cmd_start_ptr));
		while(' ' == *cmd_start_ptr || '\t' == *cmd_start_ptr){ /* skip blank */
			cmd_start_ptr++;
		}
		ik_del_last_blank(cmd_start_ptr, strlen(cmd_start_ptr));

#if 0				
		if(CMD_TERMINATE_SIGN == *cmd_start_ptr){
			goto term;
		}

		if(ik_search_terminate_flag(cmd_start_ptr)){
			terminal_flag = 1;
		}
	
		match_cmd_node = ik_cmd_match((inner_iknow_t *)pme->phandle, cmd_start_ptr);	
		if(NULL == match_cmd_node){
			iprintf(pme->phandle, client_state, "\ncommand '%s' not found!\nI#", cmd_start_ptr);
			break;
		}

		ret = ik_exec_cmd(pme, client_state, match_cmd_node);
		if(terminal_flag){
			goto term;
		}
#else
		ret = ik_cmd_parse((inner_iknow_t *)pme->phandle, pme, client_state, cmd_start_ptr);
		if(ret < 0){
			break;
		}
#endif

		iprintf(pme->phandle, client_state, "\nI#"); /* 每个命令结束后, 打印提示符 */
		cmd_buf = NULL;
	}

	return ret;
}

/* server端, 只支持单行单命令, 不支持多单行多命令.

 其他特殊命令:
   如上箭头, 退格键, tab键等, 需要在client端处理.

	a; b ; c; | grep xxx
	a; b; c > xxx.log
	client端需要拆分为3个命令分别发给server端.
*/
int ik_run_cmd(iknow_work_thread_t *pme)
{
	int ret;
	char socket_buf[IKNOW_CMD_BUF_LEN];
	//inner_iknow_t *ihandle  = (inner_iknow_t *)pme->phandle;
	int tot_len = -1;
	iknow_client_state_t *client_state = pme->client_info;

	memset(socket_buf, 0, IKNOW_CMD_BUF_LEN);
	tot_len = ik_get_complete_cmd(socket_buf, IKNOW_CMD_BUF_LEN, client_state->connfd);
	if(tot_len < 0){
		goto err;
	}

	ret = ik_split_continuous_cmd(pme, client_state, socket_buf, tot_len);
	if(ret < 0){
		goto err;
	}
	
	return 0;

err:
	return -1;
}




#ifdef __cplusplus
}
#endif


