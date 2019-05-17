#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include "iknow_internal.h"
#include "MESA_list.h"
#include "list_entry.h"

#ifdef __cplusplus
extern "C"
{
#endif

static char *ik_strdup(const char *src)
{
	char *dst;
	
	int len = strlen(src) + 1; /* plus EOF */

	dst = malloc(len);

	memcpy(dst, src, len);

	return dst;
}
void cmd_tree_debug(const cmd_tree_t *cmd_node, int level)
{
	const cmd_tree_t *list_node;
	const cmd_tree_t *next_brother;

	if(NULL == cmd_node){
		return;
	}
	
	switch(level){
		case 0:
		break;

		case 1:
			printf("\n");
		break;

		case 2:
			printf("\n\n");
		break;
		
		case 3:
			printf("\n\n\n");
		break;	
		
		case 4:
			printf("\n\n\n\n");
		break;			
	}

	printf("%s\n", cmd_node->cmd_info.this_level_section);

	cmd_tree_debug(cmd_node->child_next, level+1);

	list_node = cmd_node->brother_next;

	while(list_node != NULL){
		next_brother = list_node->brother_next;
		printf("\t %s", list_node->cmd_info.this_level_section);
		list_node = next_brother;
	}

}

/* 仅用于输入的命令串, 不存才brother_list. */
void ik_cmd_list_free(cmd_tree_t *cmd_list_head)
{
	cmd_tree_t *cmd_node, *child_cmd_node;

	if(NULL == cmd_list_head){
		return;
	}

	cmd_node = cmd_list_head;
	
	while(cmd_node){
		child_cmd_node = cmd_node->child_next;
		/* full_cmd_string不需要free, 存储于命令树中 */
		if(cmd_node->cmd_info.this_level_section){
			free(cmd_node->cmd_info.this_level_section);
		}
		free(cmd_node);
		cmd_node = child_cmd_node;
	}

	return;
}



int ik_cmd_string_equal(const char *cmd_str1, const char *cmd_str2)
{
	/* 比较两个字符串完全一样(不区别大小写) */
	if((strncasecmp(cmd_str1, cmd_str2, strlen(cmd_str1)) == 0)
	 && (strncasecmp(cmd_str1, cmd_str2, strlen(cmd_str2)) == 0)){
		return 1;
	}

	return 0;
}

cmd_tree_t *ik_cmd_brother_match(cmd_tree_t *brother_list_head, cmd_tree_t *new_cmd)
{
	cmd_tree_t *list_node, *next_node;
	
	if(NULL == brother_list_head){ /* 还无此级别命令被注册过 */
		return NULL;
	}

	list_node = brother_list_head;

	while(list_node != NULL){
		next_node = list_node->brother_next;
		if(ik_cmd_string_equal(list_node->cmd_info.this_level_section, new_cmd->cmd_info.this_level_section)){
			return list_node;
		}
		list_node = next_node;
	}

	return NULL;
}


int ik_cmd_root_init(cmd_tree_t *cmd_root)
{
	memset(cmd_root, 0, sizeof(cmd_tree_t));
	cmd_root->cmd_info.full_cmd_string = ik_strdup("#");
	cmd_root->cmd_info.this_level_section = ik_strdup("#");
	cmd_root->cmd_info.cmd_introduce = ik_strdup("root cmd node");

	return 0;
}

/* 不允许一条命令是另一条命令的真子集, 检查重复命令 */
static int ik_register_cmd_legality_check(cmd_tree_t *intree_cmd_node, cmd_tree_t *new_cmd_node, const char *input_cmd_str)
{
	if((NULL == intree_cmd_node->child_next) 
	 &&(intree_cmd_node->cmd_info.cmd_cb_fun != NULL)
	  &&(new_cmd_node->child_next != NULL)){
		printf("cmd:'%s' is superset of current tree.\n", input_cmd_str);
		return -1;
	}

	if((intree_cmd_node->child_next != NULL) 
	  &&(NULL == new_cmd_node->child_next)){
		printf("cmd:'%s' is subset of current tree.\n", input_cmd_str);
		return -1;
	}

	if((NULL == intree_cmd_node->child_next) 
	  && (NULL == new_cmd_node->child_next)){
		printf("cmd:'%s' is already registered!\n", input_cmd_str);	
		return IKNOW_ERR_DUPLICATE_CMD;
	}

	return (int)IKNOW_RET_SUCC;
}

static cmd_tree_t *ik_cmd_tree_node_dup(const cmd_tree_t * tree_node)
{
	cmd_tree_t *new_cmd_node;

	new_cmd_node = malloc(sizeof(cmd_tree_t));
	memset(new_cmd_node, 0, sizeof(cmd_tree_t));

	new_cmd_node->cmd_info.this_level_section = ik_strdup(tree_node->cmd_info.this_level_section);

	return new_cmd_node;
}


static cmd_tree_t *ik_new_cmd_section_list_insert(cmd_tree_t *parent, cmd_tree_t *new_cmd_list)
{
	cmd_tree_t *new_child_node;
	cmd_tree_t *leaf_node;
	cmd_tree_t *brother_head;

	if(NULL == parent->child_next){ /* 本级第一个命令 */
		new_child_node = ik_cmd_tree_node_dup(new_cmd_list);
		new_child_node->father = parent;
		parent->child_next = new_child_node;
		leaf_node = new_child_node;
	}else{
		brother_head = parent->child_next;
		new_child_node = ik_cmd_tree_node_dup(new_cmd_list);
		new_child_node->father = parent;

		new_child_node->brother_next = brother_head->brother_next;
		brother_head->brother_next = new_child_node;
		leaf_node = new_child_node;
	}

	if(NULL == new_cmd_list->child_next){ /* 叶子节点 */
		leaf_node->cmd_info.full_cmd_string = ik_strdup(new_cmd_list->cmd_info.full_cmd_string);
		if(new_cmd_list->cmd_info.cmd_introduce){
			leaf_node->cmd_info.cmd_introduce = ik_strdup(new_cmd_list->cmd_info.cmd_introduce);
		}
		if(new_cmd_list->cmd_info.arg_introduce){
			leaf_node->cmd_info.arg_introduce = ik_strdup(new_cmd_list->cmd_info.arg_introduce);
		}
		leaf_node->cmd_info.cmd_cb_fun = new_cmd_list->cmd_info.cmd_cb_fun;
		leaf_node->cmd_info.follow_arg = new_cmd_list->cmd_info.follow_arg;
		leaf_node->cmd_info.cmd_cb_fun_arg = new_cmd_list->cmd_info.cmd_cb_fun_arg;
	}
		
	return new_child_node;
}



/* 
	将临时生成的链表, 例:  "show"->"http"->"bps";  
	插入当前总命令树中. 
*/
static int ik_cmd_tree_create(cmd_tree_t *parent, cmd_tree_t *new_cmd_list, const char *input_cmd_str)
{
	int res = (int)IKNOW_RET_SUCC;
	cmd_tree_t *cmd_section_node;

	if(NULL == new_cmd_list){
		return res;
	}

	cmd_section_node = ik_cmd_brother_match(parent->child_next, new_cmd_list);
	if(NULL == cmd_section_node){
		/* 本级没有相同的section, 新建命令section */
		cmd_section_node = ik_new_cmd_section_list_insert(parent, new_cmd_list);
	}else{
		/* 已有相同的section, 检查是否合法 */
		if(ik_register_cmd_legality_check(cmd_section_node, new_cmd_list, input_cmd_str) < 0){
			res = (int)IKNOW_ERR_INVALID_CMD_TYPE;
			goto err;
		}
	}

	res = ik_cmd_tree_create(cmd_section_node,
						   new_cmd_list->child_next,
						   input_cmd_str);
							   
	return res;

err:
	return res;
}

static int ik_parse_ctrl_cmd(cmd_tree_t *list_node, const char *cmd_section)
{
	char *question_mark, *exclamation_mark;

	list_node->ctrl_cmd_info = NON_CTRL_CMD;
	
	question_mark = (char *)memchr(cmd_section, '?', strlen(cmd_section));
	if(question_mark != NULL){
		list_node->ctrl_cmd_info |= CTRL_CMD_AUTO_COMPLETE;
	}

	exclamation_mark = (char *)memchr(cmd_section, '$', strlen(cmd_section));
	if(exclamation_mark != NULL){
		list_node->ctrl_cmd_info |= CTRL_CMD_AUTO_CLOSE;
	}

	if(question_mark != NULL){
		*question_mark = '\0';
	}
	if(exclamation_mark != NULL){
		*exclamation_mark = '\0';
	}

	return 1;
}

/* 
	将用户输入的原始字符串, 如: "show http bps",
	按空格分隔, 转换成"show"->"http"->"bps"链表.
*/
cmd_tree_t *ik_cmd_list_create(const char *raw_cmd_str, const char *raw_cmd_introduce, 
		iknow_cmd_cb_t cmd_cb, const void *cmd_cb_arg, int follow_arg, const char *raw_arg_introduce)
{

	char *save_ptr;
	const char *delim = " \t";
	char *local_saved_cmd_str, *parse_cmd_str;
	cmd_tree_t *cmd_list_head = NULL, *list_node, *father_cmd = NULL, *last_leaf_node = NULL;
	char *cmd_section;

	/* 命令分析需要strtok操作, 为了不修改原始输入, 先将原始字符串复制一份 */
	local_saved_cmd_str = (char *)ik_strdup(raw_cmd_str);
	parse_cmd_str = local_saved_cmd_str;
	
	while((cmd_section = strtok_r(parse_cmd_str, delim, &save_ptr)) != NULL){
		if((isalnum(cmd_section[0]) == 0) && (cmd_section[0] != '?') && (cmd_section[0] != '!')){
			printf("Invalid cmd:'%s', cmd section must begin with alpha or '?', '!'.\n", raw_cmd_str);
			goto err;
		}

		list_node = (cmd_tree_t *)malloc(sizeof(cmd_tree_t));
		memset(list_node, 0, sizeof(cmd_tree_t));
		list_node->cmd_info.this_level_section = ik_strdup(cmd_section);
		
		ik_parse_ctrl_cmd(list_node, list_node->cmd_info.this_level_section);

		if(cmd_section[0] == '\0'){
			list_node->cmd_info.this_level_section[0] = '\0';/* 全部为纯控制类命令section, 当前段的字符串为空串 */
		}else{
			;
		}
		
		//ik_parse_ctrl_cmd(list_node, cmd_section);
		
		
		if(NULL == father_cmd){ /* first section */
			cmd_list_head = list_node;
		}else{
			father_cmd->child_next = list_node;
			list_node->father = father_cmd;
		}
		father_cmd = list_node;
		last_leaf_node = list_node;
		parse_cmd_str = NULL;
	}

	/* 完整的命令信息最终存储于最后命令树的叶子节点中 */
	last_leaf_node->cmd_info.full_cmd_string = raw_cmd_str;
	last_leaf_node->cmd_info.cmd_introduce = raw_cmd_introduce;
	last_leaf_node->cmd_info.arg_introduce = raw_arg_introduce;
	last_leaf_node->cmd_info.follow_arg = follow_arg;
	last_leaf_node->cmd_info.cmd_cb_fun = cmd_cb;
	last_leaf_node->cmd_info.cmd_cb_fun_arg = cmd_cb_arg; /* 2015-09-21 lijia add */

	free(local_saved_cmd_str);

	return cmd_list_head;

err:
	free(parse_cmd_str);
	ik_cmd_list_free(cmd_list_head);
	return NULL;
}

/*
	to do:
	需要检查一个命令是另一个命令的子集情况,
	如已注册命令:
		show http bps
	再注册"show http"是不允许的.
	即新的命令终结点的child必须为NULL.
*/
int iknow_register_cmd(iknow_handle apihandle, 
				  const char *input_cmd_str, const char *input_cmd_introduce, iknow_cmd_cb_t cmd_cb,
				 const void *cmd_cb_arg,  int follow_arg, const char *input_arg_introduce)
{
	int ret;
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	 
	 
	char *dup_cmd_string = NULL, *dup_cmd_introduce = NULL, *dup_arg_introduce = NULL;
	cmd_tree_t *cmd_root;
	cmd_tree_t *user_new_cmd_list;

	if(NULL == apihandle || NULL == input_cmd_str || NULL == cmd_cb){
		return -1;
	}

	cmd_root = &ihandle->cmd_root;

	/* 用户输入的可能是函数栈里的数据, 返回后内存不再有意义. 将其复制一份, 做为原始命令行输入 */
	dup_cmd_string = ik_strdup(input_cmd_str);
	if(input_cmd_introduce){
		dup_cmd_introduce = ik_strdup(input_cmd_introduce);
	}
	if(input_arg_introduce){
		dup_arg_introduce = ik_strdup(input_arg_introduce);
	}
	
	user_new_cmd_list = ik_cmd_list_create(dup_cmd_string, dup_cmd_introduce, cmd_cb, cmd_cb_arg, follow_arg, dup_arg_introduce);
	if(NULL == user_new_cmd_list){
		ret = IKNOW_ERR_INVALID_CMD;
		goto err1;
	}

	ret = ik_cmd_tree_create(cmd_root, user_new_cmd_list, input_cmd_str);
	if(ret < 0){
		ret = IKNOW_ERR_INVALID_CMD;
		goto err2;
	}

	free(dup_cmd_string);
	if(dup_cmd_introduce){
		free(dup_cmd_introduce);
	}
	if(dup_arg_introduce){
		free(dup_arg_introduce);
	}
	ik_cmd_list_free(user_new_cmd_list);

	//cmd_tree_debug(cmd_root, 0);
	
	return IKNOW_RET_SUCC;

err2:
	ik_cmd_list_free(user_new_cmd_list);
	
err1:	
	free(dup_cmd_string);
	free(dup_cmd_introduce);
	free(dup_arg_introduce);
	
	return IKNOW_ERR_INVALID_CMD;
}

static void __sig_handler(int sig_no)
{
	/* Iknow 终端按ctrl+c动作, 关闭全局打印开关, 将日志等级设为最高，modul设为空,
		并提示:
		broadcast off,
		set level = 8,
		set module = NULL,
		#
	*/
	return;
}

static int __register_sig_handle(int signum, SIG_HANDLE_T fun)
{
    struct sigaction newact;

    /* call the function "fun" when receive a signal of "signum" */
    newact.sa_handler = fun; 
    sigemptyset(&newact.sa_mask);
    newact.sa_flags = 0;
    
    if(sigaction(signum, &newact, NULL) != 0)
    {
        printf("sigaction error!\n");
        return -1;
    }

    return 0;
}

static long ik_inner_cmd_help(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	const cmd_tree_t *cmd_node = ihandle->cmd_root.child_next;

	while(cmd_node != NULL){
		iprintf(ihandle, iconn, "%s\t%s\n", cmd_node->cmd_info.this_level_section, cmd_node->cmd_info.cmd_introduce);
		cmd_node = cmd_node->brother_next;
	}
	
	return 0;
}

static long ik_inner_cmd_quit(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	
	iprintf(ihandle, iconn, "bye!\n");
	//ik_terminate_connection(); /* TODO 1: 怎么调用此函数呢?  ihandle换成pme吧? */
	close(client_state->connfd);
	return 0;
}

static long ik_inner_cmd_show_ver(iknow_handle ihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	iprintf(ihandle, iconn, "IKnow version:%s.\n", Iknow_Version);
	return 0;
}

static long ik_inner_cmd_level_info(iknow_handle apihandle,  iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	
	iprintf(ihandle, iconn, "Current level:%d.\n", client_state->log_level);
	return 0;
}

static long ik_inner_cmd_level_set(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;

	if(NULL == cmd_args || '\0' == cmd_args[0]){
		iprintf(ihandle, iconn, "must assign args.\n");
		return -1;
	}
	
	client_state->log_level = atoi(cmd_args);
	
	return 0;
}

int ik_inner_module_array_search(const char *module_name, int module_name_len, iknow_client_state_t *client_state)
{
	int i, index = -1;
	
	for(i = 0; i < IKNOW_MODULE_MAX_NUM; i++){
		if((module_name_len == client_state->module_array[i].module_str_len) 
		  &&(client_state->module_array[i].module_str != NULL)
		  &&(0 == strncasecmp(client_state->module_array[i].module_str, module_name, module_name_len))){
			index = i;
			break;
		}
	}	

	return index;
}

static int ik_inner_module_array_find_empty(iknow_client_state_t *client_state)
{
	int i, index = -1;
	
	for(i = 0; i < IKNOW_MODULE_MAX_NUM; i++){
		if((0 == client_state->module_array[i].is_valid)
		  &&(0 == client_state->module_array[i].module_str_len) 
		  &&(client_state->module_array[i].module_str == NULL)){
			index = i;
			break;
		}
	}	

	return index;
}


static int ik_inner_module_array_add_new(const char *module_name, int module_name_len, iknow_client_state_t *client_state)
{
	int index;

	if(client_state->module_array_num >= IKNOW_MODULE_MAX_NUM){
		return -1;
	}

	index = ik_inner_module_array_find_empty(client_state);
	if(index >= 0){
		; /* 复用之前的位置 */
	}else{
		index = client_state->module_array_num; /* 新增 */
	}
	
	client_state->module_array[index].is_valid = 1;
	client_state->module_array[index].module_str = ik_strdup(module_name);
	client_state->module_array[index].module_str_len = module_name_len;
	client_state->module_array_num++;
	
	return 0;
}

static void ik_inner_module_close_all(iknow_client_state_t *client_state)
{
	int i;
	
	for(i = 0; i < client_state->module_array_num; i++){
		client_state->module_array[i].is_valid = 0;
	}		
	return;
}

static long ik_inner_cmd_module_set(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *module_name)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	int index, ret;
	int module_name_len;

	if(NULL == module_name || '\0' == module_name[0]){
		iprintf(ihandle, iconn, "must assign args.\n");
		return -1;
	}

	ik_inner_module_close_all(client_state); /* 独占式 */

	module_name_len = strlen(module_name);
	index = ik_inner_module_array_search(module_name, module_name_len, client_state);
	if(index < 0){
		ret = ik_inner_module_array_add_new(module_name, module_name_len, client_state);
		if(ret < 0){
			iprintf(apihandle, iconn, "module set error!\n");
			goto err;
		}
	}else{
		client_state->module_array[index].is_valid = 1;
		client_state->module_array_num = 1;
		iprintf(apihandle, iconn, "module set success!\n");
	}

	return 0;

err:
	return -1;
}

static long ik_inner_cmd_module_add(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *module_name)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	int ret, module_name_len, index;

	if(NULL == module_name || '\0' == module_name[0]){
		iprintf(ihandle, iconn, "must assign args.\n");
		return -1;
	}

	module_name_len = strlen(module_name);
	index = ik_inner_module_array_search(module_name, module_name_len, client_state);
	if(index < 0){
		ret = ik_inner_module_array_add_new(module_name, module_name_len, client_state);
		if(ret < 0){
			iprintf(apihandle, iconn, "module add error!\n");
		}
	}else{
		client_state->module_array[index].is_valid = 1;
		iprintf(apihandle, iconn, "module add success!\n");
	}

	return 0;
}

static long ik_inner_cmd_module_del(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *module_name)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	int module_name_len, index;

	if(NULL == module_name || '\0' == module_name[0]){
		iprintf(ihandle, iconn, "must assign args.\n");
		return -1;
	}

	module_name_len = strlen(module_name);
	index = ik_inner_module_array_search(module_name, module_name_len, client_state);
	if(index < 0){
		iprintf(apihandle, iconn, "module '%s' is not exist!\n", module_name);
	}else{
		free((void *)client_state->module_array[index].module_str);
		client_state->module_array[index].module_str = NULL;
		client_state->module_array[index].module_str_len = 0;
		client_state->module_array[index].is_valid = 0;
		client_state->module_array_num--;
		iprintf(apihandle, iconn, "module del success!\n");
	}

	return 0;
}

static long ik_inner_cmd_module_info(iknow_handle apihandle,  iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	int i;

	if(client_state->module_array_num <= 0){
		iprintf(ihandle, iconn, "have not set any module!\n");
		return -1;
	}
	
	iprintf(ihandle, iconn, "Current module:");
	for(i = 0; i < IKNOW_MODULE_MAX_NUM; i++){
		if(1 == client_state->module_array[i].is_valid){
			iprintf(ihandle, iconn, "%s ", client_state->module_array[i].module_str);
		}
	}
	iprintf(ihandle, iconn, "\n");
	
	return 0;
}

static long ik_inner_cmd_flood_info(iknow_handle apihandle,  iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)apihandle;
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;
	
	iprintf(ihandle, iconn, "Current flood state:%s.\n", client_state->global_flush_flag==0?"off":"on");
	return 0;
}

static long ik_inner_cmd_flood_on(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;

	client_state->global_flush_flag = 1;

	return 0;
}

static long ik_inner_cmd_flood_off(iknow_handle apihandle, iknow_conn iconn, const void *cmd_cb_arg, const char *cmd_args)
{
	iknow_client_state_t *client_state = (iknow_client_state_t *)iconn;

	client_state->global_flush_flag = 0;

	return 0;
}

static void ik_register_reserve_cmd(inner_iknow_t *ihandle)
{
	iknow_register_cmd(ihandle, "help", "get help message", ik_inner_cmd_help, NULL, 0, NULL);
	iknow_register_cmd(ihandle, "quit", "quit IKnow", ik_inner_cmd_quit, NULL, 0, NULL);
	iknow_register_cmd(ihandle, "exit", "exit IKnow", ik_inner_cmd_quit, NULL, 0, NULL);	
	iknow_register_cmd(ihandle, "show version", NULL, ik_inner_cmd_show_ver, NULL, 0, NULL);		
	
	iknow_register_cmd(ihandle, "level info", "display current log level", ik_inner_cmd_level_info, NULL, 0, NULL);	
	iknow_register_cmd(ihandle, "level set", "set current log level", ik_inner_cmd_level_set, NULL, 1, "log level");	
	
	iknow_register_cmd(ihandle, "module info", "display current module name", ik_inner_cmd_module_info, NULL, 0, NULL);	
	iknow_register_cmd(ihandle, "module set", "set current module to xxx", ik_inner_cmd_module_set, NULL, 1, "module name");	
	iknow_register_cmd(ihandle, "module add", "add new module to current set", ik_inner_cmd_module_add, NULL, 1, "module name");
	iknow_register_cmd(ihandle, "module del", "del a module from current set", ik_inner_cmd_module_del, NULL, 1, "module name");	

	iknow_register_cmd(ihandle, "flood info", "display global message print", ik_inner_cmd_flood_info, NULL, 0, NULL);		
	iknow_register_cmd(ihandle, "flood on", "enable global message print", ik_inner_cmd_flood_on, NULL, 0, NULL);	
	iknow_register_cmd(ihandle, "flood off", "disable global message print", ik_inner_cmd_flood_off, NULL, 0, NULL);		
}

iknow_handle iknow_create(const iknow_create_args_t *args, int args_len)
{
	struct sockaddr_in listen_addr;
	int listenfd;
	int i, opt_value;
	unsigned short begin_port;
	inner_iknow_t *ihandle = NULL;

	if(args_len != sizeof(iknow_create_args_t)){
		printf("Warning! Different version of library and plugin!\n");
		sleep(3);
	}
	
	if(args->max_users < 1){
		printf("Invalid max_users: %d!\n", args->max_users);
		return NULL;
	}

	if(args->max_users > IKNOW_WORK_THREAD_MAX){
		printf("Iknow only support %d users!\n", IKNOW_WORK_THREAD_MAX);
		return NULL;
	}
	
	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&listen_addr, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listen_addr.sin_port = htons(args->listen_port_host_order);

	opt_value = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt_value, sizeof(int));

	for(begin_port = args->listen_port_host_order; begin_port < 65535; begin_port++){	
		listen_addr.sin_port = htons(begin_port);
		if(bind(listenfd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) == 0){
			printf("Iknow bind port %u success!\n", begin_port);
			break;
		}
	}
	if(begin_port >= 65535){
		printf("Iknow bind port error!\n");
		goto err_1;
	}

	ihandle = (inner_iknow_t *)malloc(sizeof(inner_iknow_t));
	memset(ihandle, 0, sizeof(inner_iknow_t));

	ihandle->listen_fd = listenfd;
	ihandle->max_users = args->max_users;  /* 外部并发连接数 */
	ihandle->work_thread_num = 0; /* 当前实际线程数, 初始化时不创建线程, 在接收命令后根据需求动态创建 */
	ihandle->work_thread_array = (iknow_work_thread_t *)malloc(args->max_users * sizeof(iknow_work_thread_t));
	memset(ihandle->work_thread_array, 0, args->max_users * sizeof(iknow_work_thread_t));

	/* 初始化时, 只初始化锁, 但不实际创建工作线程实体 */
	for(i = 0; i < args->max_users; i++){
		pthread_cond_init(&ihandle->work_thread_array[i].cond, NULL);
		pthread_mutex_init(&ihandle->work_thread_array[i].mutex, NULL);
		ihandle->work_thread_array[i].thread_state = IKNOW_THREAD_STATE_INIT;
		ihandle->work_thread_array[i].phandle = NULL;
	}

	ik_cmd_root_init(&ihandle->cmd_root);
	
	/* 先注册系统内置命令 */
	ik_register_reserve_cmd(ihandle);

	__register_sig_handle(SIGPIPE, __sig_handler);

	return (iknow_handle)ihandle;
	
err_1:
	close(listenfd);
	return NULL;
}



#ifdef __cplusplus
}
#endif
