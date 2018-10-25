#include "iknow.h"
#include "iknow_internal.h"
#include "MESA_socket_wrap.h"
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
#include <termios.h> 

int Iknow_client_version_VERSION_20150924;

/*
	安全性:
		根据本地.password.key文件, 控制客户端是否需要输入密码.
		密码采用MD5后再经过自定义的移位, 异或后的密文传输.

		iknow_keygen -k 123456 -w .password.key, 用于生成密码文件.
		iknow_client -f ./password.key , 指定保存的密码文件.

	客户端支持退格, 上箭头键表示曾使用的历史命令, 自动补全到当前命令缓存中, 并显示到屏幕,

	nc,telnet等通用工具不支持, 

	命令补全功能, 在客户端实现, 即把tab替换成'?', 发给服务器端,
	server找到对应的命令后, 如果仅有一条, 则自动补全, 并显示全部命令字符,
	同时客户端把命令的全部字符默默地复制到当前的命令输入buf中,
	只要输入回车, 其实就自动输入了补全的命令.
*/


static void sig_handler(int sig_no)
{
	/* Iknow 终端按ctrl+c动作, 自动发送如下命令:
	     关闭全局打印开关, 将日志等级设为最高，modul设为空,
		并提示:
		broadcast off,
		set level = 99999,
		set module = NONE,
		#
	*/
	return;
}


/* client端, 支持多单行多命令, 用";"分割 
   如果最后包含了'!', 则解析完后, 自动退出;

 特殊命令:
 	如上箭头, 退格键, tab键等, 直接按回车表示最近一次命令, 都需要在client端处理.

管道命令不处理, 默认由shell处理
	a; b ; c; | grep xxx
	a; b; c > xxx.log

	如果有\r\n，则清除所有的空格再处理
	如果没有\r\n, 有tab，则按原始输入查询帮助信息, a \t, 转换为a ?\r\n

	需要将上述命令拆分为3个子命令, 分3次发送给服务端, 即
	a\r\n
	b\r\n
	c;\r\n, 最后的命令执行完, 立即结束.
	和c\r\n
*/
#if 0
static int iknow_client_get_cmd(inner_iknow_t *ihandle, int connfd, char cmd_buf[])
{
	int ret;

	ret = read(connfd, cmd_buf, IKNOW_CMD_BUF_LEN);
	if(0 == ret){
		IPRINT("peer  closed!\n");
		return -1;
	}else if(ret < 0){
		IPRINT("read error:%s\n", strerror(errno));
		return -1;
	}

	del_last_rn(cmd_buf, IKNOW_CMD_BUF_LEN);

	if(iknow_special_cmd(ihandle, connfd, cmd_buf)){
		return 0;
	}

	IPRINT("get cmd '%s'\n", cmd_buf);

	iknow_cmd_match(ihandle, cmd_buf, connfd);

	return ret;
}
#endif

#define IC_CMD_HISTORY_NUM		(256)
#define IC_CMD_STR_MAX_LEN		(256)

#define IC_CTRL_CMD_ONE			(0x1b) /* 控制键第一字符 */
#define IC_CTRL_CMD_TWO			(0x5b) /* 控制键第二字符 */
#define IC_CTRL_CMD_UP_ARROW		(0x41) /* 上箭头 */
#define IC_CTRL_CMD_DOWN_ARROW	(0x42) /* 下箭头 */
#define IC_CTRL_CMD_TAB 			(0x09) /* tab 键 */
#define IC_CTRL_CMD_BACK			(0x08) /* 回退键 */
#define IC_CTRL_CMD_ENTER			(0x0a) /* 回车 */
#define IC_CTRL_CMD_IGNORE		(0x1234ABCD)


static unsigned int Ic_server_ip_host;
static unsigned short Ic_server_port_host;
static int Ic_sd = -1;
static unsigned char Ic_cmd_buf[IC_CMD_STR_MAX_LEN];
static unsigned char Ic_history_buf[IC_CMD_HISTORY_NUM][IC_CMD_STR_MAX_LEN];
static int Ic_history_index = 0;
static int Ic_arrow_index = 0; /* 历史记录下标 */
static int Ic_cmd_cur_index = 0;
static int Ic_cmd_terminate_flag = 0; /* 命令最后是否有'$'终结符 */

static void usage(void)
{
	printf("Iclient usage:\n");
	printf("\ticlient <server-ip> <server-port> ([command];)*[$]\n");
	printf("\tFor example:\n");
	printf("\t   iclient 127.0.0.1 65432\n");
	printf("\t   iclient 127.0.0.1 65432 show version$\n");
	exit(1);
}


/* 是否控制类特殊字符
	>0 : 是控制字符;
	0  : 不是控制字符;
	<0 : 是控制字符的前缀, 但还未完全识别;
*/
static int Ic_is_ctrl_cmd(int ch)
{
	int ret = 0;
	static char ctrl_one, ctrl_two;
	
	switch(ch){
		case IC_CTRL_CMD_TAB:
		case IC_CTRL_CMD_ENTER:
		case IC_CTRL_CMD_BACK:
			ret = ch;
		break;

		case IC_CTRL_CMD_ONE:
			ret = -1;
			ctrl_one = ch;
		break;

		case IC_CTRL_CMD_TWO:
			ret = -1;
			ctrl_two = ch;
		break;

		case IC_CTRL_CMD_UP_ARROW:
			if((IC_CTRL_CMD_ONE == ctrl_one) && (IC_CTRL_CMD_TWO == ctrl_two)){
				ret = IC_CTRL_CMD_UP_ARROW;
				ctrl_one = 0;
				ctrl_two = 0;
			}
		break;

		case IC_CTRL_CMD_DOWN_ARROW:
			if((IC_CTRL_CMD_ONE == ctrl_one) && (IC_CTRL_CMD_TWO == ctrl_two)){
				ret = IC_CTRL_CMD_DOWN_ARROW;
				ctrl_one = 0;
				ctrl_two = 0;
			}
		break;
		
		default:
			if((IC_CTRL_CMD_ONE == ctrl_one) && (IC_CTRL_CMD_TWO == ctrl_two)){
				ret = IC_CTRL_CMD_IGNORE;
				ctrl_one = 0;
				ctrl_two = 0;
			}
			
			break;
	}

	return ret;
}

static void Ic_recv_server_response(void)
{
	int ret, block_mode = -1;
	char res_buf[IC_CMD_STR_MAX_LEN];

	while(1){
		ret = MESA_sock_recv(Ic_sd, res_buf, IC_CMD_STR_MAX_LEN, 0, block_mode);
		if(ret < 0){
			break;
		}else if(0 == ret){
			printf("Peer closed!\n");
			exit(1);
		}

		write(1, res_buf, ret);
		block_mode = 100;
	}
}

static int Ic_exec_user_cmd(const char *user_cmd_str, int user_cmd_len)
{
	int ret;
	
	ret = MESA_sock_force_write(Ic_sd, user_cmd_str, user_cmd_len, -1);
	if(ret < 0){
		printf("Connection error, %s!\n", strerror(errno));
		exit(1);
	}

	Ic_recv_server_response();

	return 0;
}

static int Ic_getchar(void)  
{  
	struct termios oldt, newt;  
	int ch;  
	int oldf;  
	
	tcgetattr(STDIN_FILENO, &oldt);  
	newt = oldt;  
	newt.c_lflag &= ~(ICANON | ECHO);  
	//newt.c_lflag &= ~(ICANON);  
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);  
	//oldf = fcntl(STDIN_FILENO, F_GETFL, 0);  
	//fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);  
	ch = getchar();  
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);  
	//fcntl(STDIN_FILENO, F_SETFL, oldf);  
	if(ch != EOF)  {  
		return ch;  
	}  
	return EOF;  
}

static int Ic_exec_ctrl_cmd_backspace(void)
{
	if(Ic_cmd_cur_index > 0){
		write(1, "\b \b", 3);
		Ic_cmd_cur_index--;		
	}
	
	return 0;
}

static int Ic_save_history_cmd(void)
{
	if(Ic_history_index >= IC_CMD_HISTORY_NUM){
		Ic_history_index = 0; /* 循环使用缓存 */	
	}
	Ic_arrow_index = Ic_history_index;
	memset(Ic_history_buf[Ic_history_index], 0, IC_CMD_STR_MAX_LEN);
	memcpy(Ic_history_buf[Ic_history_index++], Ic_cmd_buf, Ic_cmd_cur_index);

	return 0;
}

static void Ic_clear_line(void)
{
	int i;
	write(1, "\r", 1);
	for(i = 0; i < IC_CMD_STR_MAX_LEN; i++){
		write(1, " ", 1);
	}
	write(1, "\r", 1);

	return;
}

static int Ic_exec_ctrl_cmd_uparrow(void)
{
	if(Ic_arrow_index > 0){
		Ic_arrow_index--;
		Ic_clear_line();
		write(1, "I#", 2); /* 提示符 */
		write(1, Ic_history_buf[Ic_arrow_index], strlen(Ic_history_buf[Ic_arrow_index]));
		Ic_cmd_cur_index = strlen(Ic_history_buf[Ic_arrow_index]);
		memcpy(Ic_cmd_buf, Ic_history_buf[Ic_arrow_index], Ic_cmd_cur_index);
	}

	return 0;
}

static int Ic_exec_ctrl_cmd_downarrow(void)
{

	if(Ic_arrow_index < Ic_history_index){
		Ic_arrow_index++;
		Ic_clear_line();
		write(1, "I#", 2); /* 提示符 */
		write(1, Ic_history_buf[Ic_arrow_index], strlen(Ic_history_buf[Ic_arrow_index]));
		Ic_cmd_cur_index = strlen(Ic_history_buf[Ic_arrow_index]);
		memcpy(Ic_cmd_buf, Ic_history_buf[Ic_arrow_index], Ic_cmd_cur_index);
	}

	return 0;
	
}

static int Ic_exec_ctrl_cmd_enter(void)
{
	if(Ic_cmd_cur_index > 0){
		Ic_save_history_cmd();
		write(1, "\n", 1); /* 换行 */
		Ic_cmd_buf[Ic_cmd_cur_index++] = '\n';
		Ic_exec_user_cmd(Ic_cmd_buf, Ic_cmd_cur_index);
		
	}
	memset(Ic_cmd_buf, 0, sizeof(Ic_cmd_buf));
	Ic_cmd_cur_index = 0;
	write(1, "\nI#", 3); /* 提示符 */

	return 0;
}

static int Ic_exec_ctrl_cmd_tab(void)
{
	if(Ic_cmd_cur_index > 0){
		write(1, "\n", 1); /* 换行 */
		Ic_cmd_buf[Ic_cmd_cur_index++] = '?';
		Ic_cmd_buf[Ic_cmd_cur_index++] = '\n';
		Ic_exec_user_cmd(Ic_cmd_buf, Ic_cmd_cur_index);

		Ic_cmd_cur_index -= 2; /* 插销增加的'?'和回车符 */
		write(1, "I#", 2); /* 提示符 */
		write(1, Ic_cmd_buf, Ic_cmd_cur_index); /* 将按tab之前的历史命令再输出 */
	
	}

	return 0;
}

static int Ic_exec_ctrl_cmd(int cmd_ch)
{
	switch(cmd_ch){
		case IC_CTRL_CMD_TAB:
			Ic_exec_ctrl_cmd_tab();
		break;
		
		case IC_CTRL_CMD_ENTER:
			Ic_exec_ctrl_cmd_enter();
		break;
		
		case IC_CTRL_CMD_BACK:
			Ic_exec_ctrl_cmd_backspace();
		break;

		case IC_CTRL_CMD_UP_ARROW:
			Ic_exec_ctrl_cmd_uparrow();
		break;

		case IC_CTRL_CMD_DOWN_ARROW:
			Ic_exec_ctrl_cmd_downarrow();
		break;
		
		default:			
			break;
	}	

	return 0;
}

static void Ic_interactive_mode(void)
{
	int cmd_ch;
	int ret;

	/* TODO: tcgetattr, tcsetattr */
	
	while(1){
		cmd_ch = Ic_getchar();
//printf("input:%x\n", cmd_ch);
		ret =  Ic_is_ctrl_cmd(cmd_ch);
		if(ret > 0){
			Ic_exec_ctrl_cmd(cmd_ch);
		}else if(ret < 0){
			/* do nothing, 是控制命令, 但还未完全识别 */
		}else{
			write(1, &cmd_ch, 1);
			Ic_cmd_buf[Ic_cmd_cur_index++] = (unsigned char)cmd_ch;
		}

		if(Ic_cmd_cur_index >= IC_CMD_STR_MAX_LEN){
			write(1, "\ncommand is too long!\n", strlen("\ncommand is too long!\n"));
			write(1, "I#", 2);
		}
	}

	return;
}

/*
	iclient <ip> <port> ......
*/
static int Ic_parse_ip_port(int argc, char *argv[])
{
	unsigned int ip;
	unsigned short port;

	if((isdigit(argv[1][0]) == 0) || (isdigit(argv[2][0]) == 0)){
		printf("Invalid ip or port!\n");
		exit(1);
	}

	if(inet_pton(AF_INET, argv[1], &ip) <= 0){
		printf("server ip address error!\n");
		usage();
	}

	Ic_server_ip_host = ntohl(ip);
	port = atoi(argv[2]);
	if(port < 0 || port > 65535){
		printf("server port error!\n");
		usage();		
	}

	Ic_server_port_host = (unsigned short)port;	
	return 0;
}

static int Ic_connect(void)
{
	int ret;
	char ip_str[16];
	struct sockaddr_in server_addr;

	Ic_sd = socket(AF_INET, SOCK_STREAM, 0);
	if(Ic_sd < 0){
		printf("socket error, %s\n", strerror(errno));
		exit(1);
	}

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(Ic_server_ip_host);
	server_addr.sin_port = htons(Ic_server_port_host);

	ret = MESA_sock_connect(Ic_sd, (const struct sockaddr *)&server_addr, sizeof(server_addr), 3000);
	if(ret < 0){
		inet_ntop(AF_INET, &server_addr.sin_addr.s_addr, ip_str, 16);
		printf("can't connect server %s:%u\n", ip_str, Ic_server_port_host);
		exit(1);		
	}

	/* TODO:
		命令行直接输入命令时, 服务器端不要输出欢迎字符,
		可以向服务器端输入一个特殊命令, "be quiet", 表示客户端不要欢迎字符.
	*/

	return 0;
}

static int Ic_init(void)
{
#if 0
	Ic_cmd_history_init();

	Ic_signal_init();
#endif
	return 0;
}


/* 接收来自SHELL命令行直接输入的命令, 将分割的命令行参数合并到一块完整的缓存,
     例:
	./iclient 127.0.0.1 65432 show http bps; show tcp pps; !
*/
static int Ic_join_shell_follow_cmd(int argc, char *argv[])
{
	unsigned char tmp_buf[IC_CMD_STR_MAX_LEN];
	int i, tmp_index = 0, section_len;

	memset(tmp_buf, 0, IC_CMD_STR_MAX_LEN);

	/* 从第三个参数开始, 是命令 */
	for(i = 3; i < argc; i++){
		section_len = strlen(argv[i]);
		if(tmp_index + section_len >= IC_CMD_STR_MAX_LEN){
			printf("command line too long!\n");
			exit(1);
		}
		memcpy(tmp_buf+tmp_index, argv[i], section_len);
		tmp_index += section_len;
		if(i + 1 < argc){
			tmp_buf[tmp_index] = ' '; /* 命令参数中间追加空格分隔符 */
			tmp_index++;
		}else{
			tmp_buf[tmp_index] = '\n'; /* 最后追加回车 */ 
			tmp_index++;
		}
	}
	

	Ic_exec_user_cmd((const char *)tmp_buf, strlen(tmp_buf));

	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 3){
		usage();
	}

	if(Ic_parse_ip_port(argc, argv) < 0){
		return -1;
	}

	if(Ic_connect() < 0){
		return -1;
	}

	//Ic_notify_server(); /* 告诉Iknow server, 我是Iclient, 而不是nc */

	Ic_init();

	if(argc > 3){ /* iclient 127.0.0.1 65432 ...., 超过3个参数即有后续命令 */
		Ic_join_shell_follow_cmd(argc, argv);
	}

	if(Ic_cmd_terminate_flag != 0){
		exit(1);
	}

	Ic_interactive_mode();

	return 0;
}

