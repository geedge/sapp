#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "gtest_sapp_fun.h"

static int gtest_slave_plug_fd = -1;

void *g_sapp_plug_log_handle;

#if (1 == GTEST_SAPP_COMM_MODE)	
static struct sockaddr_un gtest_slave_sockaddr;
#elif (2 == GTEST_SAPP_COMM_MODE)	
static struct sockaddr_in gtest_slave_sockaddr; 
#endif

int (*plug_custom_init_fun)(void); /* 每个测试插件独立的初始化函数 */

int sendto_test_result(int res)
{
	gtest_set_libsapp_devel_result(res);
	
	int ret;
	ret = sendto(gtest_slave_plug_fd, &res, sizeof(int), 0, 
	            (const sockaddr*)&gtest_slave_sockaddr, sizeof(gtest_slave_sockaddr));
	if(ret < 0){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","socket send result:0x%x error, fd=%d, fd address is:%p, %s! \n", res, gtest_slave_plug_fd, &gtest_slave_plug_fd, strerror(errno));
	}else{
		SAPP_PLUG_LOG(RLOG_LV_DEBUG, "plugin","socket send result:0x%x succ, fd=%d, fd address is:%p\033[0m\n", res, gtest_slave_plug_fd, &gtest_slave_plug_fd);
	}
	return 0;
}

#include "sapp_limits.h"
#include "sapp_global_val.h"
#include "stream_internal.h"

/* 某些测试用例引用了sapp的内部私有头文件, 
   直接读取sapp的内部变量, 必须保证结构体完全是一致的!! 
   需要手工更新copy sapp private相关头文件.
*/
int check_sapp_version(void)
{
	if(sapp_size_of_sapp_global() != sizeof(sapp_global_t)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","\033[1;31;40mThis program structure sapp_global_t is different with sapp, must update sapp devel header!\033[0m\n");
		return -1;
	}

	if(sapp_size_of_streaminfo_private() != sizeof(struct streaminfo_private)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","\033[1;31;40mThis program structure streaminfo_private is different with sapp, must update sapp devel header!\033[0m\n");
		return -1;
	}

	if(sapp_size_of_tcpdetail_private() != sizeof(struct tcpdetail_private)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","\033[1;31;40mThis program structure tcpdetail_private is different with sapp, must update sapp devel header!\033[0m\n");
		return -1;
	}

	if(sapp_size_of_udpdetail_private() != sizeof(struct udpdetail_private)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","\033[1;31;40mThis program structure udpdetail_private is different with sapp, must update sapp devel header!\033[0m\n");
		return -1;
	}

	if(sapp_size_of_raw_pkt_t() != sizeof(raw_pkt_t)){
		SAPP_PLUG_LOG(RLOG_LV_FATAL, "plugin","\033[1;31;40mThis program structure raw_pkt_t is different with sapp, must update sapp devel header!\033[0m\n");
		return -1;
	}
	
	return 0;
}


extern "C" int gtest_sapp_slave_init(void)
{
	int ret = 0;

	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	g_sapp_plug_log_handle = MESA_create_runtime_log_handle("./log/gtest_sapp_plug.log", 10);
	
	if(check_sapp_version() < 0){
		exit(1);
	}

#if (1 == GTEST_SAPP_COMM_MODE)	
	gtest_slave_plug_fd = socket(AF_UNIX,SOCK_DGRAM,0);
	if(gtest_slave_plug_fd < 0){
		printf("unix domain socket error!\n");
		exit(1);
	}
	printf("unix socket succ, fd=%d, fd address is %p\n", gtest_slave_plug_fd, &gtest_slave_plug_fd);

	memset(&gtest_slave_sockaddr, 0, sizeof(gtest_slave_sockaddr));
	gtest_slave_sockaddr.sun_family = AF_UNIX;
	strcpy(gtest_slave_sockaddr.sun_path, UNIX_SOCKET_NAME);
#elif (2 == GTEST_SAPP_COMM_MODE)
	gtest_slave_plug_fd = socket(AF_INET,SOCK_DGRAM,0);
	if(gtest_slave_plug_fd < 0){
		printf("udp socket error!\n");
		exit(1);
	}	

	gtest_slave_sockaddr.sin_family = AF_INET;
	gtest_slave_sockaddr.sin_port = htons(UDP_SERVER_BIND_PORT);	//host to network hostshort
	gtest_slave_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");	
#else
	printf("unsupport GTEST_SAPP_COMM_MODE!\n");
	exit(1);
#endif

	if(plug_custom_init_fun != NULL){
		ret = plug_custom_init_fun();
	}

	MESA_handle_runtime_log(g_sapp_plug_log_handle, RLOG_LV_INFO, "plugin", "gtest_sapp_slave_init success!\n");
	
	return ret;
}


extern "C" void gtest_sapp_slave_destroy(void)
{
	return;
}


