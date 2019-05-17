#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


static void * gdev_block_c3_handle;
static unsigned char gdev_block_c3_license[8];
static unsigned gdev_block_c3_service_type;
static unsigned gdev_block_c3_rule_scope;
static int gdev_block_module_conn_flag = 0;

#define GDEV_BLOCK_PLUG_CONF  "./conf/gdev_block.conf"

/* 使用动态链接模式, 避免因libc3client.so的问题, 导致sapp都无法运行 */
static void * (*dl_grule_open)(void);
static int (*dl_grule_opt_set)(void * hdl, int level, int type, const void * opt, size_t opt_size);
static int (*dl_grule_connect)(void * hdl, const char * addr);
static int (*dl_grule_send)(void * hdl, grule_t *rules, size_t rule_num, int flags);
static int (*dl_grule_recv)(void * hdl, grule_result_t *rst, size_t rst_num, int flags);

static int gdev_block_send_rule_tuple5(unsigned int sip_net, unsigned int dip_net, unsigned short sport_net, unsigned short dport_net, unsigned char protocol)
{
	grule_t grule;
	grule_result_t grule_result;
	int send_ret, recv_ret;

	memset(&grule, 0, sizeof(grule_t));
	
	/* rule_id从全局变量获取并递增, 在后面的锁保护区域内操作 */
	grule.srv_type = gdev_block_c3_service_type;
	grule.rule_scope = gdev_block_c3_rule_scope;
	grule.big_type = GRULE_BIG_TYPE_MASK4;
	grule.durable = 0;
	grule.action = GRULE_ACTION_ADD;

	/* 使用tuple组合类型1 */
	grule.rule_type.sip_flag = 1;
	//grule.rule_type.sipmsk_flag = 1;
	grule.rule_type.dip_flag = 1;
	//grule.rule_type.dipmsk_flag = 1;
	grule.rule_type.sport_flag = 1;
	//grule.rule_type.spmsk_flag = 1;
	grule.rule_type.dport_flag = 1;
	//grule.rule_type.dpmsk_flag = 1;
	grule.rule_type.proto_flag = 1;
	//grule.rule_type.pmsk_flag = 1;

	grule.m4.sip = sip_net;
	//grule.m4.sip_mask = 0xFFFFFFFF;
	grule.m4.dip = dip_net;
	//grule.m4.dip_mask = 0xFFFFFFFF;
	grule.m4.sport = sport_net;
	//grule.m4.spor_mask = 0xFFFF;
	grule.m4.dport = dport_net;
	//grule.m4.dport_maske = 0xFFFF;
	grule.m4.proto = protocol;
	//grule.m4.proto_mask = 0xFF;

	send_ret = dl_grule_send(gdev_block_c3_handle, &grule, 1, 0);
	if(send_ret < 0){
		recv_ret = dl_grule_recv(gdev_block_c3_handle, &grule_result, 1, 0);
		printf("grule_send errno is: %u\n", grule_result.result);
	}
	return send_ret;
}


int gdev_block_send_rule(const struct streaminfo *pstream)
{
	unsigned char protocol;
	int send_ret;

	if(0 == gdev_block_module_conn_flag){
		sapp_runtime_log(20, "gdev_block module not init succ!\n\n");
		return -1;
	}
	
	if(pstream->addr.addrtype != ADDR_TYPE_IPV4){
		sapp_runtime_log(20, "gdev_block unsupport IPv6 yet!\n");
		/* 暂不支持IPv6 */
		return -1;
	}

	if(STREAM_TYPE_TCP == pstream->type){
		protocol = 6;
	}else{
		protocol = 17;
	}
	
	send_ret = gdev_block_send_rule_tuple5(pstream->addr.tuple4_v4->saddr, pstream->addr.tuple4_v4->daddr, pstream->addr.tuple4_v4->source, pstream->addr.tuple4_v4->dest, protocol);
	if(send_ret <= 0){
		sapp_runtime_log(20, "gdev send c3 rule error, tuple4: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}else{
		sapp_runtime_log(10, "gdev send c3 rule SUCC, tuple4: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}
	
	return send_ret;
}


static int gdev_block_hex2mem( char *source, int srclen, unsigned char* dest)
{
        int i,j;
        unsigned char c,h4bit,l4bit;

        if( NULL == source || NULL==dest || srclen<=0 )
        {
                return -1;
        }

        for(i=0,j=0; i<srclen; )
        {
                c = source[i];
                if(c >= '0' && c <= '9')
                        h4bit = c - '0';
                else if(c >= 'A' && c <= 'F')
                        h4bit = c - 'A' + 10;
                else if(c >= 'a' && c <= 'f')
                        h4bit = c - 'a' + 10;
                else
                {
                        if(i == srclen -1)//the last c is 0a
                        {
                                return j;
                        }
                        else
                        {
                                return -1;
                        }
                }
                ++i;

                if(i>=srclen)
                {
                        return -1;
                }

                c = source[i];
                if(c >= '0' && c <= '9')
        	         l4bit = c - '0';
                else if(c >= 'A' && c <= 'F')
                        l4bit = c - 'A' + 10;
                else if(c >= 'a' && c <= 'f')
                        l4bit = c - 'a' + 10;
                else
                {
                        return -1;
                }
                dest[j]= (h4bit<<4)|l4bit;				

                j++;
                i++;
        }
        dest[j] = '\0';
	
        return j;
}

/*
	C3的连接函数有问题, 连不上也不报错, 自造一个检查对端是否存在的函数.
	-1: error
	 0: succ or other.
*/
static int gdev_detect_c3_server_is_exist(void)
{
	char c3_ip_str[32];
	int ret, tmp_int;
	unsigned short c3_port;
	struct sockaddr_in sockadd;

	MESA_load_profile_string_def(GDEV_BLOCK_PLUG_CONF, "gdev", "c3_server_ip", c3_ip_str, 32, "$");
	MESA_load_profile_int_def(GDEV_BLOCK_PLUG_CONF, "gdev", "c3_server_port", &tmp_int, 0);

	if('$' == c3_ip_str[0]){
		return 0;
	}

	if((tmp_int > 0) && (tmp_int < 65535)){
		c3_port = (unsigned short)tmp_int;
	}

	int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd < 0){
		return 0;
	}

	sockadd.sin_family = AF_INET;
	ret = inet_pton(AF_INET, c3_ip_str, &sockadd.sin_addr.s_addr);
	if(ret <= 0){
		goto err_exit;
	}
	sockadd.sin_port = htons(c3_port);
	
	ret = MESA_sock_connect(sock_fd, (const struct sockaddr  *)&sockadd, sizeof(sockadd), 3000);
	if(ret < 0){
		close(sock_fd);
		return -1;
	}
	
err_exit:
	/* 其他错误都返回0, 表示未确定是否是真的连不上 */
	close(sock_fd);
	return 0;
}

int gdev_block_init(void)
{
	int ret;
	char tmp_str[128];
	char gdev_c3_addr_list[128];
	void *libc3_client_so_handle;

	libc3_client_so_handle = dlopen("/opt/MESA/lib/libc3client.so", RTLD_NOW | RTLD_NODELETE);
	if(NULL == libc3_client_so_handle){
		printf("\n\033[33m[Warning] dlopen '%s' error!\033[0m\n", "/opt/MESA/lib/libc3client.so");
		return -1;
	}

	dl_grule_open = ( void * (*)(void))dlsym(libc3_client_so_handle, "grule_open");
	if(NULL == dl_grule_open){
		return -1;
	}

	dl_grule_opt_set = (int (*)(void * hdl, int level, int type, const void * opt, size_t opt_size))dlsym(libc3_client_so_handle, "grule_opt_set");
	if(NULL == dl_grule_opt_set){
		return -1;
	}

	dl_grule_connect = (int (* )(void * hdl, const char * addr))dlsym(libc3_client_so_handle, "grule_connect");
	if(NULL == dl_grule_connect){
		return -1;
	}

	dl_grule_send = (int (* )(void * hdl, grule_t *rules, size_t rule_num, int flags))dlsym(libc3_client_so_handle, "grule_send");
	if(NULL == dl_grule_send){
		return -1;
	}

	dl_grule_recv = (int (*)(void * hdl, grule_result_t *rst, size_t rst_num, int flags))dlsym(libc3_client_so_handle, "grule_recv");
	if(NULL == dl_grule_recv){
		return -1;
	}
	
	gdev_block_c3_handle = dl_grule_open();
	if(NULL == gdev_block_c3_handle){
		printf("grule_open() error!\n");
		return -1;
	}

	MESA_load_profile_string_def(GDEV_BLOCK_PLUG_CONF, "gdev", "auth_data", tmp_str, 128, "#");
	if('#' == tmp_str[0]){/* 没找到license */
		printf( "invalid config:%s->%s!\n", GDEV_BLOCK_PLUG_CONF, "auth_data");
		return -1;
	}
	ret = gdev_block_hex2mem(tmp_str, 16, (unsigned char *)gdev_block_c3_license);
	if(ret < 0){
		printf("invalid config:%s->%s!\n", GDEV_BLOCK_PLUG_CONF, "auth_data");
		return -1;
	}

	MESA_load_profile_string_def(GDEV_BLOCK_PLUG_CONF, "gdev", "c3_list", gdev_c3_addr_list, 128, "#");
	if('#' == tmp_str[0]){
		printf("invalid config:%s->%s!\n", GDEV_BLOCK_PLUG_CONF, "c3_list");
		return -1;
	}
	
	MESA_load_profile_uint_def(GDEV_BLOCK_PLUG_CONF, "gdev", "service_type", &gdev_block_c3_service_type, 1);
	MESA_load_profile_uint_def(GDEV_BLOCK_PLUG_CONF, "gdev", "rule_scope", &gdev_block_c3_rule_scope, 1);
	
	dl_grule_opt_set(gdev_block_c3_handle, GRULE_SOL_PROTO, GRULE_TYPE_AUTH, gdev_block_c3_license, sizeof(gdev_block_c3_license));

	if(gdev_detect_c3_server_is_exist() < 0){
		sapp_runtime_log(20, "grule_connect %s error!\n", gdev_c3_addr_list);
		return -1;
	}

	ret = dl_grule_connect(gdev_block_c3_handle, gdev_c3_addr_list);
	if(ret < 0){
		sapp_runtime_log(20, "grule_connect %s error!\n", gdev_c3_addr_list);
		return -1;
	}
	
	gdev_block_module_conn_flag = 1;
	sapp_runtime_log(10, "grule_connect %s succ!\n", gdev_c3_addr_list);

	return 0;
}

#ifdef __cplusplus
}
#endif

