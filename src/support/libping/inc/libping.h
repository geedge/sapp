#ifndef _LIBPING_H_
#define _LIBPING_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define LIBPING_WORK_MODE_MASTER		(1)
#define LIBPING_WORK_MODE_SLAVE		(2)

enum libping_opt_t{
	PO_PAIR_TAG,  /* opt value type is int, 必选项, 当前保活双方的业务标识符, 一个进程内多个不同业务插件都需要保活时, 用于彼此区分, 不同的ping_handle保证不冲突 */
	PO_WORK_MODE, /* opt value type is short */
	PO_SLAVE_PRE_REPLAY_CB, /* opt value type is libping_slave_pre_replay_cb_t *, 从应用是否回复保活请求包, 依据回调函数返回值决定 */
	PO_SLAVE_ID, /* opt value type is int, 从应用的ID, 一个ping_handle内保证无重复 */
	PO_MASTER_IP_NET_ORDER, /* opt value type is int */
	PO_MASTER_PORT_NET_ORDER, /* opt value type is short */
	PO_KEEPALIVE_INTERVAL, /* opt value type is int, 保活周期, 单位毫秒, ms */
	PO_BIND_BEGIN_PORT_NET_ORDER, /* opt value type is short, 本地绑定起始端口 */
	PO_NODE_LIST, /* opt value type is int *,  opt_len为传入传出参数, 传入表示int *数组的长度, 即元素数*sizof(int), 传出时表示实际slave的数量*sizeof(int) */
	PO_NODE_STATUS, 	/* opt value type is struct node_status_t, is value-result argument(传入传出参数), 传入时必须指定slave_id */
};

enum libping_state{
	LIBPING_STATE_INIT = 0, 			/* 0:初始状态 */
	LIBPING_STATE_DETECTING, 		/* 1:从探测主的过程 */
	LIBPING_STATE_FOUND,			/* 2:从发现主, 准备注册 */
	LIBPING_STATE_REGISTERED, 		/* 3:从向主注册成功 */
	LIBPING_STATE_KEEPALIVE_SUCC, /* 4:保活正常 */
	LIBPING_STATE_KEEPALIVE_ERR,   /* 5:保活异常 */
};

typedef struct{
	unsigned int slave_id;
	unsigned int slave_ip_net;
	unsigned short slave_port_net;
	unsigned short state;  /* refer to enum libping_state */
	unsigned int send_req_pkt;
	unsigned int recv_rep_pkt;	
}node_status_t;

typedef void *ping_handle;

/* 从应用收到主的保活请求, 根据上层应用状态决定是否要回复保活应答, libping模块根据此回调函数的返回值决定, 1:回复应答; 0:不回复,即保活失败 */
typedef int libping_slave_pre_replay_cb_t(ping_handle ph, unsigned int pair_tag, unsigned int slave_id);

ping_handle libping_create(void);

int libping_get_opt(ping_handle ph, enum libping_opt_t opt_type, void *opt_value, int *opt_len);

int libping_set_opt(ping_handle ph, enum libping_opt_t opt_type, void *opt_value, int opt_len);

int libping_run(ping_handle ph);

#ifdef __cplusplus
}
#endif

#endif

