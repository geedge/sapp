#ifdef __cplusplus
extern "C" {
#endif

#include "stream_inc/stream_base.h"


enum gdev_keepalive_opt_t{
	GDEV_KEEPALIVE_OPT_SERVICE_CTRL, 	/* 单独控制某类业务号是否保活 opt_val is struct gdev_keepalive_service_ctrl */
	GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH,   /* 全局性保活开关, opt_val is int */
	GDEV_KEEPALIVE_OPT_RCV_PKT_PPS,		/* 收到的保活包总数/秒, opt_val is long */
	GDEV_KEEPALIVE_OPT_SND_PKT_PPS,		/* 收到的保活包总数/秒, opt_val is long */
};

struct gdev_keepalive_service_ctrl{
	int service_num; /* 业务号, service number */
	int keepalive_switch; /* 1:保活, enable keepalive;  0:不保活, disable keepalive */
};


int gdev_keepalive_set_opt(const SAPP_TLV_T *tlv_value);

int gdev_keepalive_get_opt(SAPP_TLV_T *tlv_value);


/* 由源端口获取当前包所属业务号 */
unsigned char vxlan_sport_map_to_service_id(unsigned short sport_host_order);

/* 由vxlan_id获取当前包所属业务号 */
unsigned char vxlan_id_map_to_service_id(int vxlan_id_host_order);


#ifdef __cplusplus
}
#endif


