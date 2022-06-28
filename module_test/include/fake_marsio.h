/*
 *	\brief MARSIO Userspace ZeroCopy Driver Version 4
 *	
 *	This is the user api header file of MARSIOv4 ZeroCopy Driver
 *	
 *	\author	Qiuwen Lu<luqiuwen@iie.ac.cn>
 *			Institute of Information Engineering, Chinese Academy of Sciences
 *			
 *	\date	2016-12-01
 */

#pragma once

typedef enum
{
    /* 数据面线程数，没有缺省值 */
    MARSIO_OPT_THREAD_NUM,
    /* 数据面线程绑定掩码，没有缺省值，设置该掩码后，数据面线程数选项将被忽略。*/
    MARSIO_OPT_THREAD_MASK,
    /* 线程绑定模式，类型：uint32_t */
    MARSIO_OPT_THREAD_AFFINITY_MODE,

    /* 处理SIG信号，缺省值：类型：uint32_t，关闭（0） 
	 * 启用该选项后，将自动处理SIGINT、SIGTERM信号
	 */
    MARSIO_OPT_EXIT_WHEN_ERR,

    /* 拓展数据面线程绑定掩码，适应大于64个核处理器的硬件平台
	 * 设置该掩码后，数据面线程数选项将被忽略
	 */
    MARSIO_OPT_THREAD_MASK_IN_CPUSET,

} marsio_opt_type_t;

typedef enum
{
    /* 发送后不释放数据包，由应用自行释放数据包 */
    MARSIO_SEND_OPT_NO_FREE = 1 << 0,
    /* 发送时计算发包哈希值，用于分流 */
    MARSIO_SEND_OPT_REHASH = 1 << 1,
    /* 快速报文路径 */
    MARSIO_SEND_OPT_FAST = 1 << 2,
    /* 报文追踪标记 */
    MARSIO_SEND_OPT_TRACE = 1 << 3,
    /* 控制报文标记 */
    MARSIO_SEND_OPT_CTRL = 1 << 4

} marsio_opt_send_t;

enum mr_sendpath_type
{
    /* 去往特定虚设备的发包路径 */
    MR_SENDPATH_VDEV,
    /* 路由查表确定发包路径 */
    MR_SENDPATH_ROUTE_NORMAL,
    /* 特定设备路由查表确定发包路径 */
    MR_SENDPATH_ROUTE_SPEC_DEV,
    /* MAX标记 */
    MR_SENDPATH_MAX
};

enum mr_sendpath_option
{
    /* 构建四层报文头 */
    MR_SENDPATH_OPT_BUILD_L4 = 0,
    /* 构建三层报文头 */
    MR_SENDPATH_OPT_BUILD_L3 = 1,
    /* 构建二层报文头 */
    MR_SENDPATH_OPT_BUILD_L2 = 2,
    /* 构建前Hook点回调 */
    MR_SENDPATH_OPT_HOOK_PREBUILD = 50,
    /* 构建后Hook点回调 */
    MR_SENDPATH_OPT_HOOK_POSTBUILD = 51,
};

enum mr_clone_options
{
    /* 拷贝区域 */
    MR_BUFF_CLONE_DATA = 1 << 0,
    MR_BUFF_CLONE_BUFF = 1 << 1,
    MR_BUFF_CLONE_CTRLZONE = 1 << 2,
};

enum mr_thread_affinity_mode
{
    /* 禁用线程亲和性设置 */
    MR_THREAD_AFFINITY_DISABLE = 0,
    /* 自动线程亲和性设置 */
    MR_THREAD_AFFINITY_AUTO = 1,
    /* 自定义线程亲和性设置 */
    MR_THREAD_AFFINITY_USER = 255
};

enum mr_timestamp_type
{
    /* 从网卡收取时或报文缓冲区申请时的时间戳 */
    MR_TIMESTAMP_RX_OR_ALLOC = 0,
};

enum mr_buff_metadata_type
{
    /* 分流哈希值，会根据该值计算分流队列 */
    MR_BUFF_REHASH_INDEX = 0,
    /* 网卡剥离的VLAN标签 */
    MR_BUFF_METADATA_VLAN_TCI = 1,
};

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "fake_mrtunnat.h"


#ifndef MARSIO_SOCKET_ID_ANY
#define MARSIO_SOCKET_ID_ANY -1
#endif

#ifndef MARSIO_LCORE_ID_ANY
#define MARSIO_LCORE_ID_ANY -1
#endif

typedef uint32_t device_id_t;
typedef uint32_t port_id_t;
typedef uint32_t queue_id_t;
typedef uint32_t thread_id_t;

#if 0  /* lijia 修改原始marsio定义 */
typedef void marsio_buff_t;

struct mr_sendpath;
struct mr_instance;
struct mr_vdev;

#else
#define FAKE_MARSIO_MTU  (2000)

typedef enum{
	VLAN_UPLINK_ID		= 1000,
	VLAN_DOWNLINK_ID	= 1001,
}vlan_flipping_tuple_t;


typedef struct{
	int by_malloc_need_free; /* malloc的内存, 需要free */
	
	vlan_flipping_tuple_t vlan_id; /* 模拟vlan flipping环境, marsio给数据包打上的原始vlan标签 */

	vlan_flipping_tuple_t after_sapp_flip_vlan_id; /* 经过sapp翻转, 或者主动注入数据包打上的标签 */
	
	unsigned char raw_pkt_data[FAKE_MARSIO_MTU]; /* 原始包 */
	int raw_pkt_len;

	struct mr_tunnat_ctrlzone ctrlzone;
}marsio_buff_t;


typedef struct{
	marsio_buff_t *pkt_array; /* 当前pcap包的镜像 */
	int pkt_num;	/* pcap包里的数据包个数 */
}pcap_queue_t;


struct mr_instance{
	void *log_handle;
	pcap_queue_t pkt_queue;
	int pcap_queue_index; /* 当前处理到第几个包 */
	marsio_buff_t inject_pkt_buf; /* 用于给sapp调用 marsio_buff_malloc_global() 的返回值, 可以保存插件注入的数据包, 用来比较 */
};


struct mr_vdev{
	char *device_name;
	struct mr_instance *mrins;
};


struct mr_sendpath{
	struct mr_instance *mrins;
};


struct pkt_check_args_t{
	struct mr_sendpath *mr_sndpath;
	struct mr_instance *mr_ins;
	marsio_buff_t *mbuff;
};

#endif




struct mr_instance *marsio_create();
struct mr_instance *marsio_current();

typedef int (*fn_sendpath_hook_t)(struct mr_sendpath *sendpath, marsio_buff_t *mbuf[], unsigned int nr_mbuf, void *arg);

int marsio_option_get(struct mr_instance *instance, int opt_type, void *out_opt, size_t out_opt_buffer);
int marsio_option_set(struct mr_instance *instance, marsio_opt_type_t opt_type, void *opt, size_t sz_opt);
int marsio_init(struct mr_instance *instance, const char *appsym);
int marsio_thread_init(struct mr_instance *instance);
int marsio_destory(struct mr_instance *instance);

struct mr_vdev *marsio_open_device(
        struct mr_instance *instance, const char *devsym, unsigned int nr_rxstream, unsigned int nr_txstream);

void marsio_close_device(struct mr_vdev *vdev);

struct mr_vdev *marsio_device_lookup(struct mr_instance *instance, const char *devsym);

int marsio_recv_burst(struct mr_vdev *vdev, queue_id_t qid, marsio_buff_t *mbufs[], int nr_mbufs);
int marsio_recv_all_burst(struct mr_instance *instance, queue_id_t qid, marsio_buff_t *mbufs[], int nr_mbufs);
int marsio_send_burst(struct mr_sendpath *sendpath, queue_id_t qid, marsio_buff_t *mbufs[], int nr_mbufs);
int marsio_send_burst_with_options(
        struct mr_sendpath *sendpath, queue_id_t sid, marsio_buff_t *mbufs[], int nr_mbufs, uint16_t options);
void marsio_send_burst_flush(struct mr_sendpath *sendpath, queue_id_t sid);

int marsio_udp_header_construct(marsio_buff_t *buff, uint16_t s_port, uint16_t d_port);
int marsio_ipv4_header_construct(marsio_buff_t *buff, uint32_t s_ip, uint32_t d_ip, uint8_t proto);

struct mr_sendpath *marsio_sendpath_create_by_droute(struct mr_vdev *dest_device, struct in_addr addr);
struct mr_sendpath *marsio_sendpath_create_by_route(struct mr_instance *instance, struct in_addr addr);
struct mr_sendpath *marsio_sendpath_create_by_vdev(struct mr_vdev *dest_device);

struct mr_sendpath *marsio_sendpath_create(struct mr_instance *instance, int type, ...);
int marsio_sendpath_option_set(struct mr_instance *instance, struct mr_sendpath *sendpath, int opt, ...);
int marsio_sendpath_option_get(struct mr_instance *instance, struct mr_sendpath *sendpath, int opt, ...);
void marsio_sendpath_destory(struct mr_sendpath *sendpath);

//simply get control zone data ptr.
void *marsio_buff_ctrlzone(marsio_buff_t *m, uint8_t id);

//a safe way to read control zone data.
void *marsio_buff_ctrlzone_data(marsio_buff_t *m, uint8_t id, uint8_t *size);

//a safe way to set control zone data.
void marsio_buff_ctrlzone_set(marsio_buff_t *m, uint8_t id, void *ptr_data, uint8_t size);

void marsio_buff_reset(marsio_buff_t *m);

marsio_buff_t *marsio_buff_getnext_seg(marsio_buff_t *m);
marsio_buff_t *marsio_buff_getnext_pkt(marsio_buff_t *m);

void marsio_buff_append_pkt(marsio_buff_t *head, marsio_buff_t *next);
void marsio_buff_append_seg(marsio_buff_t *head, marsio_buff_t *next);
void marsio_buff_chain_pkt(marsio_buff_t *pkt, marsio_buff_t *next);

uint16_t marsio_buff_headroom(const marsio_buff_t *m);
uint16_t marsio_buff_tailroom(const marsio_buff_t *m);

marsio_buff_t *marsio_buff_getnext_seg(marsio_buff_t *m);
marsio_buff_t *marsio_buff_getnext_pkt(marsio_buff_t *m);

char *marsio_buff_mtod(marsio_buff_t *m);

uint32_t marsio_buff_buflen(marsio_buff_t *m);

uint32_t marsio_buff_datalen(marsio_buff_t *m);

char *marsio_buff_prepend(marsio_buff_t *m, uint16_t len);

char *marsio_buff_append(marsio_buff_t *m, uint16_t len);

char *marsio_buff_adj(marsio_buff_t *m, uint16_t len);

int marsio_buff_trim(marsio_buff_t *m, uint16_t len);

char *marsio_buff_offset_set(marsio_buff_t *m, off_t offset, int is_relative);

off_t marsio_buff_offset_get(marsio_buff_t *m);

/* 支持写时复制的报文修改裁剪函数 */
marsio_buff_t *marsio_buff_prepend_cw(struct mr_instance *instance, marsio_buff_t *m, uint16_t len, void **ptr_out);

marsio_buff_t *marsio_buff_append_cw(struct mr_instance *instance, marsio_buff_t *m, uint16_t len, void **ptr_out);

marsio_buff_t *marsio_buff_adj_cw(struct mr_instance *instance, marsio_buff_t *m, uint16_t len, void **ptr_out);

marsio_buff_t *marsio_buff_trim_cw(struct mr_instance *instance, marsio_buff_t *m, uint16_t len, void **ptr_out);

uint16_t marsio_buff_headroom(const marsio_buff_t *m);

uint16_t marsio_buff_tailroom(const marsio_buff_t *m);

uint32_t marsio_get_pkt_type(marsio_buff_t *m);

void marsio_pktmbuf_dump(FILE *f, const marsio_buff_t *m, unsigned dump_len);

marsio_buff_t *marsio_buff_clone_deep(struct mr_instance *instance, marsio_buff_t *md, int socket_id, int thread_id);

marsio_buff_t *marsio_buff_clone_with_options(
        struct mr_instance *instance, marsio_buff_t *md, int socket_id, int thread_id, uint16_t options);

int marsio_buff_malloc_device(
        struct mr_vdev *vdev, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id);

int marsio_buff_malloc_global(struct mr_instance *instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs,
        int socket_id, int thread_id);

void marsio_buff_free(struct mr_instance *instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id,
        int thread_id);

int marsio_buff_is_ctrlbuf(marsio_buff_t *m);

void marsio_buff_set_ctrlbuf(marsio_buff_t *m);

uint64_t marsio_buff_get_timestamp(marsio_buff_t *m);
void marsio_buff_set_timestamp(marsio_buff_t *m, uint64_t timestamp);
int marsio_buff_get_timestamp_ex(marsio_buff_t *m, enum mr_timestamp_type ts_type, struct timespec *ts);

void marsio_buff_set_rehash_index(marsio_buff_t *m, uint32_t hash);
uint32_t marsio_buff_get_rehash_index(marsio_buff_t *m);

int marsio_buff_get_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
int marsio_buff_set_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
int marsio_buff_unset_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type);

void *marsio_shared_mem_alloc(struct mr_instance *instance, size_t len);
void marsio_shared_mem_free(struct mr_instance *instance, void *mem);

#ifdef __cplusplus
}
#endif
