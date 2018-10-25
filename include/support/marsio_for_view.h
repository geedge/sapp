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
	/* 数据面线程绑定掩码，没有缺省值 
	 * 设置该掩码后，数据面线程数选项将被忽略。 
	 */
	MARSIO_OPT_THREAD_MASK,
	/* 处理SIG信号，缺省值：类型：uint32_t，关闭（0） 
	 * 启用该选项后，将自动处理SIGINT、SIGTERM信号
	 */
	MARSIO_OPT_EXIT_WHEN_ERR,

} marsio_opt_type_t;

typedef enum
{
    /* 发送后不释放数据包，由应用自行释放数据包 */
    MARSIO_SEND_OPT_NO_FREE = 1 << 0,
    /* 发送时计算发包哈希值，用于分流 */
    MARSIO_SEND_OPT_REHASH = 1 << 1,
    /* 快速报文路径 */
    MARSIO_SEND_OPT_FAST = 1 << 2
} marsio_opt_send_t;

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#ifndef SOCKET_ID_ANY
#define SOCKET_ID_ANY           -1
#endif

#ifndef LCORE_ID_ANY
#define LCORE_ID_ANY            -1
#endif
    
typedef uint32_t device_id_t;
typedef uint32_t port_id_t;
typedef uint32_t queue_id_t;
typedef uint32_t thread_id_t;
typedef void marsio_buff_t;

struct mr_sendpath;
struct mr_instance;
struct mr_vdev;

struct mr_instance * marsio_create();
struct mr_instance * marsio_current();

int marsio_option_get(struct mr_instance * instance, int opt_type, void * out_opt, size_t out_opt_buffer);
int marsio_option_set(struct mr_instance * instance, marsio_opt_type_t opt_type, void * opt, size_t sz_opt);
int marsio_init(struct mr_instance * instance, const char * appsym);
int marsio_thread_init(struct mr_instance * instance);
int marsio_destory(struct mr_instance * instance);

struct mr_vdev * marsio_open_device(struct mr_instance * instance,
    const char * devsym, unsigned int nr_rxstream, unsigned int nr_txstream);

void marsio_close_device(struct mr_vdev * vdev);

struct mr_vdev * marsio_device_lookup(struct mr_instance * instance, const char * devsym);

int marsio_recv_burst(struct mr_vdev * vdev, queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
int marsio_recv_all_burst(struct mr_instance * instance, queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
int marsio_send_burst(struct mr_sendpath * sendpath,  queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
int marsio_send_burst_with_options(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[],
    int nr_mbufs, uint16_t options);

int marsio_udp_header_construct(marsio_buff_t * buff, uint16_t s_port, uint16_t d_port);
int marsio_ipv4_header_construct(marsio_buff_t * buff, uint32_t s_ip, uint32_t d_ip, uint8_t proto);

struct mr_sendpath * marsio_sendpath_create_by_droute(struct mr_vdev * dest_device, struct in_addr addr);
struct mr_sendpath * marsio_sendpath_create_by_route(struct mr_instance * instance, struct in_addr addr);
struct mr_sendpath * marsio_sendpath_create_by_vdev(struct mr_vdev * dest_device);
void marsio_sendpath_destory(struct mr_sendpath * sendpath);

//simply get control zone data ptr.
void *marsio_buff_ctrlzone(marsio_buff_t *m, uint8_t id);

//a safe way to read control zone data.
void *marsio_buff_ctrlzone_data(marsio_buff_t *m, uint8_t id, uint8_t *size);

//a safe way to set control zone data.
void marsio_buff_ctrlzone_set(marsio_buff_t *m, uint8_t id, void* ptr_data, uint8_t size);

void marsio_buff_reset(marsio_buff_t *m);

marsio_buff_t *marsio_buff_getnext_seg(marsio_buff_t *m);
marsio_buff_t *marsio_buff_getnext_pkt(marsio_buff_t *m);

void marsio_buff_append_pkt(marsio_buff_t *head, marsio_buff_t *next);
void marsio_buff_append_seg(marsio_buff_t *head, marsio_buff_t *next);
void marsio_buff_chain_pkt(marsio_buff_t * pkt, marsio_buff_t * next);

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

uint16_t marsio_buff_headroom(const marsio_buff_t *m);

uint16_t marsio_buff_tailroom(const marsio_buff_t *m);

uint32_t marsio_get_pkt_type(marsio_buff_t *m);

marsio_buff_t *marsio_buff_dup(struct mr_vdev * vdev, marsio_buff_t *m);

int marsio_buff_malloc_device(struct mr_vdev * vdev, marsio_buff_t *marsio_buff[],
    unsigned int nr_mbufs, int socket_id, int thread_id);

int marsio_buff_malloc_global(struct mr_instance * instance, marsio_buff_t *marsio_buff[],
    unsigned int nr_mbufs, int socket_id, int thread_id);

void marsio_buff_free(struct mr_instance * instance, marsio_buff_t *marsio_buff[],
    unsigned int nr_mbufs, int socket_id, int thread_id);


#ifdef __cplusplus
}
#endif