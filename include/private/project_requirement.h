#ifndef _PROJECT_REQUIREMENT_H_
#define _PROJECT_REQUIREMENT_H_

/* 此文件与stream_project.h区别为: 本文件只用于平台内部使用 */

#include "private/stream_internal.h"
#include "private/ip_reassembly.h"

#ifdef __cplusplus
extern "C" {
#endif

void *project_requirement_create(int thread_num);
void project_requirement_destroy(int thread_num, void *pproject);
int raw_ip_frag_list_stream_attach(struct streaminfo *stream);
int raw_ip_frag_list_stream_detach(struct streaminfo *stream);
void raw_frags_list_free_one(int thread_seq, void *project_req_value);
raw_ipfrag_list_t *raw_ip_frag_list_move_pkt(struct streaminfo *stream);
int frags_list_append(struct frag_ipq *ipq, const raw_pkt_t *raw_pkt, int type, int thread_num);

#ifdef __cplusplus
}
#endif

#endif

