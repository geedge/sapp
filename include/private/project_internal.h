#ifndef _PROJECT_INTERNAL_H_
#define _PROJECT_INTERNAL_H_

#include "private/mesa_net.h"
#include "private/stream_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

void *project_requirement_create(int thread_num);
void project_requirement_destroy(int thread_num, void *pproject);

raw_ipfrag_list_t *raw_ip_frag_list_move_pkt(struct streaminfo *stream);
raw_ipfrag_list_t *raw_ip_frag_list_global_move_pkt(struct streaminfo *stream);
int update_global_ip_frag_list(raw_ipfrag_list_t *list_head, int thread_num, int type);
int update_stream_ip_frag_list(struct streaminfo *stream, raw_ipfrag_list_t *list_head);
void raw_frags_list_free_one(int thread_num, void *);
void raw_frags_list_free_stream(int thread_num, struct streaminfo *stream);
int raw_ip_frag_list_stream_attach(struct streaminfo *stream);
int raw_ip_frag_list_stream_detach(struct streaminfo *stream);


int gdev_check_pkt(int addr_type, void *pkt_data);

#ifdef __cplusplus
}
#endif
#endif

