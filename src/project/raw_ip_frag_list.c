#ifdef __cplusplus
extern "C" {
#endif

/*  
	应某项目需求, 存储全部原始IP分片包, 暂不支持隧道协议内多层分片的情况!
*/

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

//extern int g_packet_io_thread_num;

static int g_raw_ip_frag_list_v4_plugid = -1;
static int g_raw_ip_frag_list_v6_plugid = -1;
static raw_ipfrag_list_t **G_IP_FRAG_LIST_V4; 
static raw_ipfrag_list_t **G_IP_FRAG_LIST_V6; 


static inline int ip_frag_module_enable(int type)
{
	int plug_id = -1;
	
	if((__ADDR_TYPE_IP_PAIR_V4 == type) || (ADDR_TYPE_IPV4 == type)){
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if((__ADDR_TYPE_IP_PAIR_V6 == type) || (ADDR_TYPE_IPV6 == type)){
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}

	return plug_id;
}

int frags_list_append(struct frag_ipq *ipq, const raw_pkt_t *raw_pkt, int type, int thread_num)
{
	raw_ipfrag_list_t *new_list_node, *tail_list_node;
	int pkt_len, plug_id;
	void *save_pkt_ptr;

	if((__ADDR_TYPE_IP_PAIR_V4 == type) || (ADDR_TYPE_IPV4 == type)){
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if((__ADDR_TYPE_IP_PAIR_V6 == type) || (ADDR_TYPE_IPV6 == type)){
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return -1;
	}

	if(-1 == plug_id){
		return -1;
	}

	pkt_len = raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes; /* 2021-07-29 lijia modify, inline模式下, 原始ip分片包不包括overlay层 */
	save_pkt_ptr = sapp_mem_malloc(SAPP_MEM_DYN_IP_FRAG_PKT, thread_num, pkt_len);
	memcpy(save_pkt_ptr, (const char *)(raw_pkt->raw_pkt_data) + raw_pkt->overlay_layer_bytes, pkt_len);
	new_list_node = (raw_ipfrag_list_t *)sapp_mem_malloc(SAPP_MEM_DYN_IP_FRAG_PKT,thread_num, sizeof(raw_ipfrag_list_t));
	new_list_node->frag_packet = save_pkt_ptr;
	new_list_node->pkt_len = pkt_len;
	new_list_node->type = type;
	new_list_node->next = NULL;
	if(NULL == ipq->ipfrag_list){ /* is first node */
		ipq->ipfrag_list = new_list_node;
	}else {
		tail_list_node = ipq->ipfrag_list;
		while(tail_list_node->next){
			tail_list_node = tail_list_node->next;
		}
		tail_list_node->next = new_list_node; /* link the tail of current list */
	}
	
	return 0;
}


void raw_frags_list_free_one(int thread_seq, void *project_req_value)
//void raw_frags_list_free_one(raw_ipfrag_list_t *frags_list, int thread_num)
{
	raw_ipfrag_list_t *frags_list_head, *free_node, *next;
	
	if(NULL == project_req_value){
		return;
	}

	frags_list_head = (raw_ipfrag_list_t *)project_req_value;
	
#if 0 // for debug 
    __frags_list_check(frags_list);
#endif

	free_node = frags_list_head;
	while(free_node){
		next = free_node->next;
#if 0
	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)((char *)free_node->frag_packet + 14);
	printf("##### frag free  ip id:0x%x\n", ntohs(ip4hdr->ip_id));
#endif		
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT,thread_seq, free_node->frag_packet);
		sapp_mem_free(SAPP_MEM_DYN_IP_FRAG_PKT,thread_seq, free_node);
		free_node = next;
	}

	return;
}

void raw_frags_list_free_global(int thread_num, int type)
{
	if((__ADDR_TYPE_IP_PAIR_V4 == type) || (ADDR_TYPE_IPV4 == type)){
		if(-1 == g_raw_ip_frag_list_v4_plugid){
			return;
		}
		raw_frags_list_free_one(thread_num, G_IP_FRAG_LIST_V4[thread_num]);
		G_IP_FRAG_LIST_V4[thread_num] = NULL;
	}else if((__ADDR_TYPE_IP_PAIR_V6 == type) || (ADDR_TYPE_IPV6 == type)){
		if(-1 == g_raw_ip_frag_list_v6_plugid){
			return;
		}
		raw_frags_list_free_one(thread_num, G_IP_FRAG_LIST_V6[thread_num]);
		G_IP_FRAG_LIST_V6[thread_num] = NULL;
	}

	return;
}

void raw_frags_list_free_stream(int thread_num, struct streaminfo *stream)
{
	raw_ipfrag_list_t *stream_frag_list;
	//void **p_private;
	int plug_id = -1;
	UCHAR addr_type = stream->addr.addrtype;

	if((__ADDR_TYPE_IP_PAIR_V4 == addr_type) || (ADDR_TYPE_IPV4 == addr_type)){
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if((__ADDR_TYPE_IP_PAIR_V6 == addr_type) || (ADDR_TYPE_IPV6 == addr_type)){
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}

	if(-1 == plug_id){
		return;
	}

#if 0	
	p_private = project_get_private_info(stream->pproject, project_req_type);
	if(NULL == p_private){
		printf("raw_frags_list moudle error, no mem space!\n");
		assert(0);
		return;	
	}
	stream_frag_list = (raw_ipfrag_list_t *)(*p_private);
#else
	stream_frag_list = (raw_ipfrag_list_t *)project_req_get_struct(stream, plug_id);

#endif

	raw_frags_list_free_one(stream->threadnum, stream_frag_list);

	/* clear stream->project */
	project_req_add_struct(stream, plug_id, NULL);
	
	return;
}

raw_ipfrag_list_t *frags_list_merge(raw_ipfrag_list_t *new_merge_list, raw_ipfrag_list_t *old_list)
{   
    raw_ipfrag_list_t *tail;
    if((NULL == new_merge_list) && (NULL == old_list))
    {
        return NULL;
    }
    if(NULL == new_merge_list)
    {
        return old_list;
    }
    tail = new_merge_list;
    while(tail->next)
    {
        tail = tail->next;
    }
    tail->next = old_list;
    return new_merge_list;
}

#if 0
void __frags_list_check(raw_ipfrag_list_t *frags_list)
{
    struct ip *ipv4_hdr;
    struct ip6_hdr *ipv6_hdr;
    int pkt_len;
    while(frags_list)
    {
        if(__ADDR_TYPE_IP_PAIR_V4 == frags_list->type)
        {
            ipv4_hdr = (struct ip *)frags_list->frag_packet;
            pkt_len = ntohs(ipv4_hdr->ip_len);
        }
        else
        {
            ipv6_hdr = (struct ip6_hdr *)frags_list->frag_packet;
            pkt_len = ntohs(ipv6_hdr->ip6_plen) + sizeof(struct ip6_hdr);
        }
        //printf("%d->", pkt_len);
        frags_list = frags_list->next;
    }
    //printf("\n");
}


static raw_ipfrag_list_t **get_ip_frag_private_info(struct streaminfo *stream)
{
	int project_req_type;

	if(__ADDR_TYPE_IP_PAIR_V4 == stream->addr.addrtype){
		project_req_type = PROGECT_REQUIREMENT_IPV4_FRAG_LIST;
	}else{
		project_req_type = PROGECT_REQUIREMENT_IPV6_FRAG_LIST;
	}
	
	return (raw_ipfrag_list_t **)project_get_private_info(stream->pproject, project_req_type);
}
#endif

int raw_ip_frag_list_stream_attach(struct streaminfo *stream)
{
	raw_ipfrag_list_t **g_frag_list;
	int plug_id;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V4;
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if(ADDR_TYPE_IPV6 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V6;
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return -1;
	}

	if(-1 == plug_id){
		return -1;
	}

	
#if 0
	p_private = project_get_private_info(stream->pproject, project_req_type);
	if(NULL == p_private){
		return -1;
	}
	p_stream_info = (raw_ipfrag_list_t **)p_private;
	*p_stream_info = g_frag_list[stream->threadnum];
#else
	project_req_add_struct(stream, plug_id, (void *)(g_frag_list[stream->threadnum]));
	g_frag_list[stream->threadnum] = NULL; /* 2014-10-10 lijia add */
#endif

	return 0;
}

int raw_ip_frag_list_stream_detach(struct streaminfo *stream)
{
	int plug_id;
	raw_ipfrag_list_t **g_frag_list;
	
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V4;
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if (ADDR_TYPE_IPV6 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V6;
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return -1;
	}

	if(-1 == plug_id){
		return -1;
	}
	
#if 0
	p_private = project_get_private_info(stream->pproject, project_req_type);
	if(NULL == p_private){
		return -1;
	}
	p_stream_info = (raw_ipfrag_list_t **)p_private;
	*p_stream_info = NULL;
#else
	g_frag_list[stream->threadnum] = (raw_ipfrag_list_t *)project_req_get_struct(stream, plug_id); /* 2014-10-10 lijia add */
	project_req_add_struct(stream, plug_id, NULL); //置空
#endif

	return 0;
}


/* IP分片链表暂存于'struct buf_unorder'结构中, 然后将g_frag_list[tid]指针置空, 避免被ip_entry层释放 */
raw_ipfrag_list_t *raw_ip_frag_list_move_pkt(struct streaminfo *stream)
{
	raw_ipfrag_list_t *pkt_frag_list;
	raw_ipfrag_list_t **g_frag_list;
	int plug_id = -1;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V4;
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if (ADDR_TYPE_IPV6 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V6;
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return NULL;
	}

	if(-1 == plug_id){
		return NULL;
	}

#if 0	
	p_private = project_get_private_info(stream->pproject, project_req_type);
	
	pkt_frag_list = (raw_ipfrag_list_t *)(*p_private);
#else
	pkt_frag_list = (raw_ipfrag_list_t *)project_req_get_struct(stream, plug_id);
	project_req_add_struct(stream, plug_id, NULL);
#endif

	g_frag_list[stream->threadnum] = NULL;

	return pkt_frag_list;
}

int update_global_ip_frag_list(raw_ipfrag_list_t *list_head, int thread_num, int type)
{	
	if((__ADDR_TYPE_IP_PAIR_V4 == type) && (g_raw_ip_frag_list_v4_plugid >= 0)){
		G_IP_FRAG_LIST_V4[thread_num] = list_head;
	}else if((__ADDR_TYPE_IP_PAIR_V6 == type) && (g_raw_ip_frag_list_v6_plugid >= 0)){
		G_IP_FRAG_LIST_V6[thread_num] = list_head;
	}else{
		return -1;
	}
	
	return 0;
}

int update_stream_ip_frag_list(struct streaminfo *stream, raw_ipfrag_list_t *list_head)
{
	int plug_id;

	plug_id = ip_frag_module_enable(stream->addr.addrtype);
	if(-1 == plug_id){
		return -1;
	}

#if 0	
	p_private = project_get_private_info(stream->pproject, project_req_type);
	
	(*p_private) = (void *)list_head;
#else
	project_req_add_struct(stream, 	plug_id, list_head);
#endif
	return 0;
}


const raw_ipfrag_list_t *get_raw_frag_list(const struct streaminfo *stream)
{
	const raw_ipfrag_list_t *ip_frag_list = NULL;
	
	if((__ADDR_TYPE_IP_PAIR_V4 == stream->addr.addrtype)
	|| (ADDR_TYPE_IPV4 == stream->addr.addrtype)){
		ip_frag_list = (const raw_ipfrag_list_t *)project_req_get_struct(stream, g_raw_ip_frag_list_v4_plugid);
	}else if ((__ADDR_TYPE_IP_PAIR_V6 == stream->addr.addrtype)
	 ||(ADDR_TYPE_IPV6 == stream->addr.addrtype)){
		ip_frag_list = (const raw_ipfrag_list_t *)project_req_get_struct(stream, g_raw_ip_frag_list_v6_plugid);
	}else{
		ip_frag_list = NULL;
		sapp_runtime_log(RLOG_LV_FATAL, "get_raw_frag_list(), unknown addrtype:%d.\n", stream->addr.addrtype);		
	}

	return ip_frag_list;
}

/* 2016-03-11 lijia add, 
   papp平台下, Ip层插件无streaminfo结构体, 也就无法获取原始IP分片报文列表, 
   新增如下函数:
*/

const raw_ipfrag_list_t *ip_plug_get_raw_ipfrag_list(int thread_num, enum addr_type_t addr_type)
{
	if(ADDR_TYPE_IPV4 == addr_type){
		return G_IP_FRAG_LIST_V4[thread_num];
	}else if(ADDR_TYPE_IPV6 == addr_type){
		return G_IP_FRAG_LIST_V6[thread_num];
	}

	return NULL;
}

void set_raw_frag_list(struct streaminfo *stream, void *list_head)
{
	int plug_id;
	
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if (ADDR_TYPE_IPV6 == stream->addr.addrtype){
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return ;
	}

	if(-1 == plug_id){
		return;
	}

	project_req_add_struct(stream, plug_id, list_head);

	return;
}

int raw_ip_frag_list_v4_init(void)
{
#if (0 == HIGH_PERF)	
	int project_req_id;

	G_IP_FRAG_LIST_V4 = (raw_ipfrag_list_t **)calloc(g_packet_io_thread_num, sizeof(void *));
	memset(G_IP_FRAG_LIST_V4, 0, g_packet_io_thread_num*sizeof(void *));
	
	project_req_id = project_producer_register(RAW_FRAG_V4_MODULE_NAME, "struct", raw_frags_list_free_one);
	if(project_req_id >= 0){
		g_raw_ip_frag_list_v4_plugid = project_req_id;
	}else{
		/* 配置文件没有'ipv4_frag_list'项, 关闭此功能 */
		g_raw_ip_frag_list_v4_plugid = -1;
	}
#endif
	return 0;
}

int raw_ip_frag_list_v6_init(void)
{
#if (0 == HIGH_PERF)	
	int project_req_id;
	
	G_IP_FRAG_LIST_V6 = (raw_ipfrag_list_t **)calloc(g_packet_io_thread_num, sizeof(void *));
	memset(G_IP_FRAG_LIST_V6, 0, g_packet_io_thread_num*sizeof(void *));
	
	project_req_id = project_producer_register(RAW_FRAG_V6_MODULE_NAME, "struct", raw_frags_list_free_one);
	if(project_req_id >= 0){
		g_raw_ip_frag_list_v6_plugid = project_req_id;
	}else{
		/* 配置文件没有'ipv6_frag_list'项, 关闭此功能 */
		g_raw_ip_frag_list_v6_plugid = -1;
	}
#endif
	return 0;
}


/* IP分片链表暂存于'struct buf_unorder'结构中, 然后将g_frag_list[tid]指针置空, 避免被ip_entry层释放 */
raw_ipfrag_list_t *raw_ip_frag_list_global_move_pkt(struct streaminfo *stream)
{
	raw_ipfrag_list_t *pkt_frag_list;
	raw_ipfrag_list_t **g_frag_list;
	int plug_id;

	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V4;
		plug_id = g_raw_ip_frag_list_v4_plugid;
	}else if (ADDR_TYPE_IPV6 == stream->addr.addrtype){
		g_frag_list = G_IP_FRAG_LIST_V6;
		plug_id = g_raw_ip_frag_list_v6_plugid;
	}else{
		return NULL;
	}

	if(-1 == plug_id){
		return NULL;
	}

	pkt_frag_list = g_frag_list[stream->threadnum];

	g_frag_list[stream->threadnum] = NULL;

	return pkt_frag_list;
}

void raw_ip_frag_list_v4_destroy(void)
{
	free(G_IP_FRAG_LIST_V4);
	G_IP_FRAG_LIST_V4 = NULL;
	g_raw_ip_frag_list_v4_plugid = -1;
}

void raw_ip_frag_list_v6_destroy(void)
{
	free(G_IP_FRAG_LIST_V6);
	G_IP_FRAG_LIST_V6 = NULL;
	g_raw_ip_frag_list_v6_plugid = -1;
}


#ifdef __cplusplus
}
#endif


