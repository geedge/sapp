#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h"
#include "linux_kernel_jhash.h"
#include <MESA/MESA_handle_logger.h>

#if USE_LINUX_KERNEL_HASH_ALGO
int stream_make_hash(struct streaminfo_private *stream_pr, unsigned int maxsize)
{
	unsigned int a, b;
	unsigned short c, d;
	unsigned int hash_val;
	void *for_werror_compile;
	const struct layer_addr *addr = &stream_pr->stream_public.addr;

	if(ADDR_TYPE_IPV4== addr->addrtype){
		const struct stream_tuple4_v4 *tuple4_v4 = addr->tuple4_v4;	
		if(1 == stream_pr->layer_dir){
			a = tuple4_v4->saddr;
			b = tuple4_v4->daddr;
			c = tuple4_v4->source;
			d = tuple4_v4->dest;
		}else{
			a = tuple4_v4->daddr;
			b = tuple4_v4->saddr;
			c = tuple4_v4->dest;
			d = tuple4_v4->source;			
		}
	}else if(ADDR_TYPE_IPV6 == addr->addrtype){
		const struct stream_tuple4_v6 *tuple4_v6 = addr->tuple4_v6;	
		if(1 == stream_pr->layer_dir){
#if 0 /* 20160930 lijia add, 编译器警告不对齐问题 */		
			a = *((unsigned int *)(&tuple4_v6->saddr[12]));
			b = *((unsigned int *)(&tuple4_v6->daddr[12]));
#elif 0
			memcpy(&a, &tuple4_v6->saddr[12], sizeof(int));
			memcpy(&b, &tuple4_v6->daddr[12], sizeof(int));
#else
			for_werror_compile = (void *)(&tuple4_v6->saddr[12]);
			a = *((unsigned int *)for_werror_compile);
			for_werror_compile = (void *)(&tuple4_v6->daddr[12]);
			b = *((unsigned int *)for_werror_compile);			
#endif
			c = tuple4_v6->source;
			d = tuple4_v6->dest;			
		}else{
#if 0	/* 20160930 lijia add, 编译器警告不对齐问题 */		
			a = *((unsigned int *)(&tuple4_v6->daddr[12]));
			b = *((unsigned int *)(&tuple4_v6->saddr[12]));
#else
			memcpy(&a, &tuple4_v6->daddr[12], sizeof(int));
			memcpy(&b, &tuple4_v6->saddr[12], sizeof(int));
#endif
			c = tuple4_v6->dest;
			d = tuple4_v6->source;				
		}
	}else{
		printf("stream_make_hash() error, addr type is not IPv4 or IPv6!\n");
		sapp_runtime_log(RLOG_LV_FATAL, "stream_make_hash() error, addr type is not IPv4 or IPv6!\n");
		abort();
	}

	//hash_val = jhash_3words(a, b, c, d);	
	hash_val = jhash_4words(a, b, c, d, &stream_pr->hash_slave);	

#if HIGH_PERF
	return hash_val & (maxsize - 1);
#else
	return hash_val % maxsize;
#endif	
}
#endif

#ifdef __cplusplus
}
#endif

