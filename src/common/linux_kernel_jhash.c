#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#if USE_LINUX_KERNEL_HASH_ALGO


#ifndef u32
typedef unsigned int u32;
#endif

#ifndef __u32
typedef unsigned int __u32;
#endif

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)


/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

#if 0
/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c;
	const u8 *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);
		b += __get_unaligned_cpu32(k + 4);
		c += __get_unaligned_cpu32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	/* All the case statements fall through */
	switch (length) {
	case 12: c += (u32)k[11]<<24;
	case 11: c += (u32)k[10]<<16;
	case 10: c += (u32)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (u32)k[7]<<24;
	case 7:  b += (u32)k[6]<<16;
	case 6:  b += (u32)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (u32)k[3]<<24;
	case 3:  a += (u32)k[2]<<16;
	case 2:  a += (u32)k[1]<<8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}
#endif

/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{
	u32 a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + (length<<2) + initval;

	/* Handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/* Handle the last 3 u32's: all the case statements fall through */
	switch (length) {
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		__jhash_final(a, b, c);
	case 0:	/* Nothing left to add */
		break;
	}

	return c;
}


/* jhash_3words - hash exactly 3, 2 or 1 word(s) */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}


static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
	return jhash_3words(a, b, 0, initval);
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}


static inline u32 jhash_4words(u32 a, u32 b, u32 c, u32 initval, u32 *out_val)
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__jhash_final(a, b, c);

	*out_val = b;

	return c;
}


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
		//printf("stream_make_hash() error, addr type is not IPv4 or IPv6!\n");
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

