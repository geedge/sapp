#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif


#define HASH_RND_LEN_V4	(12 ) /* 2012-08-23 LiJia add, IPv4环境下四元组最大长度 */
#define HASH_RND_LEN_V6     (36 ) /*  2013-08-16 LiJia add, IPv6环境下四元组最大长度 */

/* 2013-08-16 LiJia modify, 
   因V4和V6的四元组长度不同, 在计算perm数组值时,按V6四元组长度初始化后,在V4环境下可能会使用合法地址之外数据,
   所以将V4和V6地址HASH值数组分开计算.
 */
static u_char xor4[HASH_RND_LEN_V4];
static u_char perm4[HASH_RND_LEN_V4];
static u_char xor6[HASH_RND_LEN_V6];
static u_char perm6[HASH_RND_LEN_V6];
static void getrnd(void)
{
    struct timeval s;
    u_int * ptr;
    int i;
    int fd = open ("/dev/urandom", O_RDONLY);
    if (fd > 0)
      {
		read (fd, xor4, HASH_RND_LEN_V4);
		read (fd, perm4, HASH_RND_LEN_V4);
		read (fd, xor6, HASH_RND_LEN_V6);
		read (fd, perm6, HASH_RND_LEN_V6);
	  close (fd);
	  return;
      }

    gettimeofday (&s, 0);
    srandom (s.tv_usec);
#if 0    /* 2012-08-23 LiJia modify */
    ptr = (u_int *) xor;
    *ptr = random ();
    *(ptr + 1) = random ();
    *(ptr + 2) = random ();
    ptr = (u_int *) perm;
    *ptr = random ();
    *(ptr + 1) = random ();
    *(ptr + 2) = random ();
#else
	for(ptr = (u_int *) xor4, i = 0; i < (int)HASH_RND_LEN_V4/(int)sizeof(int); i++)
	{
		*(ptr + i) = random();
	}

	for(ptr = (u_int *) perm4, i = 0; i < (int)HASH_RND_LEN_V4/(int)sizeof(int); i++)
	{
		*(ptr + i) = random();
	}	

	/* 2013-08-16 LiJia add */
	for(ptr = (u_int *) xor4, i = 0; i < (int)HASH_RND_LEN_V6/(int)sizeof(int); i++)
	{
		*(ptr + i) = random();
	}

	for(ptr = (u_int *) perm4, i = 0; i < (int)HASH_RND_LEN_V6/(int)sizeof(int); i++)
	{
		*(ptr + i) = random();
	}	
#endif

}


/* 2013-08-16 LiJia modify, V4和V6地址HASH值分开计算 */
static void init_hash_v4(void)
{
    int i, n, j;
    int p[HASH_RND_LEN_V4];

    for (i = 0; i < HASH_RND_LEN_V4; i++)
	p[i] = i;
    for (i = 0; i < HASH_RND_LEN_V4; i++)
      {
	  n = perm4[i] % (HASH_RND_LEN_V4 - i);
	  perm4[i] = p[n];
	  for (j = 0; j < HASH_RND_LEN_V4 - 1 - n; j++)
	      p[n + j] = p[n + j + 1];
      }
    
}

/* 2013-08-16 LiJia modify, V4和V6地址HASH值分开计算 */
static void init_hash_v6(void)
{
    int i, n, j;
    int p[HASH_RND_LEN_V6];

    for (i = 0; i < HASH_RND_LEN_V6; i++)
	p[i] = i;
    for (i = 0; i < HASH_RND_LEN_V6; i++)
      {
	  n = perm6[i] % (HASH_RND_LEN_V6 - i);
	  perm6[i] = p[n];
	  for (j = 0; j < HASH_RND_LEN_V6 - 1 - n; j++)
	      p[n + j] = p[n + j + 1];
      }
}

#if 0
void fix_rand_v4(void)
{
	*((unsigned int*)&xor4[0]) = 1010297553;
	*((unsigned int*)&xor4[4]) = 1654752629;
	*((unsigned int*)&xor4[8]) = 1527270735;
	 
	*((unsigned int*)&perm4[0]) = 1159559006 ;
	*((unsigned int*)&perm4[4]) = 4095079788;
	*((unsigned int*)&perm4[8]) = 2751541157;
}
#endif


void wy_init_hash(void)
{
#if 1 // 2014-12-17 lijia close for test 
    getrnd(); 
#else
    fix_rand_v4();
#endif
    init_hash_v4();
    init_hash_v6();

}

#if 0 /* 2012-08-23 LiJia delete */
u_int mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
    u_int res = 0;
    int i;
    u_char data[12];
    *(u_int *) (data) = src;
    *(u_int *) (data + 4) = dest;
    *(u_short *) (data + 8) = sport;
    *(u_short *) (data + 10) = dport;
    for (i = 0; i < 11; i++)
	res = ((res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
    return res;
}
#endif

#if (0 == USE_LINUX_KERNEL_HASH_ALGO)
//add by lqy 20120503
int mkaddrhash(char *pdata,int datalen)
{
    u_int res = 0;
    int i;
    u_char *p_xor, *p_perm;
   //tmp for 12 rand 
#if 0   /* 2012-08-23 LiJia modify */
    char *data=pdata+8;
    for (i = 0; i < datalen-1; i++)
	res = ((res << 8) + (data[perm[i]] ^ xor[i])) % 0xff100f;
#else
	char *data = pdata;
	if(HASH_RND_LEN_V4 == datalen)
	{
            p_xor = xor4;
            p_perm = perm4;
	}
	else
	{
            p_xor = xor6;
            p_perm = perm6;
	}
	
	for (i = 0; i < datalen; i++)
	{
		res = ((res << 8) + (data[p_perm[i]] ^ p_xor[i])) % 0xff100f;
	}	
#endif
	
    //printf("\ndata=%p, datalen=%d, hash vale = %u\n",pdata, datalen, res);
    return res;
}
#endif

#ifdef __cplusplus
}
#endif


