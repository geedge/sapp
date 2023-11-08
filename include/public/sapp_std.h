#ifndef _SAPP_STD_H_
#define _SAPP_STD_H_ 1

typedef struct {
	unsigned short type;
	unsigned char user_arg1;
	unsigned char user_arg2;
	unsigned int length;
	union{
		char	char_value;
		unsigned char uchar_value;
		short	short_value;
		unsigned short ushort_value;
		int		int_value;
		unsigned int uint_value;
		long long	long_value;
		unsigned long long ulong_value;
		char	*string_value; 	/* standard C string with EOF('\0'), length include EOF, differ with strlen() */
		void	*bin_value; 	/* unprintable character, binary data, or custom complex struct. */
	};
}sapp_tlv_t;


#ifndef ALLOC
#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#endif

#define	TRUE	1
#define	FALSE	0

#ifndef FREE
#define FREE(p)	{free(*p);*p=NULL;}
#endif

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#endif

#define timeval_delta_ms(start, end) ((end.tv_sec-start.tv_sec)*1000 + (end.tv_usec-start.tv_usec)/1000)


#endif

