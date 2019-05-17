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

#endif

