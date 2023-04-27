#define _XOPEN_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _ISOC99_SOURCE 1
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>


#ifdef __cplusplus
extern "C"{
#endif

static const char *gs_version = "v1.0.0-20191119";

static void usage(const char *prog)
{
	printf("usage: %s <stream_id> [\"base_time\"]\n", prog);
	printf("\tbase_time format is: '%%Y-%%m-%%d %%H:%%M:%%S'\n");
	printf("\texample: %s 2274325413085511680\n", prog);
	printf("\texample: %s 2274319137695858688 \"2018-08-08 08:00:00\"\n", prog);
	exit(1);
}


static void decode(int argc, char *argv[])
{
#define RELATIVE_TIME_MAX (268435456L)

	time_t tt;
	struct tm ttm;
	struct tm *decode_time;
	char decode_time_str[32];
	int i;

	unsigned long long arg_stream_id = strtoull(argv[1], NULL, 10);

	unsigned long long dev_id_from_sapp = (arg_stream_id & 0x7FF8000000000000UL) >> 51;
	unsigned long long thread_id_from_sapp = (arg_stream_id & 0x0007F80000000000UL) >> 43;
	unsigned long long ts_from_sapp = (arg_stream_id & 0x07ffffff8000) >> 15;
	unsigned long long seq_per_thread = (arg_stream_id & 0x7FFF);

	printf("stream_id is %llu, decode result:\n", arg_stream_id);
	printf("    %-13s: %llu\n", "device-id", dev_id_from_sapp);
	printf("    %-13s: %llu\n", "thread-id", thread_id_from_sapp);
	printf("    %-13s: %llu\n", "relative-time", ts_from_sapp);
	printf("    %-13s: %llu\n", "sequence",seq_per_thread);
	
	if(argc >= 3){
		void *res = strptime(argv[2], "%Y-%m-%d %H:%M:%S", &ttm);
		if(NULL == res){
			printf("\033[1;31;40mbase time format error!\033[0m\n");
			return ;
		}
		
		tt = mktime(&ttm);
		tt += ts_from_sapp;

		decode_time = localtime(&tt);
		strftime(decode_time_str, sizeof(decode_time_str), "%Y-%m-%d %H:%M:%S", decode_time);
		printf("    %-13s: %s\n", "Absolute-time", decode_time_str);
	}else{ /* no base time asign */
		printf("    not input base time, use EPOCH as base time, absolute time maybe as follow:\n");

		for(i = 0; i < 10; i++){
			tt = RELATIVE_TIME_MAX * i + ts_from_sapp;
			decode_time = localtime(&tt);
			strftime(decode_time_str, sizeof(decode_time_str), "%Y-%m-%d %H:%M:%S", decode_time);
			printf("\t\t%s\n", decode_time_str);

		}
	}

}

int main(int argc, char *argv[])
{
	if(argc < 2){
		usage(argv[0]);
	}
	
	if(strncasecmp(argv[1], "-v", 2) == 0){
		printf("%s\n", gs_version);
		exit(0);
	}
	
	if(strncasecmp(argv[1], "-h", 2) == 0){
		usage(argv[0]);
	}

	if(strncasecmp(argv[1], "--help", 6) == 0){
		usage(argv[0]);
	}	

	decode(argc, argv);

	return 0;
}


#ifdef __cplusplus
}
#endif



