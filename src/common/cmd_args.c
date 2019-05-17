#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include "sapp_api.h"


typedef int args_legality_check_t(const char *opt_name, const char *opt_arg);

typedef struct{
	const char *long_opt_name;
	args_legality_check_t *check_fun;
	const char *usage;
}sapp_cmd_args_usage_t;


typedef struct{
	const char *long_opt_name;
	sapp_tlv_t arg_val;
}sapp_cmd_args_val_t; 

/* 用于存储解析后的命令行参数,不直接对外提供,其他模块靠 sapp_get_cla()获取 */
static sapp_cmd_args_val_t **g_cmd_args_val;
static int g_cmd_args_num = 0;

static inline int dumpfile_speed_check(const char *opt_name, const char *opt_arg)
{
	int ret;
	
	if(strncasecmp(opt_arg, "top-speed", strlen("top-speed")) == 0){
		ret = 0;
	}else if(strncasecmp(opt_arg, "timestamp", strlen("timestamp")) == 0){
		ret = 0;
	}else{
		ret = -1;
	}

	return ret;
}



static const sapp_cmd_args_usage_t cmd_args_usage[] = 
{
	{"help", 	NULL,	"show help message"},
	{"version", NULL,	"show platform version"},
	{"dumpfile", NULL,	"running as pcap dumpfile mode"},
	{"dumpfile-speed",	dumpfile_speed_check, "\n  \ttop-speed\tprocess packets as fast as possible, this is default option\n  \ttimestamp\tprocess packets as pcap file timestamp interval"},
	{NULL, 		NULL}
};

static const char *sapp_cla_short_options = "hv";

static const struct option sapp_cla_long_options[] = 
{
	{"help",		no_argument,      NULL,      'h'},
	{"version",		no_argument,      NULL,      'v'},
	{"dumpfile",	no_argument,      NULL,      '#'},
	{"dumpfile-speed",	required_argument,      NULL,      '#'},
	{NULL,          0,      NULL,      0}
};


static int check_args_legality(const char *opt_name, const char *opt_arg)
{
	int index = 0, ret = 0;

	while(cmd_args_usage[index].long_opt_name != NULL){
		/* 选项名称要用不同的长度比较两次, 防止dumpfile 与 dumpfile-speed使用较短长度比较, 而误命中的情况 */
		if((strncasecmp(opt_name, cmd_args_usage[index].long_opt_name, strlen(opt_name)) == 0)
		 && (strncasecmp(opt_name, cmd_args_usage[index].long_opt_name, strlen(cmd_args_usage[index].long_opt_name)) == 0)
		 && (cmd_args_usage[index].check_fun != NULL)){
			ret = cmd_args_usage[index].check_fun(opt_name, opt_arg);
			break;
		 }

		 index++;
	}

	return ret;
}

/* 检查不同参数之间的相互关联关系 */
static int check_args_sanity(void)
{
	//TODO
	return 0;
}




static void usage(void)
{
	int index = 0;

	printf("Usage:\n");
	while(cmd_args_usage[index].long_opt_name != NULL){
		printf("  --%s\t%s\n", cmd_args_usage[index].long_opt_name, cmd_args_usage[index].usage);
		index++;
	}
	exit(1);
}


int sapp_get_cla(const char *opt_long_name, char ** const opt_string_value)
{
	int i, ret = -1;

	if(NULL == opt_long_name || NULL == opt_string_value || NULL == *opt_string_value){
		return -1;
	}

	for(i = 0; i < g_cmd_args_num; i++){
		/* 选项名称要用不同的长度比较两次, 防止dumpfile 与 dumpfile-speed使用较短长度比较, 而误命中的情况 */
		if((strncasecmp(opt_long_name, g_cmd_args_val[i]->long_opt_name, strlen(opt_long_name)) == 0)
		 && (strncasecmp(opt_long_name, g_cmd_args_val[i]->long_opt_name, strlen(g_cmd_args_val[i]->long_opt_name)) == 0)){
			if(g_cmd_args_val[i]->arg_val.string_value != NULL){
				*opt_string_value = g_cmd_args_val[i]->arg_val.string_value;
				ret = 1;
			}else{
				*opt_string_value = NULL;
				ret = 0;
			}

			break;
		}
	}

	return ret;
}

static int store_cmd_args(const char *opt_name, const char *opt_arg)
{
	sapp_cmd_args_val_t *new_opt;
	char *void_val;

	if(sapp_get_cla(opt_name, &void_val) != -1){
		printf("Error! Duplicate option: %s\n", opt_name);
		return -1;
	}

	new_opt = (sapp_cmd_args_val_t *)calloc(1, sizeof(sapp_cmd_args_val_t));
	new_opt->long_opt_name = strdup(opt_name);
	if(opt_arg){
		new_opt->arg_val.string_value = strdup(opt_arg);
	}
	
	if(NULL == g_cmd_args_val){
		g_cmd_args_val = (sapp_cmd_args_val_t **)calloc(1, sizeof(void *));
	}else{
		g_cmd_args_val = (sapp_cmd_args_val_t **)realloc(g_cmd_args_val, sizeof(void *) * (g_cmd_args_num + 1));
	}

	g_cmd_args_val[g_cmd_args_num] = new_opt;

	g_cmd_args_num++;

	return 0;
}


int sapp_parse_cmd_args(int argc, char *argv[])
{
	int ret = 0;
	int c;
	int opt_index;

	while(1){
		c = getopt_long(argc, argv, sapp_cla_short_options, sapp_cla_long_options, &opt_index);
		if(c == -1){
			ret = 0;
			break;	
		}

		switch(c){
			case 'h':
				usage();
			break;

			case 'v':
				printf("Version: %s\n", GITVER);
				exit(1);
			break;

			case '?': /* invalid or unknown option */
				ret = -1;
				return ret;
			break;
		}

		if(sapp_cla_long_options[opt_index].has_arg != no_argument){
			ret = check_args_legality(sapp_cla_long_options[opt_index].name, optarg);
			if(ret < 0){
				printf("Invalid args for '%s':%s\n", sapp_cla_long_options[opt_index].name, optarg);
				return -1;
			}
		}

		if(store_cmd_args(sapp_cla_long_options[opt_index].name, optarg) < 0){
			return -1;
		}
	}

	if(check_args_sanity() < 0){
		return -1;
	}

	return ret;
}


#ifdef __cplusplus
}
#endif



