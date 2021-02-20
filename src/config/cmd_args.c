#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef GIT_VERSION
 __attribute__((__used__)) const char *sapp_git_ver = GIT_VERSION;
#endif


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


static char *popen_result_store(FILE *fp)
{
	int chr;
	char *exec_result;
	int exec_result_size = 0;
	char line_buf[PATH_MAX];

	exec_result = (char *)malloc(1);
	
	while((chr = fgetc(fp)) != EOF){
		exec_result = realloc(exec_result, exec_result_size + 2);
		exec_result[exec_result_size] = (char)chr;
		exec_result_size++;
	}

	exec_result[exec_result_size] = '\0';

	if(exec_result_size <= 0){
		free(exec_result);
		return NULL;
	}

	return exec_result;
}


static int get_dumpfile_list_array(const char *opt_arg)
{
	FILE *fp;
	char *exec_result, *tobe_free_result;

	/* 先执行一遍, 看命令是否成功 */
	sapp_log(10, ~0, ~0, "Executing command --dumpfile-file '%s' ... ", opt_arg);
	if(system(opt_arg) != 0){
		sapp_log(30, ~0, ~0, "Execute command --dumpfile-file '%s' error!", opt_arg);
		exit(1);		
	}

	fp = popen(opt_arg, "r");
	if(NULL == fp){
		sapp_log(30, ~0, ~0, "Execute command --dumpfile-file '%s' error!", opt_arg);
		exit(1);
	}

	exec_result = popen_result_store(fp);
	if(NULL == exec_result){
		sapp_log(30, ~0, ~0, "Execute command --dumpfile-file '%s', but no valid result!", opt_arg);
		exit(1);
	}

	const char *delim = "\n\r";
	char *ptr_cont;
	int line_num = 0;

	tobe_free_result = exec_result;
	sapp_global_val->cla.dumpfie_list_array = NULL;
	
	while(ptr_cont = strtok(exec_result, delim)){
		sapp_global_val->cla.dumpfie_list_array = (char **)realloc(sapp_global_val->cla.dumpfie_list_array, sizeof(void *) * (line_num + 2));//当前要存储的指针再加上EOF
		sapp_global_val->cla.dumpfie_list_array[line_num] = strdup(ptr_cont);;
		
		//printf("#### %d: result_content:%s\n", line_num, sapp_global_val->cla.dumpfie_list_array[line_num]);
		line_num++;
		exec_result = NULL;
	}

	sapp_global_val->cla.dumpfie_list_array[line_num] = NULL; //EOF

	free(tobe_free_result);
	fclose(fp);

	return 0;
}


/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const sapp_cmd_args_usage_t cmd_args_usage[] = 
{
	{"-h", "help", 		NULL,	"show help message"},
	{"-v", "version", 	NULL,	"show platform version"},
	{"-g", "coredump", 	NULL,	"generate coredump for test"},
	{"-c", "sample-config", NULL, "generate sample config file->sapp.toml"},
	{"-d", "dumpfile", 	NULL,	"running as pcap offline mode, default pcap file is './dumpfile'"},
	{"-r", "dumpfile-file", NULL,	"read packets from which pcap file"},
	{"-f", "dumpfile-list", NULL, "get the list of pcap files by command, example: 'ls files/*.pcap', 'find /home/files -name *.pcap'"},
	{"-p",  "dumpfile-speed",	dumpfile_speed_check, "\n  \t\ttop-speed\tprocess packets as fast as possible, this is default behavior\n  \t\ttimestamp\tprocess packets as pcap file timestamp interval"},
	{NULL,	NULL, 		NULL}
};

/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const char *sapp_cla_short_options = "cdhr:p:f:vg";

/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const struct option sapp_cla_long_options[] = 
{
	{"help",			no_argument,      	NULL,      'h'},
	{"version",			no_argument,      	NULL,      'v'},
	{"dumpfile",		no_argument,      	NULL,      'd'},
	{"dumpfile-file",	required_argument,  NULL,      'r'},
	{"dumpfile-list",	required_argument,  NULL,      'f'},
	{"dumpfile-speed",	required_argument,  NULL,      'p'},
	{"sample-config", 	no_argument,      	NULL,      'c'},
	{"coredump", 		no_argument,      	NULL,      'g'},
	{NULL,          	0,      			NULL,      0}
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
	char *no_use;
	int dumpfile_mode_enabled = 0;

	if(sapp_get_cla_raw("dumpfile", &no_use) >= 0){
		dumpfile_mode_enabled = 1;
	}

	if((sapp_get_cla_raw("dumpfile-speed", &no_use) >= 0) && (0 == dumpfile_mode_enabled)){
		sapp_log(30, ~0, ~0, "args --dumpfile-speed must used with --dumpfile,--dumpfile-file or --dumpfile-list!");
		exit(1);
	}

	return 0;
}


static void usage(void)
{
	int index = 0;

	printf("\033[32mUsage:\033[0m\n");
	printf("\033[32m%10s %-15s\t%-15s\033[0m\n", "short-arg", "long-arg", "description");
	while(cmd_args_usage[index].long_opt_name != NULL){
		printf("%10s --%-15s\t%s\n", cmd_args_usage[index].short_opt_name, cmd_args_usage[index].long_opt_name, cmd_args_usage[index].usage);
		index++;
	}
	exit(1);
}

/*
	For get command-line arguments(CLA).
	
	Note:
		The string value 'opt_string_value' is read-only, 
		caller must not modify or free it after call sapp_get_cla_raw().
		
	return value:
		-1: not found opt_long_name;
		 0: opt_long_name is set but no argument value. 
		 1: opt_long_name is set and has valid argument store in *opt_string_value. 
*/
int sapp_get_cla_raw(const char *opt_long_name, char ** const opt_string_value)
{
	int i, ret = -1;
	const sapp_cmd_args_val_t **local_tmp_array;
	int local_tmp_cla_num;

	if(NULL == opt_long_name || NULL == opt_string_value){
		return -1;
	}

	local_tmp_array = (const sapp_cmd_args_val_t **)sapp_global_val->cla.cmd_args_array;
	local_tmp_cla_num = sapp_global_val->cla.cmd_args_num;
	
	for(i = 0; i < local_tmp_cla_num; i++){
		/* 选项名称要用不同的长度比较两次, 防止dumpfile 与 dumpfile-speed使用较短长度比较, 而误命中的情况 */
		if((strncasecmp(opt_long_name, local_tmp_array[i]->long_opt_name, strlen(opt_long_name)) == 0)
		 && (strncasecmp(opt_long_name, local_tmp_array[i]->long_opt_name, strlen(local_tmp_array[i]->long_opt_name)) == 0)){
			if(local_tmp_array[i]->arg_val.string_value != NULL){
				*opt_string_value = local_tmp_array[i]->arg_val.string_value;
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

int sapp_get_cla_long(const char *opt_long_name, long long *opt_long_value)
{
	int ret = -1;
	char *opt_string_value;

	if(NULL == opt_long_name || NULL == opt_long_value){
		return -1;
	}

	ret = sapp_get_cla_raw(opt_long_name, &opt_string_value);
	if(ret <= 0){
		return ret;
	}

	*opt_long_value = (long long)strtoull(opt_string_value, NULL, 10);

	return ret;
}


static int store_cmd_args(const char *opt_name, const char *opt_arg)
{
	sapp_cmd_args_val_t *new_opt;
	char *void_val;

	if(sapp_get_cla_raw(opt_name, &void_val) != -1){
		printf("Error! Duplicate option: %s\n", opt_name);
		return -1;
	}

	new_opt = (sapp_cmd_args_val_t *)calloc(1, sizeof(sapp_cmd_args_val_t));
	new_opt->long_opt_name = strdup(opt_name);
	if(opt_arg){
		new_opt->arg_val.string_value = strdup(opt_arg);
	}
	
	if(NULL == sapp_global_val->cla.cmd_args_array){
		sapp_global_val->cla.cmd_args_array = (sapp_cmd_args_val_t **)calloc(1, sizeof(void *));
	}else{
		sapp_global_val->cla.cmd_args_array = (sapp_cmd_args_val_t **)realloc(sapp_global_val->cla.cmd_args_array, sizeof(void *) * (sapp_global_val->cla.cmd_args_num + 1));
	}

	sapp_global_val->cla.cmd_args_array[sapp_global_val->cla.cmd_args_num] = new_opt;

	sapp_global_val->cla.cmd_args_num++;

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
#ifdef GIT_VERSION
				printf("Version: %s\n", sapp_git_ver);
#endif	

				exit(1);
			break;

			case 'c':
				sapp_generate_sample_config();
				exit(1);
			break;

			case 'd':
				store_cmd_args("dumpfile", NULL);
				continue;
			break;

			case 'g':
				sapp_init_breakpad_mini();
				sapp_segv_generate();
				continue;
			break;

			case 'r':
				store_cmd_args("dumpfile", NULL);
				store_cmd_args("dumpfile-file", optarg);
				continue;
			break;

			case 'p':
				store_cmd_args("dumpfile-speed", optarg);
				continue;
			break;

			case 'f':
				store_cmd_args("dumpfile", NULL);
				store_cmd_args("dumpfile-list", optarg);
				get_dumpfile_list_array(optarg);
				continue;
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


