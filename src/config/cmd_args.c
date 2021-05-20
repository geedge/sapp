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
	/* 按字母顺序排列输出: */
	{"-c", "config-root-dir", 	"required", NULL,	"specifies the root directory of the config files, will append the subdirectory sapp\n  \t\t\t\t\t\tfor example: ./sapp -c /home/config, sapp actually uses the dir: /home/config/sapp/"},
	{"-d", "dumpfile", 	"no", NULL,	"running as pcap offline mode, default pcap file is './dumpfile'"},
	{"-D", "data-root-dir",		"required",NULL,	"specifies the root directory of the local data and state files, will append the subdirectory sapp\n\t\t\t\t\t\tfor example: ./sapp -D /home/data, sapp actually uses the dir: /home/data/sapp/"},	
	{"-e", "example-config", "required",NULL, "generate example main config file sapp.toml"},
	{"-f", "dumpfile-list", "required",NULL, "read many pcap files at one time without exiting, get the list of pcap files by command, \n\t\t\t\t\t\tfor example: ./sapp -f 'ls files/*.pcap', ./sapp -f 'find /home/files -name *.pcap'"},
	{"-g", "coredump", 	"no",NULL,	"generate coredump for test"},
	{"-h", "help",		"no",NULL,	"show help message"},
	{"-p",  "dumpfile-speed",	"required",dumpfile_speed_check, "\n  \t\ttop-speed\tprocess packets as fast as possible, this is default behavior\n\t\ttimestamp\tprocess packets as pcap embedded timestamp interval"},
	{"-r", "dumpfile-file", "required",NULL,	"read packets from which pcap file"},
	{"-t", "test-config", "optional",NULL,	"check validity of the configuration file, support level t1,t2,t3"},
	{"-v", "version", 	"no",NULL,	"show platform version"},
	{NULL,	NULL, 		NULL}
};

/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const char *sapp_cla_short_options = "dhgvc:D:e:r:p:f:t::";

/* 静态只读全局变量可以放在任何代码段, 无需在sapp_global_val里 */
static const struct option sapp_cla_long_options[] = 
{
	{"help",			no_argument,      	NULL,      'h'},
	{"version",			no_argument,      	NULL,      'v'},
	{"config-root-dir", required_argument,	NULL,	   'c'},
	{"data-root-dir", 	required_argument,	NULL,	   'D'},
	{"dumpfile",		no_argument,      	NULL,      'd'},
	{"dumpfile-file",	required_argument,  NULL,      'r'},
	{"dumpfile-list",	required_argument,  NULL,      'f'},
	{"dumpfile-speed",	required_argument,  NULL,      'p'},
	{"example-config", 	required_argument,  NULL,      'e'},
	{"coredump", 		no_argument,      	NULL,      'g'},
	{"test-config",		optional_argument,  NULL,      't'},
	{NULL,          	0,      			NULL,      0}
};


static int get_opt_index(int short_opt)
{
	int i;
	int index = -1;

	for(i = 0; sapp_cla_long_options[i].name != NULL; i++){
		if(sapp_cla_long_options[i].val == short_opt){
			index = i;
			break;
		}
	}

	return index;
}


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
	printf("\033[32m%10s %-15s \t%-8s \t%-15s\033[0m\n", "short-arg", "long-arg", "argument", "description");
	while(cmd_args_usage[index].long_opt_name != NULL){
		printf("%10s --%-15s \t%-8s \t%s\n", cmd_args_usage[index].short_opt_name, cmd_args_usage[index].long_opt_name, cmd_args_usage[index].need_args, cmd_args_usage[index].usage);
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



/*
	根据-c参数指定的根目录, 将配置文件的相对路径转为绝对路径, 
	如果没有-c参数, 默认路径是./etc/
*/
void sapp_update_config_root_dir(const char *cfg_root_dir)
{
	char sapp_secondary_dir[PATH_MAX];
	char sapp_cfg_filename[PATH_MAX];
	sapp_config_file_link_t *pconfig;

	pconfig = &sapp_global_val->config.cfg_file_path;
	
	if(NULL == cfg_root_dir){ //no cmd args, use default ./etc/
		snprintf(sapp_secondary_dir, PATH_MAX, "%s", "./etc");
		pconfig->cfg_files_root_dir = sapp_strdup("./etc");
	}else{
		pconfig->cfg_files_root_dir = sapp_strdup(cfg_root_dir);
		snprintf(sapp_secondary_dir, PATH_MAX, "%s/%s", cfg_root_dir, SAPP_CFG_SECONDARY_DIR);
	}

	pconfig->cfg_main_entry_relative = sapp_strdup("sapp.toml");
	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, "sapp.toml");
	pconfig->cfg_main_entry_absolute = sapp_strdup(sapp_cfg_filename);

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_sapp_log_relative);
	pconfig->cfg_sapp_log_absolute = sapp_strdup(sapp_cfg_filename);

	 /* 为了向前兼容, 没有-c参数时, 插件配置文件默认是./plug/conflist.inf */
	if(NULL == cfg_root_dir){ 
		pconfig->cfg_plug_list_absolute = sapp_strdup("./plug/conflist.inf");	
	}else{
		snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_plug_list_relative);
		pconfig->cfg_plug_list_absolute = sapp_strdup(sapp_cfg_filename);
	}
	
	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_project_list_relative);
	pconfig->cfg_project_list_absolute = sapp_strdup(sapp_cfg_filename);

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_entry_list_relative);
	pconfig->cfg_entry_list_absolute = sapp_strdup(sapp_cfg_filename);	

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_send_raw_pkt_relative);
	pconfig->cfg_file_send_raw_pkt_absolute = sapp_strdup(sapp_cfg_filename);	
	
	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_vxlan_sport_map_relative);
	pconfig->cfg_file_vxlan_sport_map_absolute = sapp_strdup(sapp_cfg_filename);	

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_inline_dev_relative);
	pconfig->cfg_file_inline_dev_absolute = sapp_strdup(sapp_cfg_filename);		

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_necessary_plug_relative);
	pconfig->cfg_file_necessary_plug_absolute = sapp_strdup(sapp_cfg_filename);		
	

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_stream_compare_layer_relative);
	pconfig->cfg_file_stream_compare_layer_absolute = sapp_strdup(sapp_cfg_filename);	

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_vlan_flipping_relative);
	pconfig->cfg_file_vlan_flipping_absolute = sapp_strdup(sapp_cfg_filename);		

	snprintf(sapp_cfg_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pconfig->cfg_file_asymmetric_addr_layer_relative);
	pconfig->cfg_file_asymmetric_addr_layer_absolute = sapp_strdup(sapp_cfg_filename);		
}

void sapp_update_data_root_dir(const char *data_root_dir)
{
	char sapp_secondary_dir[PATH_MAX];
	char sapp_data_filename[PATH_MAX];
	sapp_data_file_link_t *pdata;

	pdata = &sapp_global_val->config.data_file_path;
	
	if(NULL == data_root_dir){ //no cmd args, use default ./
		snprintf(sapp_secondary_dir, PATH_MAX, "%s", "./");
		pdata->data_files_root_dir = sapp_strdup("./");
	}else{
		pdata->data_files_root_dir = sapp_strdup(data_root_dir);
		snprintf(sapp_secondary_dir, PATH_MAX, "%s/%s", data_root_dir, SAPP_DATA_SECONDARY_DIR);
		MESA_mkdir_p(sapp_secondary_dir, 0755);
	}
	
	snprintf(sapp_data_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pdata->data_sapp_sysinfo_log_relative);
	pdata->data_sapp_sysinfo_log_absolute = sapp_strdup(sapp_data_filename);

	snprintf(sapp_data_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pdata->data_sapp_fs2_log_relative);
	pdata->data_sapp_fs2_log_absolute = sapp_strdup(sapp_data_filename);	

	snprintf(sapp_data_filename, PATH_MAX, "%s/%s", sapp_secondary_dir, pdata->data_inline_keepalive_log_relative);
	pdata->data_inline_keepalive_log_absolute = sapp_strdup(sapp_data_filename);		
}


int sapp_parse_cmd_args(int argc, char *argv[])
{
	int ret = 0;
	int c;
	int opt_index;
	int cfg_root_dir_changed = 0;
	int data_root_dir_changed = 0;
	int option_array_index;

	int test_config_flag = 0;
	char *test_config_option_value = NULL;

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
				cfg_root_dir_changed = 1;
				sapp_update_config_root_dir(optarg);
			break;

			case 'D':
				data_root_dir_changed = 1;
				sapp_update_data_root_dir(optarg);
			break;

			case 'e':
				sapp_generate_example_config(optarg);
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

			case 't':
				test_config_flag = 1;
				if(optarg != NULL){
					if((strcmp(optarg, "1") != 0)
					&& (strcmp(optarg, "2") != 0)
					&& (strcmp(optarg, "3") != 0)){
						printf("option -t --test-config only support level [t1,t2,t3]\n");
						exit(1);
					}
					test_config_option_value = sapp_strdup(optarg);
				}else{
					test_config_option_value = sapp_strdup("1"); //default is t1
				}
				continue;

			case '?': /* invalid or unknown option */
				ret = -1;
				return ret;
			break;
		}

		option_array_index = get_opt_index(c);

		if(sapp_cla_long_options[option_array_index].has_arg != no_argument){
			ret = check_args_legality(sapp_cla_long_options[option_array_index].name, optarg);
			if(ret < 0){
				printf("Invalid args for '%s':%s\n", sapp_cla_long_options[option_array_index].name, optarg);
				return -1;
			}
		}

		if(store_cmd_args(sapp_cla_long_options[option_array_index].name, optarg) < 0){
			return -1;
		}
	}

	if(check_args_sanity() < 0){
		return -1;
	}

	/* 没有指定-c路径, 使用默认./rtc */
	if(0 == cfg_root_dir_changed){
		sapp_update_config_root_dir(NULL);
	}

	/* 没有指定-D路径, 使用默认./rtc */
	if(0 == data_root_dir_changed){
		sapp_update_data_root_dir(NULL);
	}

	if(test_config_flag != 0){
		ret = sapp_config_check(atoi(test_config_option_value));
		exit(ret);
	}

	return ret;
}


#ifdef __cplusplus
}
#endif


