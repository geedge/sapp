#include "sapp_declaration.h"
#include "sapp_mem.h"


#ifdef __cplusplus
extern "C" {
#endif

static MESA_htable_handle g_plug_necessary_htable;


struct plug_uniq_t{
	const char *plug_path;
	int is_necessary;
	int plug_id;
	int priority;	
};

static MESA_htable_handle g_plug_uniq_htable;


struct plug_manage_key_t{
	const char *plug_name;
	const char *plug_entry_type;
};

typedef struct{
	time_t init_time;
	int init_state;
	long long time_spent_in_us;
	const char *plug_path;
	const char *plug_name;
}plugin_load_state_t;


static plugin_load_state_t g_plugin_load_state[SAPP_MAX_PLUG_ENTRY_NUM];
static int plugin_load_state_num = 0;


static MESA_htable_handle g_plug_manage_htable;

int g_max_priority=0;
plug_global_entry_t g_plug_global_entry[SAPP_MAX_PLUG_ENTRY_NUM];
int g_plug_global_entry_index;


int max_plug_priority_get()
{
	return g_max_priority;
}

int plug_priority_get(int entry_id)
{
	return g_plug_global_entry[entry_id].priority;
}

int plug_mange_get_entry_id(const char *plug_name, const char *plug_entry_name)
{
	int this_entry_id;
	
	if(g_plug_global_entry_index >= SAPP_MAX_PLUG_ENTRY_NUM){
		sapp_runtime_log(RLOG_LV_FATAL, "plug entry number overflow! no valid id for %s->%s\n", plug_name, plug_entry_name);
		return -1;
	}

	struct plug_uniq_t *plug_info = (struct plug_uniq_t *)MESA_htable_search(g_plug_uniq_htable, (unsigned char *)plug_name, strlen(plug_name));
	if(plug_info == NULL){
		sapp_runtime_log(RLOG_LV_FATAL, "plugin %s not found in g_plug_uniq_htable", plug_name);
		return -1;
	}
	if(plug_info->priority > g_max_priority)
	{
		g_max_priority=plug_info->priority;
	}
	this_entry_id = g_plug_global_entry_index;
	g_plug_global_entry[this_entry_id].entry_id = this_entry_id;
	g_plug_global_entry[this_entry_id].priority = plug_info->priority;
	size_t plug_name_length = strlen(plug_name);
	g_plug_global_entry[this_entry_id].plug_name =  (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, plug_name_length+1);
	strncpy((char *)g_plug_global_entry[this_entry_id].plug_name, plug_name, plug_name_length);
	
	size_t plug_entry_name_length = strlen(plug_entry_name);
	g_plug_global_entry[this_entry_id].plug_entry_name =  (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, plug_entry_name_length+1);
	strncpy((char *)g_plug_global_entry[this_entry_id].plug_entry_name, plug_entry_name, plug_entry_name_length);
	g_plug_global_entry_index++;
	
	return this_entry_id;
}

static void plug_necessary_htable_free_cb(void *data)
{
	if(data)sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, data);
	;
}

static MESA_htable_handle create_plug_necessary_htable(void)
{
	MESA_htable_handle htable;
	int opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	


	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)plug_necessary_htable_free_cb, sizeof(void *));	
	
	MESA_htable_mature(htable);
	
	return htable;
}

static void plug_uniq_htable_free_cb(void *data)
{
	struct plug_uniq_t *plug_info = (struct plug_uniq_t *)data;

	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)plug_info->plug_path);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)plug_info);
}


static MESA_htable_handle create_plug_uniq_htable(void)
{
	MESA_htable_handle htable;
	int opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	


	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE,  (void *)plug_uniq_htable_free_cb, sizeof(void *));	
	
	MESA_htable_mature(htable);
	
	return htable;
}


static unsigned int plug_manage_key_to_index_cb(const MESA_htable_handle table, const uchar * key, unsigned int size)
{
	const struct plug_manage_key_t *mg_key = (struct plug_manage_key_t *)key;	
	unsigned int hash_index;

	hash_index = BKDR_hash_algo(table, (unsigned char*)mg_key->plug_name, strlen(mg_key->plug_name));
	hash_index += BKDR_hash_algo(table, (unsigned char*)mg_key->plug_entry_type, strlen(mg_key->plug_entry_type));

	return hash_index;
}

static int plug_manage_key_cmp_cb(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	if(size1 != size2){
		return -1;
	}

	const struct plug_manage_key_t *mg_key1 = (struct plug_manage_key_t *)key1;	
	const struct plug_manage_key_t *mg_key2 = (struct plug_manage_key_t *)key2;	

	if(strcasecmp(mg_key1->plug_name, mg_key2->plug_name) != 0){
		return -1;
	}

	if(strcasecmp(mg_key1->plug_entry_type, mg_key2->plug_entry_type) != 0){
		return -1;
	}

	return 0;
}


static uchar * plug_manage_key_dup_cb(const uchar *key, uint key_size)
{
	struct plug_manage_key_t *new_mg_key; 
	const struct plug_manage_key_t *raw_mg_key = (struct plug_manage_key_t *)key;

	new_mg_key = (struct plug_manage_key_t *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(struct plug_manage_key_t));

	size_t name_length = strlen(raw_mg_key->plug_name);
	new_mg_key->plug_name = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, name_length+1);
	strncpy((char *)new_mg_key->plug_name, raw_mg_key->plug_name, name_length);


	size_t type_length = strlen(raw_mg_key->plug_entry_type);
	new_mg_key->plug_entry_type = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, type_length+1);
	strncpy((char *)new_mg_key->plug_entry_type, raw_mg_key->plug_entry_type, type_length);

	return (uchar *)new_mg_key;
}


static void plug_manage_key_free_cb(uchar *key, uint key_size)
{
	struct plug_manage_key_t *raw_mg_key = (struct plug_manage_key_t *)key;

	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key->plug_name);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key->plug_entry_type);
	sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, MEM_STAT_GLOBAL_THREAD_ID, (void *)raw_mg_key);
}


static MESA_htable_handle create_plug_manage_htable(void)
{
	MESA_htable_handle htable;
	int opt_int;
	
	htable = MESA_htable_born();
	assert(htable != NULL);

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1024 * 128;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_SCREEN_PRINT_CTRL, &opt_int, sizeof(int));

	opt_int = HASH_ELIMINATE_ALGO_FIFO;
	MESA_htable_set_opt(htable, MHO_ELIMIMINATE_TYPE, &opt_int, sizeof(int));	

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX,  (void *)&plug_manage_key_to_index_cb, sizeof(void *));
	
	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&plug_manage_key_cmp_cb, sizeof(void *));		

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP,  (void *)&plug_manage_key_dup_cb, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE, (void *)&plug_manage_key_free_cb, sizeof(void *));

	
	MESA_htable_mature(htable);
	
	return htable;
}


int plugin_is_necessary(const char *plug_path, int *priority)
{
	int *p = (int *)MESA_htable_search(g_plug_necessary_htable, (unsigned char *)plug_path, strlen(plug_path));
	if(p != NULL){
		if(priority != NULL){
			*priority = *p;
		}
		return 1;
	}

	return 0;
}

int plugin_load_new_plug(const char *plug_name, const char *plug_path)
{
	struct plug_uniq_t *plug_info;
	int priority=0;

	plug_info = (struct plug_uniq_t *)MESA_htable_search(g_plug_uniq_htable, (unsigned char *)plug_name, strlen(plug_name));
	if(plug_info != NULL){
		sapp_log(30, 1, 1, "plugin %s->[PLUGNAME]=%s has duplicate name with %s->[PLUGNAME]=%s!", plug_path, plug_name, plug_info->plug_path, plug_name);
		return -1;
	}
	size_t path_length = strlen(plug_path);
	plug_info = (struct plug_uniq_t *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, sizeof(struct plug_uniq_t));
	plug_info->plug_path = (char *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, path_length+1);
	strncpy((char *)plug_info->plug_path, plug_path, path_length);
	plug_info->is_necessary = plugin_is_necessary(plug_path, &priority);
	plug_info->priority = priority;
	MESA_htable_add(g_plug_uniq_htable, (unsigned char *)plug_name, strlen(plug_name), plug_info);

	return 0;
}


int plugin_load_new_plug_entry(const char *plug_name, const char *plug_entry_type, void *entry_addr)
{
	struct plug_manage_key_t mg_key = {};
	int ret;

	mg_key.plug_name = plug_name;
	mg_key.plug_entry_type = plug_entry_type;
	
	ret = MESA_htable_add(g_plug_manage_htable, (const uchar * )&mg_key, sizeof(struct plug_manage_key_t), entry_addr);

	assert(ret >= 0);

	return 0;
}

void *plugin_get_plug_entry(const char *plug_name, const char *plug_entry_type)
{
	struct plug_manage_key_t mg_key = {};
	void *plug_entry_addr;

	mg_key.plug_name = plug_name;
	mg_key.plug_entry_type = plug_entry_type;
	
	plug_entry_addr = MESA_htable_search(g_plug_manage_htable, (const uchar * )&mg_key, sizeof(struct plug_manage_key_t));

	return plug_entry_addr;
}


static int plugin_parse_necessary_conf(void)
{
	FILE *fp;
	char line_buf[1024]="";
	char plugin_path[1024]="";
	int priority=0;

	fp = fopen(ABBR_NECESSARY_PLUG_CONF_FILE, "r");
	if(NULL == fp){
		return 0;
	}

	while(fgets(line_buf, 1024, fp)){
		if('#' == line_buf[0] || ' ' == line_buf[0] || '\r' == line_buf[0] || '\n' == line_buf[0]){
			continue;
		}	
		del_last_rn(line_buf, 1024);
		sscanf(line_buf, "%1023s\t%d", plugin_path, &priority);
		int *p = (int *)sapp_mem_calloc(SAPP_MEM_FIX_PLUG_CTRL, -1, sizeof(int));
		*p = priority;
		MESA_htable_add(g_plug_necessary_htable, (unsigned char *)plugin_path, strlen(plugin_path), (void *)p);
	}

	fclose(fp);
	return 0;
}



void plugin_load_state_update(int init_state, long long time_spent_in_us, const char *plug_path, const char *plug_name)
{
	int i, index, bingo;

	if(plugin_load_state_num >= SAPP_MAX_PLUG_ENTRY_NUM){
		MESA_handle_runtime_log(g_plugin_runtime_handle,RLOG_LV_FATAL, PLUGIN_LOGNAME,"plugin_load_state_update() error, plug number overload, max support:%d", SAPP_MAX_PLUG_ENTRY_NUM);	
		return;
	}

	bingo = 0;
	index = -1;
	for(i = 0; i < SAPP_MAX_PLUG_ENTRY_NUM; i++){
		if((g_plugin_load_state[i].plug_path != NULL) && 
		  (strncmp(g_plugin_load_state[i].plug_path, plug_path, strlen(plug_path)) == 0)){
			index = i;
			bingo = 1;
			break;
		}
	}

	if(0 == bingo){
		index = plugin_load_state_num;
		plugin_load_state_num++;
	}

	g_plugin_load_state[index].init_time = time(NULL);

	if(init_state < 0){
		g_plugin_load_state[index].init_state = 0;
		g_plugin_load_state[index].time_spent_in_us = 0;
	}else{
		g_plugin_load_state[index].init_state = 1;
		g_plugin_load_state[index].time_spent_in_us = time_spent_in_us;
	}
	if(0 == bingo){
		g_plugin_load_state[index].plug_path = sapp_strdup(plug_path);
		if(plug_name){
			g_plugin_load_state[index].plug_name = sapp_strdup(plug_name);
		}
	}
}

static int qsort_compare_time_spent_cb(const void *item1, const void *item2)
{
	const plugin_load_state_t **load_state1 = (const plugin_load_state_t **)item1;
	const plugin_load_state_t **load_state2 = (const plugin_load_state_t **)item2;
	
	return (int)((*load_state1)->time_spent_in_us - (*load_state2)->time_spent_in_us);
}



static void sapp_plug_modify_char(char *str, int raw_char, int new_char)
{
	char *ptr;

	while((ptr = strchr(str, raw_char))){
		*ptr = (char)new_char;
	}
}

const long long USEC_PER_SEC = 1000000LL;
const long long USEC_PER_MSEC = 1000LL;
const int SEC_PER_MIN = 60;
const int MIN_PER_HOUR = 60;
const int HOUR_PER_DAY = 24;

static char* beautify_time(long long us) {
    static char result[100];
    long long days, hours, mins, secs, msecs, usecs;

    days = us / (USEC_PER_SEC * SEC_PER_MIN * MIN_PER_HOUR * HOUR_PER_DAY);
    us %= USEC_PER_SEC * SEC_PER_MIN * MIN_PER_HOUR * HOUR_PER_DAY;

    hours = us / (USEC_PER_SEC * SEC_PER_MIN * MIN_PER_HOUR);
    us %= USEC_PER_SEC * SEC_PER_MIN * MIN_PER_HOUR;

    mins = us / (USEC_PER_SEC * SEC_PER_MIN);
    us %= USEC_PER_SEC * SEC_PER_MIN;

    secs = us / USEC_PER_SEC;
    us %= USEC_PER_SEC;

    msecs = us / USEC_PER_MSEC;
    us %= USEC_PER_MSEC;

    usecs = us;

    if (days > 0) {
        sprintf(result, "%lld days, %lld hours, %lld mins, %lld.%03lld secs", days, hours, mins, secs, msecs);
    } else if (hours > 0) {
        sprintf(result, "%lld hours, %lld mins, %lld.%03lld secs", hours, mins, secs, msecs);
    } else if (mins > 0) {
        sprintf(result, "%lld mins, %lld.%03lld secs", mins, secs, msecs);
    } else if (secs > 0) {
        sprintf(result, "%lld.%03lld secs", secs, msecs);
    } else if (msecs > 0) {
        sprintf(result, "%lld.%03lld msecs", msecs, usecs);
    } else {
        sprintf(result, "%lld usecs", usecs);
    }

    return result;
}



void sapp_plugin_load_state_output(void)
{
	int i;
	plugin_load_state_t *ptr_plugin_load_state[128] = {};
	char time_str[64];
	FILE *fp;

	fp = fopen(ABBR_LOAD_PLUG_STAT_LOG_DATA_FILE, "w+");
	if(NULL == fp){
		return;
	}

	for(i = 0; i < plugin_load_state_num; i++){
		ptr_plugin_load_state[i] = &g_plugin_load_state[i];
	}

	qsort(ptr_plugin_load_state, plugin_load_state_num, sizeof(void *), qsort_compare_time_spent_cb);

	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");
	fprintf(fp, "sapp load plugins statistics:\n");
	fprintf(fp, "%20s %5s %24s %6s\n", "start_time", "state", "time_spent_us", "plugin_path");

	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");
	for(i = 0; i < plugin_load_state_num; i++){
		timet_to_str(ptr_plugin_load_state[i]->init_time, time_str, sizeof(time_str));
		fprintf(fp, "%20s %5s %24s %6s\n", time_str, 
				(ptr_plugin_load_state[i]->init_state < 0) ? "\033[1;31;40mFAIL\033[0m":"\033[32mSUCC\033[0m", 
				beautify_time(ptr_plugin_load_state[i]->time_spent_in_us), 
				ptr_plugin_load_state[i]->plug_path);	
	}	
	fprintf(fp, "-----------------------------------------------------------------------------------------------\n");
	fclose(fp);
}


int plugin_manage_init(void)
{
	g_plug_global_entry_index = 0;
	plugin_load_state_num = 0;
	
	g_plug_necessary_htable = create_plug_necessary_htable();
	assert(g_plug_necessary_htable != NULL);
	
	g_plug_uniq_htable = create_plug_uniq_htable();
	assert(g_plug_uniq_htable != NULL);

	g_plug_manage_htable = create_plug_manage_htable();
	assert(g_plug_manage_htable != NULL);
	
	plugin_parse_necessary_conf();

	g_plug_global_entry[0].entry_id = 0;
	g_plug_global_entry[0].plug_name = sapp_strdup("inner_plug");
	g_plug_global_entry[0].plug_entry_name = sapp_strdup("inner_entry");
	g_plug_global_entry_index++;
	return 0;
}

void plugin_manage_destroy(void)
{
	int i;
	
	MESA_htable_destroy(g_plug_necessary_htable, NULL);
	g_plug_necessary_htable = NULL;
	
	MESA_htable_destroy(g_plug_uniq_htable, NULL);
	g_plug_uniq_htable = NULL;
	
	MESA_htable_destroy(g_plug_manage_htable, NULL);
	g_plug_manage_htable = NULL;

	for(i = 0; i < g_plug_global_entry_index; i++){
		sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)g_plug_global_entry[i].plug_name);
		sapp_mem_free(SAPP_MEM_FIX_PLUG_CTRL, -1, (void *)g_plug_global_entry[i].plug_entry_name);
	}
	memset(g_plug_global_entry, 0, sizeof(g_plug_global_entry));
	g_plug_global_entry_index = 0;

	for(i = 0; i < plugin_load_state_num; i++){
		SAPP_GLOBAL_FREE(g_plugin_load_state[i].plug_path);
		SAPP_GLOBAL_FREE(g_plugin_load_state[i].plug_name);
	}
	memset(g_plugin_load_state, 0, sizeof(g_plugin_load_state));
	plugin_load_state_num = 0;
}

#ifdef __cplusplus
}
#endif


