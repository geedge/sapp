#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>//using memset
#include <time.h>
#include <errno.h>
#include <stdio.h>
//#include <execinfo.h>//backtrace
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>
//#include <libunwind.h>

#include "dictator.h"
#include "dictator_core.h"
#ifdef	DICTATOR_DEBUG
extern struct dictator_space_t D_SPACE;
thread_mem_pool_t* DEBUGGER_MP=NULL;
extern char boundary_marker[D_MARKER_SIZE];

#define	D_CMD_HELP			0
#define	D_CMD_STAT			1
#define	D_CMD_LIST_MALLOC	2
#define	D_CMD_CHECK			3
#define	D_CMD_LIST_LARGE_M		4
const char* support_cmd_full[]={"help","stat memory","list malloc","check memory","list large","\0"};
const char support_cmd_short[]={'h','s','l','c','m','\0'};
const char* cmd_introduce[]={"Print this text",
							 "Statistic memory usage",
							 "List 'max_num' and 'minmum_bytes' malloc backtrace,list all as default",
							 "Check	'times' and 'interval us' to find if any memroy corrupt,check 1 time and 100*1000 us as default",
							 "List 'max_num' and 'minmum_bytes' of SINGLE malloc backtrace which size is larger than 'minmum_bytes',list 65535(64KB) as default",
							 "\0"};

backtrace_info_t* create_bt_info(void** bt_array,int size,thread_mem_pool_t *p_mempool)
{
	backtrace_info_t*caller_bt=NULL;
	unsigned int memsize=sizeof(backtrace_info_t)+sizeof(void**)*size;
	caller_bt=(backtrace_info_t*)block_alloc(memsize,(IMP_t*)p_mempool);
	atomic_set(&(caller_bt->ref_cnt),0);
	atomic_set(&(caller_bt->ref_bytes),0);
	atomic_set(&(caller_bt->maxsize),0);
	caller_bt->bt_array=(void**)((char*)caller_bt+sizeof(backtrace_info_t));
	memcpy(caller_bt->bt_array,bt_array,sizeof(void**)*size);
	caller_bt->array_size=size;
	caller_bt->p_mempool=(IMP_t*)p_mempool;
	return caller_bt;
}
void destroy_bt_info(void* bt_info)
{
	backtrace_info_t*caller_bt=(backtrace_info_t*)bt_info;
	block_free(caller_bt,caller_bt->p_mempool);
	return;
}
void init_debugger(thread_mem_debugger_t* debugger,thread_mem_pool_t* p_mp)
{
	unsigned int i=0;
	int ret=0;
	struct dbg_index_t* idx_pool_buff=NULL;

	D_kernel_list_init(&(debugger->malloced_in_reach_list));
	pthread_mutex_init(&(debugger->mutex_malloced_in_reach_list),NULL);
	pthread_mutex_init(&(debugger->mutex_pool_tail),NULL);
	atomic_set(&(debugger->app_mem),0);
	atomic_set(&(debugger->assigned_mem),0);
	atomic_set(&(debugger->inuse_num),0);
	atomic_set(&(debugger->malloc_cnt),0);
	atomic_set(&(debugger->free_cnt),0);
	atomic_set(&(debugger->selfcost_mem),sizeof(thread_mem_pool_t));
	debugger->cached_mem=DICTATOR_UNIT_SIZE*D_SPACE.INIT_THREAD_BLOCK_NUM;
	

	idx_pool_buff=(struct dbg_index_t*)mmap_alloc(D_SPACE.INIT_THREAD_BLOCK_NUM*sizeof(struct dbg_index_t));
	atomic_add(&(debugger->selfcost_mem),D_SPACE.INIT_THREAD_BLOCK_NUM*sizeof(struct dbg_index_t));

	debugger->raw_mem_header[0]=idx_pool_buff;
	debugger->rawmem_idx=1;
	D_kernel_list_init(&(debugger->index_pool));
	for(i=0;i<D_SPACE.INIT_THREAD_BLOCK_NUM;i++)
	{
		D_kernel_list_add_tail(&(debugger->index_pool), &(idx_pool_buff[i].malloced_in_reach_hook));
	}
	atomic_set(&(debugger->pool_unit_cnt),D_SPACE.INIT_THREAD_BLOCK_NUM);
	ret=D_INTERNAL_MESA_hash_create_v2(&(debugger->malloc_backtrace_hash), 
									1,//thread safe
									1024*32,
									0,//unlimited max element num
									NULL,
									NULL,
									destroy_bt_info,
									NULL,
									0,
									0,//never expire
									(IMP_t*)p_mp);
	assert(ret==0);
	ret=D_INTERNAL_MESA_hash_create_v2(&(debugger->free_backtrace_hash), 
									1,//thread safe
									1024*32,
									0,//unlimited max element num
									NULL,
									NULL,
									destroy_bt_info,
									NULL,
									0,
									0,//never expire
									(IMP_t*)p_mp);
	assert(ret==0);
	return;
}
void destroy_thread_mem_debugger(thread_mem_debugger_t* debugger)
{
	unsigned int i=0;
	D_INTERNAL_MESA_hash_destroy_v2(&(debugger->malloc_backtrace_hash),NULL);
	D_INTERNAL_MESA_hash_destroy_v2(&(debugger->free_backtrace_hash),NULL);
	for(i=0;i<debugger->rawmem_idx;i++)
	{
		mmap_free(debugger->raw_mem_header[i]);
		debugger->raw_mem_header[i]=NULL;
	}
	pthread_mutex_destroy(&(debugger->mutex_malloced_in_reach_list));
	pthread_mutex_destroy(&(debugger->mutex_pool_tail));
	return;
}
struct dbg_index_t* get_dbg_index(thread_mem_debugger_t* debugger)
{
	struct dbg_index_t* p;
	struct D_kernel_list_head* elem=NULL;
	struct dbg_index_t* idx_pool_buff=NULL;
	unsigned int i=0;
	if(atomic_read(&(debugger->pool_unit_cnt))<2)
	{
		idx_pool_buff=(struct dbg_index_t*)mmap_alloc(BATCH_DBG_IDX_NUM*sizeof(struct dbg_index_t));
		atomic_add(&(debugger->selfcost_mem),BATCH_DBG_IDX_NUM*sizeof(struct dbg_index_t));
		assert(debugger->rawmem_idx<MAX_THREAD_RAWMEM_CNT);
		debugger->raw_mem_header[debugger->rawmem_idx]=idx_pool_buff;
		debugger->rawmem_idx++;
		for(i=0;i<BATCH_DBG_IDX_NUM;i++)
		{
			D_kernel_list_add_head(&(debugger->index_pool), &(idx_pool_buff[i].malloced_in_reach_hook));
		}
		atomic_add(&(debugger->pool_unit_cnt),BATCH_DBG_IDX_NUM);		
	}
	elem=D_kernel_list_get_head(&(debugger->index_pool));
	p=container_of(elem,struct dbg_index_t,malloced_in_reach_hook);
	atomic_dec(&(debugger->pool_unit_cnt));
	p->used_size=0;
	p->p_backtrace=NULL;
	p->mem_info=0;
	return p;
}
void restore_dbg_index(thread_mem_debugger_t* debugger,struct dbg_index_t*idx)
{
	pthread_mutex_lock(&(debugger->mutex_pool_tail));
	D_kernel_list_add_tail(&(debugger->index_pool),&(idx->malloced_in_reach_hook));
	atomic_inc(&(debugger->pool_unit_cnt));
	pthread_mutex_unlock(&(debugger->mutex_pool_tail));
	return;
}
struct sort_data_t
{
	long val;
	void* data;
};
static int sort_data_pos=0;

void quick_sort(struct sort_data_t *a,int i,int j) 
{ 

	int m,n;
	struct sort_data_t temp; 
	int k; 
	m=i; 
	n=j; 
	k=a[(i+j)/2].val; /*选取的参照*/ 
	do { 
		while(a[m].val<k&&m<j) 
			m++; /* 从左到右找比k大的元素*/ 
		while(a[n].val>k&&n>i) 
			n--; /* 从右到左找比k小的元素*/ 
		if(m<=n)
		{ /*若找到且满足条件，则交换*/ 
			temp=a[m]; 
			a[m]=a[n]; 
			a[n]=temp; 
			m++; 
			n--; 
		} 

	}while(m<=n); 

	if(m<j) 
		quick_sort(a,m,j); /*运用递归*/ 
	if(n>i) 
		quick_sort(a,i,n); 

} 
void show_help(int sd)
{
	int i=0;
	char buff[4096]={0};
	unsigned int printed=0;
	printed+=snprintf(buff,sizeof(buff)-printed,"Command Usage:\n");
	while(strlen(support_cmd_full[i])>1&&printed<sizeof(buff))
	{
		printed+=snprintf(buff+printed,sizeof(buff)-printed,"\t%s(or '%c'):\t\t\t%s\n",support_cmd_full[i],
															support_cmd_short[i],
															cmd_introduce[i]);
		i++;
	}
	write(sd,buff,printed);
}
void stat_memory(int sd)
{
	int i=0;
	char buff[4096]={0};
	unsigned int printed=0;
	unsigned long long app_mem=0,assigned_mem=0,cached_mem=0;
	unsigned long long inuse_num=0,malloc_cnt=0,free_cnt=0;
	unsigned long long num_malloced_places=0,num_freed_places=0;
	unsigned long long selfcost_mem=0;
	for(i=0;i<=atomic_read(&(D_SPACE.used_mem_pool_counter));i++)
	{
		if(D_SPACE.thread_mem_info[i]==NULL)
		{
			continue;
		}
		app_mem+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.app_mem));
		cached_mem+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.cached_mem));
		assigned_mem+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.assigned_mem));
		num_malloced_places+=D_SPACE.thread_mem_info[i]->debugger.malloc_backtrace_hash.elem_count;
		num_freed_places+=D_SPACE.thread_mem_info[i]->debugger.free_backtrace_hash.elem_count;
		inuse_num+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.inuse_num));
		malloc_cnt+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.malloc_cnt));
		free_cnt+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.free_cnt));
		selfcost_mem+=atomic_read(&(D_SPACE.thread_mem_info[i]->debugger.selfcost_mem));
	}
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"pool num:%d inuse %llu block\n",i,inuse_num);
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"malloced %llu times in %llu context(s)\n",malloc_cnt,num_malloced_places);
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"freed %llu times in %llu context(s)\n",free_cnt,num_freed_places);
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"app used:%llu bytes/%lluMB\n",app_mem,app_mem/(1024*1024));
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"assigned:%llu bytes/%lluMB\n",assigned_mem,assigned_mem/(1024*1024));
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"cached  :%llu bytes/%lluMB\n",cached_mem,cached_mem/(1024*1024));
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"selfcost:%llu bytes/%lluMB\n",selfcost_mem,selfcost_mem/(1024*1024));
	write(sd,buff,printed);
}

/*
int unw_backtrace(void **bt_array,int number)
{
	unw_cursor_t cursor; 
	unw_context_t uc;
	unw_word_t ip;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	int ret_cnt=0;
	while (unw_step(&cursor) > 0) {
		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if(ret_cnt<number)
		{
			bt_array[ret_cnt]=(void*)ip;
			ret_cnt++;
		}
		else
		{
			break;
		}
	}
	if(ret_cnt>0)//make exception for unw_backtrace
	{ 
		return ret_cnt-1;
	}
	else
	{
		return 0;
	}
}
*/
#define STACKCALL __attribute__((regparm(1),noinline))
void ** STACKCALL getEBP(void){
		void **ebp=NULL;
		__asm__ __volatile__("mov %%rbp, %0;\n\t"
					:"=m"(ebp)      /* 输出 */
					:      /* 输入 */
					:"memory");     /* 不受影响的寄存器 */
		return (void **)(*ebp);
}
int mesa_backtrace(void **buffer,int size){
	
	int frame=0;
	void ** ebp;
	void **ret=NULL;
	unsigned long long func_frame_distance=0;
	if(buffer!=NULL && size >0)
	{
		ebp=getEBP();
		func_frame_distance=(unsigned long long)(*ebp) - (unsigned long long)ebp;
		while(ebp&& frame<size
			&&(func_frame_distance< (1ULL<<24))//assume function ebp more than 16M
			&&(func_frame_distance>0))
		{
			ret=ebp+1;
			buffer[frame++]=*ret;
			ebp=(void**)(*ebp);
			func_frame_distance=(unsigned long long)(*ebp) - (unsigned long long)ebp;
		}
	}
	return frame;
}


backtrace_info_t* backtrace_ref_inc(MESA_hash_tab_v2_t* hash,size_t inc_size,thread_mem_pool_t *p_mempool)
{
	void *bt_array[MAX_BACKTRACE_DEPTH];
	void** except_self_bt_array;
	size_t bt_depth,except_self_bt_depths;
	bt_depth = mesa_backtrace(bt_array, MAX_BACKTRACE_DEPTH);
//	bt_depth = backtrace(bt_array, MAX_BACKTRACE_DEPTH);
//	bt_depth = unw_backtrace(bt_array, MAX_BACKTRACE_DEPTH);
	backtrace_info_t *caller_bt;
	if(bt_depth<=MALLOC_SELF_DEPTH)
	{
		bt_depth=MALLOC_SELF_DEPTH+1;
		memset(bt_array,0,sizeof(bt_array));
	}
	except_self_bt_array=bt_array+MALLOC_SELF_DEPTH;
	except_self_bt_depths=bt_depth-MALLOC_SELF_DEPTH;
	caller_bt=(backtrace_info_t *)D_INTERNAL_MESA_hash_sel_v2(hash,
															(uchar*)(except_self_bt_array),
															sizeof(void*)*(except_self_bt_depths));
	if(caller_bt==NULL)
	{
		caller_bt=create_bt_info(except_self_bt_array, except_self_bt_depths,p_mempool);
		D_INTERNAL_MESA_hash_add_v2(hash,
									(uchar*)except_self_bt_array,
									sizeof(void*)*except_self_bt_depths,
									caller_bt);
	}
	atomic_inc(&(caller_bt->ref_cnt));
	atomic_add(&(caller_bt->ref_bytes),inc_size);
	if(atomic_read(&(caller_bt->maxsize))<(signed long)inc_size)
	{
		atomic_set(&(caller_bt->maxsize),(signed long)inc_size);
	}
	return caller_bt;
}
void merge_mp_hash(uchar * key, uint size, void * data, void * u)
{
	MESA_hash_tab_v2_t* target_hash=(MESA_hash_tab_v2_t*)u;
	backtrace_info_t* tmp_bt_info=(backtrace_info_t*)data;
	if(0==atomic_read(&(tmp_bt_info->ref_bytes)))
	{
		return;
	}
	backtrace_info_t* target_bt_info=(backtrace_info_t *)D_INTERNAL_MESA_hash_sel_v2(target_hash,
															(uchar*)key,
															size);
	if(target_bt_info==NULL)
	{
		target_bt_info=create_bt_info(tmp_bt_info->bt_array, tmp_bt_info->array_size,DEBUGGER_MP);

		D_INTERNAL_MESA_hash_add_v2(target_hash,
									key,
									size,
									target_bt_info);
	}
	atomic_add(&(target_bt_info->ref_bytes),atomic_read(&(tmp_bt_info->ref_bytes)));
	atomic_add(&(target_bt_info->ref_cnt),atomic_read(&(tmp_bt_info->ref_cnt)));
	if(atomic_read(&(target_bt_info->maxsize))<atomic_read(&(tmp_bt_info->maxsize)))
	{
		atomic_set(&(target_bt_info->maxsize),atomic_read(&(tmp_bt_info->maxsize)));
	}
	return;
}
void dump2array_by_refbytes(uchar * key, uint size, void * data, void * u)
{

	backtrace_info_t* bt_info=(backtrace_info_t*)data;
	struct sort_data_t* sort_array=(struct sort_data_t*)u;
	sort_array[sort_data_pos].val=atomic_read(&(bt_info->ref_bytes));
	sort_array[sort_data_pos].data=data;
	sort_data_pos++;
	return;
}
void dump2array_by_maxsize(uchar * key, uint size, void * data, void * u)
{

	backtrace_info_t* bt_info=(backtrace_info_t*)data;
	struct sort_data_t* sort_array=(struct sort_data_t*)u;
	sort_array[sort_data_pos].val=atomic_read(&(bt_info->maxsize));
	sort_array[sort_data_pos].data=data;
	sort_data_pos++;
	return;
}
int exec_shell(const char*cmd ,char* buff,int buff_size)
{
	FILE* fp = popen(cmd, "r");
	if(fp==NULL)
	{
		return -1;
	}
	memset(buff,0,buff_size);
	fgets(buff,buff_size,fp);
	pclose(fp);
	return strlen(buff);
}
int get_backtrace_string(void* bt,char* buff,int buff_size)
{
	char cmd[128] = {0};
	char property[256]={0};
	char not_care1[128]={0},not_care2[128]={0},not_care3[128]={0};
	char library_path[256]={0};
	char exe_path[256]={0},function_name[256]={0};
	char maps_line[1024]={0};
	void* offset_start,*offset_end;
	int maps_column_num=0;
	FILE* fd_maps=NULL;
	fd_maps=fopen("/proc/self/maps","r");
	unsigned long exe_symbol_offset=0;
	const char* unknow_position="??:0\n";
	if(fd_maps==NULL)
	{
		return -1;
	}
	while(NULL!=fgets(maps_line,sizeof(maps_line),fd_maps))
	{
		maps_column_num=sscanf(maps_line,"%p-%p\t%s\t%s\t%s\t%s\t%s"
														,&offset_start
														,&offset_end
														,property
														,not_care1
														,not_care2
														,not_care3
														,library_path);
		if(maps_column_num==7&&bt>=offset_start&&bt<=offset_end)
		{
			break;
		}
		
	}
	fclose(fd_maps);
	memset(exe_path,0,sizeof(exe_path));
	readlink("/proc/self/exe", exe_path, sizeof(exe_path));
	if(exe_path[strlen(exe_path)-1]=='\n')
	{
		exe_path[strlen(exe_path)-1]='\0';
	}
	if(0==strcmp(exe_path,library_path))
	{
		exe_symbol_offset=(unsigned long)bt;
	}
	else
	{
		exe_symbol_offset=(char*)bt-(char*)offset_start;
	}
	snprintf(cmd,sizeof(cmd),"addr2line -C -e %s 0x%lx",library_path,exe_symbol_offset);
	exec_shell(cmd, buff, buff_size);
	if(0==strcmp(buff,unknow_position))
	{
		snprintf(cmd,sizeof(cmd),"addr2line -Cif -e %s 0x%lx",library_path,exe_symbol_offset);
		exec_shell(cmd, function_name, sizeof(function_name));
		function_name[strlen(function_name)-1]='\0';
		snprintf(buff,buff_size,"%s(%s+0x%lx)\n",library_path,function_name,exe_symbol_offset);
	}
	return 0;
}

int merge_malloc_bt(MESA_hash_tab_v2_t *merged_hash)
{
	int ret=0,i=0;
	MESA_hash_tab_v2_t* mp_malloc_hash;
	int to_sort_size=0;
	ret=D_INTERNAL_MESA_hash_create_v2(merged_hash, 
									1,//thread safe
									1024*32,
									0,//unlimited max element num
									NULL,
									NULL,
									destroy_bt_info,
									NULL,
									0,
									0,//never expire
									(IMP_t*)DEBUGGER_MP);
	assert(ret==0);
	for(i=0;i<=atomic_read(&(D_SPACE.used_mem_pool_counter));i++)
	{
		if(D_SPACE.thread_mem_info[i]==NULL)
		{
			continue;
		}
		mp_malloc_hash=&(D_SPACE.thread_mem_info[i]->debugger.malloc_backtrace_hash);
		D_INTERNAL_MESA_hash_iterate_v2_2(mp_malloc_hash, merge_mp_hash,merged_hash);
	}
	 
	to_sort_size=merged_hash->elem_count;
	return to_sort_size;
}


void list_malloc_bt(int sd,const char*args,int CMD)
{
	int i=0,printed=0,list_cnt=0;
	unsigned int j=0;
	backtrace_info_t* bt_info=NULL;
	long ref_bytes=0,ref_cnt=0;
	struct sort_data_t* sort_array=NULL;
	int to_sort_size=0;
	char buff[4096]={0},bt_string[1024]={0};
	pid_t pid=getpid();
	int max_list_num=-1,min_list_size=-1;
	MESA_hash_tab_v2_t merged_hash;
	sscanf(args,"%d %d",&max_list_num,&min_list_size);
	if(CMD!=D_CMD_LIST_LARGE_M&&CMD!=D_CMD_LIST_MALLOC)
	{
		assert(0);
	}
	to_sort_size=merge_malloc_bt(&merged_hash);
	sort_array=(struct sort_data_t*)mmap_alloc(to_sort_size*sizeof(struct sort_data_t));

	if(CMD==D_CMD_LIST_LARGE_M)
	{
		D_INTERNAL_MESA_hash_iterate_v2_2(&merged_hash, dump2array_by_maxsize,sort_array);

	}
	else if(CMD==D_CMD_LIST_MALLOC)
	{
		D_INTERNAL_MESA_hash_iterate_v2_2(&merged_hash, dump2array_by_refbytes,sort_array);
	}
	sort_data_pos=0;
	quick_sort(sort_array, 0,to_sort_size-1);
	for(i=to_sort_size-1;i>=0;i--)
	{
		printed=0;
		memset(buff,0,sizeof(buff));
		bt_info=(backtrace_info_t*)(sort_array[i].data);
		if(list_cnt>=max_list_num&&max_list_num>0)
		{
			break;
		}
		if(CMD==D_CMD_LIST_LARGE_M)
		{
			if(atomic_read(&(bt_info->maxsize))<min_list_size&&min_list_size>0)
			{
				break;
			}
		}
		else if(CMD==D_CMD_LIST_MALLOC)
		{
			if(atomic_read(&(bt_info->ref_bytes))<min_list_size&&min_list_size>0)
			{
				break;
			}
		}

		ref_bytes=atomic_read(&(bt_info->ref_bytes));
		ref_cnt=atomic_read(&(bt_info->ref_cnt));
		printed+=snprintf(buff+printed,sizeof(buff)-printed,
			"=%u=\t malloc %ld bytes(%ldMB) and %ld times in contexts (MAX %ld bytes,AVG %ld bytes)\n",
			pid,
			ref_bytes,
			ref_bytes/(1024*1024),
			ref_cnt,
			atomic_read(&(bt_info->maxsize)),
			ref_bytes/ref_cnt);
		for(j=0;j<bt_info->array_size;j++)
		{
			memset(bt_string,0,sizeof(bt_string));
			get_backtrace_string(bt_info->bt_array[j],bt_string,sizeof(bt_string));
			printed+=snprintf(buff+printed,sizeof(buff)-printed,"=%u=\tby %s",pid,bt_string);
		}
		printed+=snprintf(buff+printed,sizeof(buff)-printed,"\n");
		write(sd,buff,printed);
		list_cnt++;
	}
	D_INTERNAL_MESA_hash_destroy_v2(&merged_hash,NULL);
	mmap_free(sort_array);
}
int d_chk_one_mem(struct dbg_index_t* idx,char* err_string,int size)
{
	int printed=0,invalid_write_size=0,i=0;
	unsigned int assigned_size=0;
	const char* user_boundary=NULL;
	mem_info_t* block=(mem_info_t*)(idx->mem_info);
	int boundary_len=0,is_corrupt=0;
	if(block->magic!=DICTATOR_MAGIC)
	{
		printed+=snprintf(err_string+printed,size-printed,"Magic Error|");
		is_corrupt=1;
	}
	assigned_size=block->blk_num*DICTATOR_UNIT_SIZE;
	if(assigned_size<idx->used_size+USED_MEM_HEAD_LEN)
	{
		printed+=snprintf(err_string+printed,size-printed,"Corrupt mem head usd(%lu)>assigned(%u)|"
														,idx->used_size+USED_MEM_HEAD_LEN
														,assigned_size);
		is_corrupt=1;
	}
	user_boundary=(char*)block+USED_MEM_HEAD_LEN+idx->used_size;
	boundary_len=MIN(assigned_size-idx->used_size-USED_MEM_HEAD_LEN,D_MARKER_SIZE);
	if(0!=memcmp(user_boundary,boundary_marker,boundary_len))
	{
		for(i=0;i<boundary_len;i++)
		{
			if(user_boundary[i]!='d')
			{
				invalid_write_size++;
			}
		}
		printed+=snprintf(err_string+printed,size-printed,"Invaid write %d bytes after %p|",invalid_write_size,user_boundary);
		if(invalid_write_size==boundary_len)
		{
			printed+=snprintf(err_string+printed,size-printed,"May stack overflow|");

		}
		is_corrupt=1;
	}
	return is_corrupt;
}
void D_check_mem(int sd,int is_scheduled)
{
	int i=0;
	unsigned int j=0;
	int is_corrupt=0,printed=0;
	unsigned long  chked_blk_sum=0,chked_bytes_sum=0,corrupt_sum=0;
	struct D_kernel_list_head* to_check_list=NULL,*to_check_elem=NULL;
	struct dbg_index_t* to_chk_idx=NULL;
	mem_info_t* block=NULL;
	char err_string[256]={0},bt_string[1024]={0};;
	char buff[4096]={0};
	pid_t pid=getpid();
	for(i=0;i<=atomic_read(&(D_SPACE.used_mem_pool_counter));i++)
	{
		if(D_SPACE.thread_mem_info[i]==NULL)
		{
			continue;
		}
		pthread_mutex_lock(&(D_SPACE.thread_mem_info[i]->debugger.mutex_malloced_in_reach_list));
		to_check_list=&(D_SPACE.thread_mem_info[i]->debugger.malloced_in_reach_list);
		to_check_elem=to_check_list->next;
		while(to_check_elem!=to_check_list)
		{
			printed=0;
			to_chk_idx=container_of(to_check_elem,struct dbg_index_t, malloced_in_reach_hook);
			chked_blk_sum++;
			chked_bytes_sum+=to_chk_idx->used_size;
			is_corrupt=d_chk_one_mem(to_chk_idx, err_string,sizeof(err_string));
			if(is_corrupt==1)
			{
				block=(mem_info_t*)to_chk_idx->mem_info;
				corrupt_sum++;
				printed=snprintf(buff+printed,sizeof(buff)-printed,"Mem %p size %d(%s) D_id %u %s in context\n",
															(char*)block+USED_MEM_HEAD_LEN,
															to_chk_idx->used_size,
															block->blk_num?"block":"chunk",
															block->D_id,
															err_string);
	
				for(j=0;j<to_chk_idx->p_backtrace->array_size;j++)
				{
					memset(bt_string,0,sizeof(bt_string));
					get_backtrace_string(to_chk_idx->p_backtrace->bt_array[j],bt_string,sizeof(bt_string));
					printed+=snprintf(buff+printed,sizeof(buff)-printed,"=%u=\tby %s",pid,bt_string);
				}
				
				write(sd,buff,printed);
			}
			to_check_elem=to_check_elem->next;
		}
		pthread_mutex_unlock(&(D_SPACE.thread_mem_info[i]->debugger.mutex_malloced_in_reach_list));

	}
	printed=0;
	printed+=snprintf(buff+printed,sizeof(buff)-printed,"Corrutp Sumary:\n\tChecked %d threads.\n\tChecked %lu block,%lu bytes(%luMB).\n\t%lu block(s) Corrupt.\n",
													i,
													chked_blk_sum,
													chked_bytes_sum,
													chked_bytes_sum/(1024*1024),
													corrupt_sum);
	if(!is_scheduled)
	{
		write(sd,buff,printed);
	}
	return;
	
}
int dictator_parse_cmd(const char* cmd,const char**args)
{
	int i=0,ret=0;
	while(strlen(support_cmd_full[i])>1)
	{
		ret=strncasecmp(cmd,support_cmd_full[i],strlen(support_cmd_full[i]));
		if(ret==0)
		{
			*args=cmd+strlen(support_cmd_full[i])+1;
			break;
		}
		else if((cmd[0]==support_cmd_short[i])&&(cmd[1]=='\n'||cmd[1]==' '))
		{
			*args=cmd+2;
			break;
		}
		i++;
	}
	return i;
}
void * dictator_debug_thread(void* param)
{
	pid_t app_pid=0;
	char listen_path[64];
	char cmd_buff[1024],debug_cmd[1024];
	app_pid=getpid();
	char banner[1024]={0};
	const char* unknown_cmd="UNKNOWN CMD.\n";
	const char* shell="dictator2>";
	const char* schedule_checking="Schedule Checking";
	snprintf(listen_path,sizeof(listen_path),"/tmp/dictator_%u",app_pid);
	snprintf(banner,sizeof(banner),"WELCOME TO DICTATOR2(%s) DEBUG CONSOLE.\n",
																			DICTATOR2_VERSION);
	DEBUGGER_MP=create_mem_pool(-1);
	struct sockaddr_un address;
	int sock, conn,cmd_id=0;
	int check_times=-1,check_interval_us=1000*100;
	int i=0,ret=-1;
	size_t addrLength;
	const char *args=NULL;

	if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr,"DICTATOR2 INIT FAILED!\n");
	}
	
	unlink(listen_path);

	address.sun_family = AF_UNIX;
	strcpy(address.sun_path,listen_path);

	addrLength = sizeof(address.sun_family) + strlen(address.sun_path);

	if (bind(sock, (struct sockaddr *) &address, addrLength))
	{
		fprintf(stderr,"DICTATOR2 bind %s FAILED!\n",listen_path);
	}
	if (listen(sock, 1))
	{
		fprintf(stderr,"DICTATOR2 listen %s FAILED!\n",listen_path);
	}
	fprintf(stderr,"Using DICTATOR2 memory debugger (%s)\n",listen_path);
	while ((conn = accept(sock, (struct sockaddr *) &address,(socklen_t*)&addrLength)) >= 0) 
	{
		write(conn,banner,strlen(banner));
		memset(debug_cmd,0,sizeof(debug_cmd));
		write(conn,shell,strlen(shell));
		while(read(conn,cmd_buff,sizeof(cmd_buff))>0)
		{
			if(cmd_buff[0]!='\n')
			{
				memcpy(debug_cmd,cmd_buff,sizeof(debug_cmd));
				cmd_id=dictator_parse_cmd(debug_cmd,&args);
			}
			check_times=-1;
			check_interval_us=1000*100;
			switch(cmd_id)
			{
				case D_CMD_HELP:
					show_help(conn);
					break;
				case D_CMD_STAT:
					stat_memory(conn);
					break;
				case D_CMD_LIST_MALLOC:
				case D_CMD_LIST_LARGE_M:
					list_malloc_bt(conn,args,cmd_id);
					break;
				case D_CMD_CHECK:
					sscanf(args,"%d %d",&check_times,&check_interval_us);
					if(check_times>0)
					{
						write(conn,schedule_checking,strlen(schedule_checking));
						for(i=0;i<check_times;i++)
						{
							D_check_mem(conn,1);
							ret=write(conn,".",1);
							if(ret<=0)
							{
								break;
							}
							usleep(check_interval_us);
						}
						write(conn,"\n",1);
					}
					else
					{
						D_check_mem(conn,0);
					}
					break;
				default:
					write(conn,unknown_cmd,strlen(unknown_cmd));
				break;
			}
			memset(cmd_buff,0,sizeof(cmd_buff));
			write(conn,shell,strlen(shell));
		}
		close(conn);
	}
	return NULL;
}
#endif	//end of DICTATOR_DEBUG

