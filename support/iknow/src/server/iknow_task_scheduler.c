#include "iknow.h"
#include "iknow_internal.h"
#include "dynamic_array.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <assert.h>
#include <arpa/inet.h>
#ifdef __cplusplus
extern "C"
{
#endif

int ik_run_cmd(iknow_work_thread_t *pme);
void ik_terminate_connection(iknow_work_thread_t *pme);
static void *ik_worker(void *arg);

static iknow_work_thread_t *ik_create_new_work_thread(inner_iknow_t *ihandle)
{
	//int i;
	iknow_work_thread_t *new_idle_worker = NULL;

	if(ihandle->work_thread_num >= ihandle->max_users){
		IPRINT("Error, too many users:%d\n", ihandle->work_thread_num);
		return NULL;
	}

	new_idle_worker = &(ihandle->work_thread_array[ihandle->work_thread_num]);
	memset(new_idle_worker, 0, sizeof(iknow_work_thread_t));
	new_idle_worker->phandle = ihandle;
	new_idle_worker->thread_state = IKNOW_THREAD_STATE_INIT;
	ihandle->work_thread_num++;
	
	pthread_create(&new_idle_worker->pid, NULL, ik_worker, (void *)new_idle_worker);
	sched_yield();
	
	/* 刚创建了新线程, 但不一定马上就被系统调度, 需要等待一会, 直至新线程被CPU真正运行 */
	while(1){
		usleep(10);
		pthread_mutex_lock(&new_idle_worker->mutex);
		if(IKNOW_THREAD_STATE_IDLE == new_idle_worker->thread_state){
			pthread_mutex_unlock(&new_idle_worker->mutex);
			break;
		}
		pthread_mutex_unlock(&new_idle_worker->mutex);
	}
	
	return new_idle_worker;
}

static iknow_work_thread_t *ik_search_idle_work_thread(inner_iknow_t *ihandle)
{
	int i;
	iknow_work_thread_t *new_idle_worker = NULL;

	for(i = 0; i < ihandle->max_users; i++){
		pthread_mutex_lock(&ihandle->work_thread_array[i].mutex);
		if(IKNOW_THREAD_STATE_IDLE == ihandle->work_thread_array[i].thread_state){
			new_idle_worker = &ihandle->work_thread_array[i];
			ihandle->work_thread_array[i].thread_state = IKNOW_THREAD_STATE_REDY;
			pthread_mutex_unlock(&ihandle->work_thread_array[i].mutex);
			break;
		}
		pthread_mutex_unlock(&ihandle->work_thread_array[i].mutex);
	}

	/* 没有空闲工作线程 */
	if(NULL == new_idle_worker){
		new_idle_worker = ik_create_new_work_thread(ihandle);
	}

	return new_idle_worker;
}

static void ik_client_info_free(iknow_client_state_t *client_state)
{
	if(client_state->module_array){
		free(client_state->module_array);
	}

	free(client_state);
}
#if 0
static void ik_client_state_init(iknow_client_state_t *client_state, int new_sd)
{
	memset(client_state, 0, sizeof(iknow_client_state_t));
	client_state->connfd = new_sd;
	client_state->global_flush_flag = 0;
	client_state->log_level = 0x7FFFFFFF; /* 如果默认等级太低, 可能刚登录就会被DEBUG信息冲刷 */
	client_state->module_array_num = 0;
}
#endif
/* 将线程状态置为REDY, 其他工作均由"iknow_worker()"完成 */
static int ik_push_cmd_task(inner_iknow_t *ihandle, iknow_work_thread_t *new_idle_worker, 
							   iknow_client_state_t *client_info)
{
	pthread_mutex_lock(&new_idle_worker->mutex);
	new_idle_worker->client_info = client_info;
	new_idle_worker->thread_state = IKNOW_THREAD_STATE_REDY;
	pthread_mutex_unlock(&new_idle_worker->mutex);

	return 0;
}

/* 在新线程中执行client端命令, 有些命令可能长时间不退出 */
static int ik_call_worker(inner_iknow_t *ihandle, iknow_client_state_t *client_info)
{
	//int ret;
	iknow_work_thread_t *new_idle_worker = NULL;
	
	new_idle_worker = ik_search_idle_work_thread(ihandle);
	if(NULL == new_idle_worker){
		iprintf(ihandle, client_info,  "Too many users, no enough resource, connection close!\r\n");
		return -1;
	}
	
	ik_push_cmd_task(ihandle, new_idle_worker, client_info);

	return 0;
}

static int ik_accept_new_client(inner_iknow_t *ihandle)
{
	struct sockaddr_in cliaddr;
	socklen_t cliaddr_len = sizeof(cliaddr);
	int new_fd, ret;
	char ip_str[16];
	iknow_client_state_t *client_info;

	new_fd = accept(ihandle->listen_fd, (struct sockaddr *) &cliaddr, &cliaddr_len);
	if(new_fd < 0){
		return -1;
	}

#if 0
	/* 使用非阻塞模式, 防止各种网络情况造成"iknow_print"函数阻塞, 影响系统运行 */
	fd_flags = fcntl(new_fd, F_GETFL, 0);
	fcntl(new_fd, F_SETFL, fd_flags | O_NONBLOCK);
#endif
	client_info = (iknow_client_state_t *)malloc(sizeof(iknow_client_state_t));
	memset(client_info, 0, sizeof(iknow_client_state_t));

	client_info->connfd = new_fd;
	client_info->global_flush_flag = 0;
	client_info->log_level = 0x7FFFFFFF; /* 最大等级 */
	client_info->module_array_num = 0;

	inet_ntop(AF_INET, &cliaddr.sin_addr.s_addr, ip_str, 16);
	IPRINT("recv a new fd:%d from %s:%u\n", new_fd, ip_str, ntohs(cliaddr.sin_port));

	ret = ik_call_worker(ihandle, client_info);
	if(ret < 0){
		goto err;
	}

	return 0;
err:
	ik_client_info_free(client_info);
	return -1;
}

static void *ik_task_wait_thread(void *arg)
{
	inner_iknow_t *ihandle = (inner_iknow_t *)arg;

	listen(ihandle->listen_fd, ihandle->work_thread_num);

	while(1){
		ik_accept_new_client(ihandle);
	}

	return NULL;
}

static int ik_get_worker_state(iknow_work_thread_t *pme)
{
	int thread_state;
	
	pthread_mutex_lock(&pme->mutex);
	thread_state = pme->thread_state;
	pthread_mutex_unlock(&pme->mutex);

	return thread_state;
}

int ik_set_worker_state(iknow_work_thread_t *pme, state_t thread_state)
{
	pthread_mutex_lock(&pme->mutex);
	pme->thread_state = thread_state;
	pthread_mutex_unlock(&pme->mutex);

	return thread_state;
}

static void ik_welcome(iknow_handle ihandle, iknow_client_state_t *client_state)
{
	iprintf(ihandle, client_state, "\n################################################################\n");
	iprintf(ihandle, client_state, "#  Welcome to IKnow! \n#\tVersion:%s\n", Iknow_Version);
	iprintf(ihandle, client_state, "#  Ctrl Key Note:\n");
	iprintf(ihandle, client_state, "#\t':' - isolate multiple command.\n");		
	iprintf(ihandle, client_state, "#\t'$' - close connection after executed command.\n" );			
	iprintf(ihandle, client_state, "#\t'?' - get help message.\n");
	iprintf(ihandle, client_state, "################################################################\nI#");
}

static void ik_wait_new_task(iknow_work_thread_t *pme)
{
	while(1){
		if(IKNOW_THREAD_STATE_REDY == ik_get_worker_state(pme)){
			/* 收到新任务 */
			break;
		}
		
		usleep(10);
	}
	
	return;
}


static void ik_task_run(iknow_work_thread_t *pme)
{
	int ret, thread_state;

	ik_welcome(pme->phandle, pme->client_info);

	while(1){
		ret = ik_run_cmd(pme);
		if(ret < 0){
			ik_terminate_connection(pme);
		}
		thread_state = ik_get_worker_state(pme);
		if(IKNOW_THREAD_STATE_IDLE == thread_state){
			return;
		}
	}

	return;
}

static void *ik_worker(void *arg)
{
	iknow_work_thread_t *pme = (iknow_work_thread_t *)arg;

	while(1){
		switch(pme->thread_state){
			case IKNOW_THREAD_STATE_INIT:
				/* 先将状态由INIT改为IDLE, 即可接收任务态 */
				ik_set_worker_state(pme, IKNOW_THREAD_STATE_IDLE);
			break;

			case IKNOW_THREAD_STATE_IDLE:
				/* 等待主线程任务调度 */
				ik_wait_new_task(pme);
			break;

			case IKNOW_THREAD_STATE_REDY:
			case IKNOW_THREAD_STATE_BUSY:
				ik_set_worker_state(pme, IKNOW_THREAD_STATE_BUSY);
				/* 处理客户端命令请求 */
				ik_task_run(pme);
			break;
			
		}
		
	}

	return NULL;
}

void iknow_run(iknow_handle apihandle)
{
	pthread_t pid;

	pthread_create(&pid, NULL, ik_task_wait_thread, apihandle);
	sched_yield();

	return;
}	

#ifdef __cplusplus
}
#endif
