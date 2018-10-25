#ifndef _AGENT_SMITH_H_
#define _AGENT_SMITH_H_

#ifdef __cplusplus
extern "C"
{
#endif
int agent_smith_init(int thread_num, void (*callback_func)(const unsigned char *data, int datalen, int thread_seq));

void agent_smith_run();

void agent_smith_destroy();
#ifdef __cplusplus
}
#endif
#endif


