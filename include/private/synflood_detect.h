#ifdef __cplusplus
extern "C"
{
#endif
#include<time.h>

#ifndef ATTACKING
#define ATTACKING 1
#endif

#ifndef NORMAL
#define NORMAL 0
#endif

int synflood_detect_init(int thread_num, int syn_threshold, int tcp_threshold, int data_threshold);

int synflood_detector(int thread_num);

int dataflood_detector(int thread_num);

int synflood_detect_destroy();
#ifdef __cplusplus
}
#endif





