#ifndef _CAPTURE_H_
#define _CAPTURE_H_

#ifdef __cplusplus
extern "C" {
#endif

void nids_run_pcap(void);
void nids_run(void);
int nids_init(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif
