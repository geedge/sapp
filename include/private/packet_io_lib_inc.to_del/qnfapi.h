/*
 * Copyright (c) 2010-2015 Qice Technology Ltd, Beijing, China.
 * All rights reserved.
 *
 * This source code is proprietary to Qice Technology Limited and no part
 * of it may be redistributed, published or disclosed except as outlined in
 * the written contract supplied with this product.
 *
 *******************************************************************************
 *	qnfapi.c: this file defines the api functions
 *******************************************************************************
 *  note:	
 *		num_stream : number of streams
 *		stream_index : the index of stream
 *******************************************************************************/

#ifndef __QNFAPI_H__
#define __QNFAPI_H__

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* C Standard Library headers. */
#include <ctype.h>
#include <errno.h>
#include <regex.h>

/* POSIX headers. */
#include <fcntl.h>
#include <netinet/in.h>    /* for ntohs() */
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <inttypes.h>

#include "qnftypes.h"
#include "qnfreg.h"


// defines for flash update
#define     BANK_SIZE_W 		 (512 * 1024) // 512K words
#define     BLOCK_SIZE_W 	        (64 * 1024)
#define     BLOCK_SIZE_B 		 (128 * 1024)


// most commonly used apis
/*****************************************************************************/
__inline__ unsigned int reg_read(int qnffd, unsigned int offset );
__inline__ unsigned int reg_write(int qnffd, unsigned int offset, unsigned int value );

int qnf_open(char * qnfname);
int qnf_close(int qnffd);
int qnf_configure(int qnffd, int num_stream, int cap_len);
int qnf_attach_stream(int qnffd, int stream_index, uint32_t flags, uint32_t extra_window_size);
int qnf_detach_stream(int qnffd, int stream_index);
int qnf_start_stream(int qnffd, int stream_index);
int qnf_stop_stream(int qnffd, int stream_index);
int qnf_set_stream_poll(int qnffd, int stream_index, uint32_t mindata, struct timeval * maxwait, struct timeval * poll);
uint8_t * qnf_advance_stream(int qnffd, int stream_index, uint8_t ** bottom);
int capture_start(int qnffd, int cap_len, int start);
// tcam related
int qnf_cam_init(int qnffd);
int qnf_tag_map_int(int qnffd);
int qnf_rule_set(int qnffd, unsigned int entry, qnf_rule_t *rule, qnf_action_t *action);
int qnf_rule_set_ipv6(int qnffd, unsigned int entry, qnf_rule_t *rule, qnf_action_t *action);
int qnf_rule_clear(int qnffd);
// statistics
uint32_t qnf_get_drop_cnt(int qnffd, int stream_num);

int qnf_set_hashmode(int qnffd, int mode);
int qnf_get_hashmode(int qnffd, int *mode);

// i2c api
/*****************************************************************************/
void qnf_i2c_init(int qnffd,uint8_t port);
uint8_t qnf_i2c_random_read8(int qnffd, uint8_t port, uint8_t slave_addr, uint8_t mem_addr);
void qnf_i2c_sequential_read(int qnffd,uint8_t port, uint8_t slave_addr, uint8_t base_addr, uint8_t *pdata, uint8_t count);
uint16_t qnf_i2c_random_read16(int qnffd,uint8_t port, uint8_t slave_addr, uint8_t mem_addr);
void qnf_i2c_random_write16(int qnffd, uint8_t port, uint8_t slave_addr, uint8_t mem_addr, uint16_t data);

void vcs_mdio_random_write(int qnffd,uint8_t devad, uint16_t addr, uint16_t data);
uint16_t vcs_mdio_random_read(int qnffd,uint8_t devad, uint16_t addr);
int qnf_10ge_wanmode_set(int qnffd,int wan_mode);

int qnf_mac_cfgreg_read(int qnffd, int addr);
int qnf_mac_cfgreg_write(int qnffd, int addr, int data);
uint64_t qnf_mac_statsreg_read(int qnffd, int addr);


// flash update apis
/*****************************************************************************/
void set_logic_num(int qnffd,uint64_t sn_logic);
void set_hardware_num(int qnffd,uint64_t no);
uint64_t read_logic_num(int qnffd);
uint64_t read_hardware_num(int qnffd);
uint16_t bit_swap(uint16_t value);
void flash_write(int qnffd, uint32_t addr, uint16_t data);
uint16_t flash_read(int qnffd, uint32_t addr);
void reconfig(int qnffd);
void set_config_register(int qnffd, uint16_t data);
void clear_stats_regs(int qnffd);
void block_unlock(int qnffd, uint8_t bank, uint8_t block); 
void bank_unlock(int qnffd, uint8_t bank);
void block_erase(int qnffd,uint8_t bank, uint8_t block);
void bank_erase(int qnffd, uint8_t bank);
void word_program(int qnffd,uint32_t addr,uint16_t data);
void buffer_program(int qnffd,uint32_t start_addr,int n,uint16_t* pdata);
void block_program(int qnffd, uint8_t bank, uint8_t block, uint32_t w_size, uint16_t* pdata);
void bank_program(int qnffd, uint8_t bank, uint32_t w_size, uint16_t* pdata);
void blank_check_command(int qnffd,uint32_t blockToCheck);
void locking_operation_command(int qnffd,uint32_t addr,lock_stat_t lock_operation);
void protection_register_program_command(int qnffd,uint32_t addr,uint16_t data);
void buffer_enhanced_factory_program_command(int qnffd,uint32_t start_addr , uint32_t count,uint16_t data_flow[]);
int  compare_file_order(char * path1,char *path2);




#endif /* __QNFAPI_H__ */


