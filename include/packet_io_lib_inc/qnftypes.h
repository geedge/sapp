/*
 * Copyright (c) 2010-2015 Qice Technology Ltd, Beijing, China.
 * All rights reserved.
 *
 * This source code is proprietary to Qice Technology Limited and no part
 * of it may be redistributed, published or disclosed except as outlined in
 * the written contract supplied with this product.
 *
 *******************************************************************************
 * File Name   	: 	qnftype.h
 * Description	:	header file for qnfxxx card structure types
 *******************************************************************************/

#ifndef __QNFTYPE_H__
#define __QNFTYPE_H__

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>


#define QNF_STREAM_MAX 8
#define QNF_CAM_RULES_MAX	32
#define QNF_REG_MAX_ENTRIES 32


// same as the one defined in qnf_drv.h
typedef enum qnfminor
{
	QNFMINORBITS  = 3,
	QNFMINORMASK  = (1<<QNFMINORBITS)-1,
	QNFMINOR_QNF  = 0,
	QNFMINOR_MEM  = 1,
	QNFMINOR_IOM  = 2,
	QNFMINOR_MAX  = 3
} qnfminor_t;

// structure used for driver interface
// same as the one defined in qnf_drv.h
typedef struct qnfinf 
{
	uint32_t		id;									// QNF device number
	uint32_t		phy_addr;							// PCI address of large buffer
	uint32_t		buf_size;								// its size
	uint32_t		iom_size;								// iom size
	uint16_t		device_code;							// PCI device ID
#if defined(_WIN32)
	uint32_t		bus_num;							// PCI bus number
	uint16_t		dev_num;							// PCI device number
	uint16_t		fun_num;							// Function number within a PCI device
	uint32_t		ui_num;								// User-perceived slot number
#endif
}  qnfinf_t;

#ifndef WITHOUT_TS
// structure used for driver interface
// same as the one defined in qnf_drv.h
typedef struct tsinf
{
  uint64_t    Last_Ticks;
  uint64_t    Last_TSC;
  time_t      Stat_Start, Stat_End;
  uint32_t    Crystal_Freq;
  uint32_t    Synth_Freq;
  uint32_t    Resyncs;
  uint32_t    Bad_Pulses;
  uint32_t    Worst_Freq_Err, Worst_Phase_Err;
  uint32_t    Health_Thresh;
  uint32_t    Pulses, Single_Pulses_Missing, Longest_Pulse_Missing;
  uint32_t    Health, Sickness;
  int32_t     Freq_Err, Phase_Err;
  uint32_t    Set_Ts_Field;
} tsinf_t;
#endif

typedef struct qnf_reg
{
#if defined(__ppc__) || defined(__POWERPC__) /* Big-endian layout. */
	uint32_t  addr    : 16;
	uint32_t  module  : 8;
	uint32_t  version : 4;
	uint32_t  flags   : 4;
#else  /* Little-endian layout. */
	uint32_t  addr    : 16;
	uint32_t  module  : 8;
	uint32_t  flags   : 4;
	uint32_t  version : 4;
	
#endif /* Endianness. */
} qnf_reg_t;

typedef struct qnfpbm_global 
{
	volatile uint32_t * status;					// Control / Status
	volatile uint32_t * burst_threshold;                    // Burst threshold
	volatile uint32_t * burst_timeout;	                     // Burst timeout
	uint8_t  version;							// Burst manager version
} qnfpbm_global_t;


typedef struct qnfpbm_stream 
{
	volatile uint32_t *status;					// Control / Status
	volatile uint32_t dma_buf_start;		              // Mem hole base address
	volatile uint32_t dma_buf_end;			       // Mem hole size
	volatile uint32_t record_ptr;				       // Record pointer
	volatile uint32_t limit_ptr;				       // Limit pointer
	volatile uint32_t *safetynet_cnt;		              // At limit event pointer
	volatile uint32_t drop_cnt;					// Drop counter
	volatile uint32_t dma_ctl_reg;
} qnfpbm_stream_t;


typedef struct stream
{
	uint8_t            *buf;            // large buffer                    
	uint32_t           size;            // Size of the stream's memory hole
	uint32_t           offset;          // Offset to current record       
	uint32_t           processed;       // Amount of data processed so far
	qnfpbm_stream_t   *pbm;             // Pointer to stream burst manager
	uint32_t           phyaddr;         // Pointer to physical base address
	uint32_t           mindata;
	struct timeval 		 maxwait;
	struct timespec    poll;
	uint32_t           extra_window_size; // size of the second mmap         
	int64_t            free_space;        // free/used space                 
	uint32_t           last_top;          // last read value of record ptr   
	uint32_t           last_bottom;       // last written value of limit ptr 
	uint32_t           is_first_time:1;   // is the stream's first call?     
	uint32_t           attached:1;        // is the stream attached?         
	uint32_t           started:1;         // is the stream started?          
} stream_t;

	
typedef struct sheep 
{
#if defined(_WIN32)
	HANDLE      handle;
#endif
	char				qnfname[32];   		// QNF card device name
	int					qnfiom;         		// IOM file descriptor, cannot be 0
	stream_t		stream[QNF_STREAM_MAX]; 	// Stream properties
	uint8_t*		iom;           				// IO memory pointer
	qnfinf_t		qnfinf;
	uint32_t		brokencuraddr;  					
	uint32_t		byteswap;       			// endianness
	qnf_reg_t		regs[QNF_REG_MAX_ENTRIES];// register enum cache
	qnfpbm_global_t *pbm;           			// Pointer to global burst manager
	uint8_t		num_rx_streams; 		        // Number of receive streams
	uint8_t		num_tx_streams; 		        // Number of transmit streams
	uint32_t		has_arm:1;     			// indicates arm is present
	uint32_t		has_tx:1;
	uint32_t		implicit_detach:1;
	uint32_t		opened:1;
	uint32_t		cap_length;
	uint32_t		msu_config:1;
	uint32_t		num_stream;
} sheep_t;


typedef volatile union {
	struct {
		uint8_t		  stream_num		:3;  //0-2
		uint8_t		  in_port			:1;//3 	
		uint8_t       out_port          :1;//4
		uint8_t       reseved1          :1;//5
		uint8_t       drop_flag         :1;//6
		uint32_t      hash              :23;//29-7
		uint8_t       strategy_type     :2; //31-30
		}data;
	uint32_t value;
}hash_fwd_arg_t;


typedef struct erf_record {
	uint32_t          ts[2];
	uint16_t          rlen;
	uint16_t          wlen;
	hash_fwd_arg_t    hash_fwd_arg;
} erf_record_t;


typedef struct qnf_rule{
	unsigned char proto;
	unsigned char proto_mask;
	unsigned int src;
	unsigned int src_mask;
	unsigned int dst;
	unsigned int dst_mask;
	unsigned short sport;
	unsigned short sport_mask;
	unsigned short dport;
	unsigned short dport_mask;
} qnf_rule_t;

typedef struct qnf_action {
	unsigned short cmd;
	unsigned short outch;
} qnf_action_t;

typedef volatile union {

	struct {
#ifdef QNF_BIG_ENDIAN	
		unsigned short reserved0	: 6; /* bit 31 ~ 22 */
		unsigned short cam_data		: 10; /* bit 25 ~ 16 : cam data[10:0] */
		unsigned short reserved1	: 3; /* bit 15 ~ 13 */
		unsigned short cam_addr		: 5; /* bit 12 ~ 8 */
		unsigned short reserved2	: 6; /* bit 7 ~ 2 */
		unsigned short cam_update	: 1; /* bit 1 */
		unsigned short cam_busy		: 1; /* bit 0 */
#else
		unsigned short cam_busy		: 1; /* bit 0 */	
		unsigned short cam_update	: 1; /* bit 1 */	
		unsigned short reserved2	: 6; /* bit 7 ~ 2 */	
		unsigned short cam_addr		: 5; /* bit 12 ~ 8 */
		unsigned short reserved1	: 3; /* bit 15 ~ 13 */	
		unsigned short cam_data		: 10; /* bit 25 ~ 16 : cam data[10:0] */		
		unsigned short reserved0	: 6; /* bit 31 ~ 26 */
#endif		
		}data;	

	unsigned int value;
}cam_data3_t;

typedef volatile union {
	struct {
#ifdef QNF_BIG_ENDIAN
		unsigned short reserved0		: 15; /* bit 31 ~ 17 */
		unsigned short tag_update		: 1; /* bit 16 */
		unsigned short reserved1		: 7; /* bit 15 ~ 9 */
		unsigned short tag_addr			: 5; /* bit 8 ~ 4 */
		unsigned short tag_value		: 4; /* bit 3 ~ 0 */
#else
		unsigned short tag_value		: 4; /* bit 3 ~ 0 */
		unsigned short tag_addr			: 5; /* bit 9 ~ 5 */
		unsigned short reserved1		: 7; /* bit 15 ~ 9 */
		unsigned short tag_update		: 1; /* bit 16 */
		unsigned short reserved0		: 15; /* bit 31 ~ 17 */
#endif
		}data;
	unsigned int value;
} tag_map_t;

typedef volatile union 
{
	struct 
	{
#ifdef QNF_BIG_ENDIAN
		unsigned int reserved0			: 28;
		unsigned short dma_pause_n		: 1;
		unsigned short status_clear		: 1;
		unsigned short addr_load		: 1; 
		unsigned short burst_ready		: 1; 
#else
		unsigned short burst_ready		: 1; 
		unsigned short addr_load		: 1; 
		unsigned short status_clear		: 1;		
		unsigned short dma_pause_n		: 1;
		unsigned int reserved0			: 28; 
#endif
	}data;
	unsigned int value;
}dma_ctl_reg_t;


// flash update
/**************************************************************************/
typedef volatile union status_reg{
	struct {
#ifdef QNF_BIG_ENDIAN	
		uint16_t sr15	:1;	//bit15
		uint16_t sr14	:1;
		uint16_t sr13	:1;
		uint16_t sr12	:1;
		uint16_t sr11	:1;
		uint16_t sr10	:1;
		uint16_t sr9	:1;
		uint16_t sr8	:1;
		uint16_t sr7	:1;
		uint16_t sr6	:1;
		uint16_t sr5	:1;
		uint16_t sr4	:1;
		uint16_t sr3	:1;
		uint16_t sr2	:1;
		uint16_t sr1	:1;
		uint16_t sr0	:1;	//bit0
#else
		uint16_t sr0	:1;	//bit0
		uint16_t sr1	:1;
		uint16_t sr2	:1;
		uint16_t sr3	:1;
		uint16_t sr4	:1;
		uint16_t sr5	:1;
		uint16_t sr6	:1;
		uint16_t sr7	:1;
		uint16_t sr8	:1;
		uint16_t sr9	:1;
		uint16_t sr10	:1;
		uint16_t sr11	:1;
		uint16_t sr12	:1;
		uint16_t sr13	:1;
		uint16_t sr14	:1;
		uint16_t sr15	:1;	//bit16
#endif
		}SR_t;
	uint16_t value;
} status_reg_t ;


typedef enum{
	UNLOCKED = 0X0000,
	LOCKED = 0X0001,
	UNLOCKED_AND_LOCKEDDOWN = 0X0002,
	LOCKED_AND_LOCKEDDOWN = 0X0003
} lock_stat_t;


#define QNF_IOC_MAGIC  		'i'
#define QNF_IOC_MAXNR		4
#define QNFIOCINFO     		_IOR(QNF_IOC_MAGIC,  2, qnfinf_t)
#ifndef WITHOUT_TS
#define QNFIOCTS				_IOWR(QNF_IOC_MAGIC, 4, tsinf_t)
#endif


#endif /* __QNFTYPE_H__ */
