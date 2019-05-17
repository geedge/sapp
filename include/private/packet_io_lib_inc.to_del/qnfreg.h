/*
 * Copyright (c) 2010-2015 Qice Technology Ltd, Beijing, China.
 * All rights reserved.
 *
 * This source code is proprietary to Qice Technology Limited and no part
 * of it may be redistributed, published or disclosed except as outlined in
 * the written contract supplied with this product.
 *
 *******************************************************************************
 *	qnfreg.h: this file defines the internal registers
 *******************************************************************************/

#ifndef __QNFREG_H__
#define __QNFREG_H__


// DMA regs
#define DMA_CTL_REG 		      (0x80000)
#define HOST_ADDR_LO_REG 	(0x80004)
#define HOST_ADDR_HI_REG 	(0x80008)
#define BUF_BOTTOM_LO_REG 	(0x8000C)
#define BUF_BOTTOM_HI_REG 	(0x80010)
#define LIMIT_PTR_LO_REG 	      (0x80014)
#define LIMIT_PTR_HI_REG 	      (0x80018)
#define RECORD_PTR_LO_REG 	(0x80020)
#define RECORD_PTR_HI_REG 	(0x80024)
#define DROP_CNT_REG 		(0x80028)
#define STREAM_REG_DIFF_0x40	(0x40)

// internal tcam
#define CAM0_DATA 	      (0x90000)
#define CAM1_DATA 	      (0x90004)
#define CAM2_DATA 	      (0x90008)
#define CAM3_DATA 	      (0x9000C)

#define CAM0_MASK 	      (0x90010)
#define CAM1_MASK 	      (0x90014)
#define CAM2_MASK 	      (0x90018)
#define CAM3_MASK 	      (0x9001C)

// tag map for scheduler
#define TAG_MAP_REG 		      (0x90020)
#define CAP_LENGTH_REG 	      (0x90024)
#define CAPTURE_CTL_REG	      (0x90028)
#define HASH_MODE_REG          (0x9002c)
#define ACTIVE_STREAM	      (0x900EC)

//flash update regs
#define FLASH_ADDR                 (0x900E4)
#define FLASH_DATA                 (0x900E0)

// i2c regs
#define I2C_BASEADDR             (0x900E8)
#define MDIO_BASEADDR          (0x900F0)


// MAC reg interface
#define MAC_DATA_LO               (0x90090)
#define MAC_DATA_HI               (0x90094)
#define MAC_ADDR                    (0x90098)
#define MAC_CFGREG_OFFSET     (0x00200)
#define MAC_STATSREG_OFFSET  (0x00000)

// DEBUG registers
#define BUILDDATE                    (0x900F8)
#define PKT_INPUT_CNT_LO        (0x900C0)
#define PKT_INPUT_CNT_HI        (0x900C4)
#define DLFIFOSTATUS               (0x900C8)

#endif  /* __QNFREG_H__ */


