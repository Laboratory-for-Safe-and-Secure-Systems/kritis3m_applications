//****************************************************************************
//
//  Project:  CardOS
//
//*****************************************************************************
//
/// \file   CardOS_IoT_I2C_driver.h
///
/// \brief  header file for CardOS_IoT_I2C_driver.c
///
///
/// Communication layer
///
//  Copyright (C) Atos IT Solution and Services GmbH 2017. All rights reserved.
//
//  Protection Class:  Confidential!
//
//******************************** Version ***********************************
//*
//* $Id: 
//*
//***************************************************************************

#ifndef CARDOS_IOT_I2C_DRIVER_H
#define CARDOS_IOT_I2C_DRIVER_H

#define SMARTCARDINTERFACE_ENABLE_I2C 1

#if SMARTCARDINTERFACE_ENABLE_I2C

//raspiI2C return value
#define I2C_RV 									int

//return codes
#define I2C_S_SUCCESS 							0
#define I2C_E_CONFIG_ERROR 						1
#define I2C_E_RW_ERROR							2

//max buffer sizes
#define I2C_SEND_BUFF_SIZE    					5120
#define I2C_RESP_BUFF_SIZE    					5120

#define SMARTCARDREADER_NAME_MAXLEN 128 //TODO: just use one define
#define SMARTCARDREADER_ID_MAXLEN 256 //TODO: just use one define

typedef struct _i2cParameters
{
	int address;
} i2cParameters;	

typedef struct _i2cReader
{
  char readerName[SMARTCARDREADER_NAME_MAXLEN];
  char readerID[SMARTCARDREADER_ID_MAXLEN];
} i2cReader;

//Calculates LRC (packet checksum) and puts it into packet buffer
uint8_t calculateLrcI2C(uint8_t *buff, uint32_t length, uint8_t storeToBuffer);

//checks checksum of received packet
uint8_t checkChecksumI2C(uint8_t *response, uint32_t responseLength);

//SPI setup function
 __attribute__((weak)) I2C_RV setupI2C(i2cParameters *i2cParams);

//SPI read/write function
 __attribute__((weak)) I2C_RV I2C_RW(void *context, unsigned char *packet, int packetLength, unsigned char *response, int *responseLength);	

I2C_RV getReadersI2C(i2cReader * readers);

#endif /* SMARTCARDINTERFACE_ENABLE_I2C */

#endif
