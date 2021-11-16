/***************************************************************************//**
 * @file
 * @brief iostream usart examples functions
 *******************************************************************************
 * # License
 * <b>Copyright 2020 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include "em_chip.h"
#include "sl_iostream.h"
#include "sl_iostream_init_instances.h"
#include "sl_iostream_handles.h"

#include "psa/crypto.h"
#include "ml_apset.h"

/*******************************************************************************
 *******************************   DEFINES   ***********************************
 ******************************************************************************/

#ifndef BUFSIZE
#define BUFSIZE    80
#endif

#define CMAC

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

/* Input buffer */
static char buffer[BUFSIZE];




/*******************************************************************************
 **************************   GLOBAL FUNCTIONS   *******************************
 ******************************************************************************/

/****************************************************
 * Set up Attributes and CMAC key.
 ****************************************************/





/***************************************************************************//**
 * Initialize example.
 ******************************************************************************/
void app_iostream_usart_init(void)
{
  /* Prevent buffering of output/input.*/
#if !defined(__CROSSWORKS_ARM) && defined(__GNUC__)
  setvbuf(stdout, NULL, _IONBF, 0);   /*Set unbuffered mode for stdout (newlib)*/
  setvbuf(stdin, NULL, _IONBF, 0);   /*Set unbuffered mode for stdin (newlib)*/
#endif

  /* Output on vcom usart instance */
  const char str1[] = "IOstream USART example\r\n\r\n";
  sl_iostream_write(sl_iostream_vcom_handle, str1, strlen(str1));

  /* Setting default stream */
  sl_iostream_set_default(sl_iostream_vcom_handle);
  const char str2[] = "This is output on the default stream\r\n";
  sl_iostream_write(SL_IOSTREAM_STDOUT, str2, strlen(str2));

  /* Using printf */
  /* Writing ASCII art to the VCOM iostream */
  printf("Printf uses the default stream, as long as iostream_retarget_stdio is included.\r\n");
}

/***************************************************************************//**
 * Example ticking function.
 ******************************************************************************/
void app_iostream_usart_process_action(void)
{
  int8_t c = 0;
  static uint8_t index = 0;
  static bool print_welcome = true;
  psa_status_t ret;
  psa_key_id_t key_id;
  static uint8_t hash_key[32];
  static size_t hash_key_size;
  static uint8_t mac[32];
  static size_t mac_size;

  if (print_welcome) {
    printf("> ");
    print_welcome = false;

  }

  /* Retrieve characters, print local echo and full line back */
  c = getchar();
  if (c > 0) {
    if (c == '\r' || c == '\n') {
      buffer[index] = '\0';

      //Initialise cmac key.
      printf("\r\nTesting the CMAC operation:\r\n");
      ret= create_cmac_hash_key(&key_id, hash_key, sizeof(hash_key), &hash_key_size);
      if (ret == PSA_SUCCESS){
      // Sign message.
          ret = cmac_sign_message((uint8_t*)buffer, (size_t)index, key_id, mac, sizeof(mac), &mac_size);

      }

      if(ret == PSA_SUCCESS){

      // Verify the message
          ret = message_cmac_authenticate(key_id, buffer, index, mac, mac_size);
      }
      if(ret == PSA_SUCCESS)
        printf("\r\n\nVerification successful\n\n");
      else
        printf("\r\n\nVerification failed #%ld\n\n", ret);


      if(ret == PSA_SUCCESS)
        printf("\r\nYou wrote: %s\r\n> ", buffer);
      psa_destroy_key(key_id);


      // HMAC
      printf("\r\nTesting the HMAC operation:\r\n");

      ret= create_hmac_hash_key(&key_id, hash_key, sizeof(hash_key), &hash_key_size);
      if (ret == PSA_SUCCESS){
      // Sign message.
          ret = calculate_hmac_message((uint8_t*)buffer,(size_t)index,key_id, mac, sizeof(mac), &mac_size);
      }

      if(ret == PSA_SUCCESS){

      // Verify the message
          ret = message_hmac_authenticate(key_id, buffer, index, mac, mac_size);

      }



      if(ret == PSA_SUCCESS)
        printf("\r\n\nVerification successful\n\n");
      else
        printf("\r\n\nVerification failed #%ld\n\n", ret);


      if(ret == PSA_SUCCESS)
        printf("\r\nYou wrote: %s\r\n> ", buffer);
      psa_destroy_key(key_id);

      index = 0;
    } else {
      if (index < BUFSIZE - 1) {
        buffer[index] = c;
        index++;
      }
      /* Local echo */
      putchar(c);
    }
  }
}
