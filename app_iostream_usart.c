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


/*
 * Print a non zero terminated buffer values in hex.
 */

void print_buffer(uint8_t *array, int array_length){
  int i;
  for(i=0; i< array_length; i++){
      printf("0x%02X", (unsigned int) (array[i]&0xFF));
      if(i+1 < array_length)
         printf(", ");
  }

}
/*
 * Print the key attributes values.
 */
void print_key_attributes(psa_key_attributes_t *attributes){
  printf("{type: 0x%X, bits: 0X%X, lifetime: 0x%X, id: 0x%X, alg: 0x%X, alg2: 0x%X, usage: 0x%X, flags: 0x%X}",
         attributes->core.type,
         attributes->core.bits,
         (unsigned int)attributes->core.lifetime,
         (unsigned int)attributes->core.id,
         (unsigned int)attributes->core.policy.alg,
         (unsigned int)attributes->core.policy.alg2,
         (unsigned int)attributes->core.policy.usage,
         attributes->core.flags);
}

void clear_terminal_screen(){
  for(int i=0; i<80; i++)
     printf("\n");
}


psa_status_t create_cmac_hash_key(psa_key_id_t *key_id, uint8_t* hash_key, size_t hash_key_size, size_t* hash_key_lenght)
{
  uint8_t key[256/8];
  psa_key_attributes_t key_attr;
  psa_status_t ret;

  printf("\r\n\n Creating CMAC Hash Key:\n");
  ret = psa_crypto_init();
  ret = psa_generate_random(key, sizeof(key));  // Generate a random key AES-256
  printf("\r\nRandom key:\n");
  print_buffer(key, sizeof(key));
  /* Hash the key */
  ret = psa_hash_compute(PSA_ALG_SHA_256, key, sizeof(key), hash_key, hash_key_size, hash_key_lenght);
  printf("\r\n\nHashing key (%d):\n", *hash_key_lenght);
  print_buffer(hash_key, *hash_key_lenght);


  /* Create CMAC key. */
  key_attr = psa_key_attributes_init();

  psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&key_attr, *hash_key_lenght * 8);
  psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH|PSA_KEY_USAGE_VERIFY_MESSAGE|PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&key_attr, PSA_ALG_CMAC);


  // Generate a random key.
  ret = psa_generate_key(&key_attr, key_id);
  printf("\r\n\nKey Attributes:\n");
  if(ret == PSA_SUCCESS){
  // Import a volatile plain key
      ret = psa_import_key(&key_attr, hash_key, hash_key_size, key_id);
  }
  print_key_attributes(&key_attr);
  return ret;
}

psa_status_t create_hmac_hash_key(psa_key_id_t *key_id, uint8_t* hash_key, size_t hash_key_size, size_t* hash_key_lenght)
{
  uint8_t key[256/8];
  psa_key_attributes_t key_attr;
  psa_status_t ret;

  printf("\r\n\n Creating HMAC Hash Key:\n");
  ret = psa_crypto_init();
  ret = psa_generate_random(key, sizeof(key));  // Generate a random key AES-256
  printf("\r\nRandom key:\n");
  print_buffer(key, sizeof(key));


  /* Hash the key */
  ret = psa_hash_compute(PSA_ALG_SHA_256, key, sizeof(key), hash_key, hash_key_size, hash_key_lenght);
  printf("\r\n\nHashing key (%d):\n", *hash_key_lenght);
  print_buffer(hash_key, *hash_key_lenght);



  /* Create CMAC key. */
  key_attr = psa_key_attributes_init();

  psa_set_key_type(&key_attr, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&key_attr, *hash_key_lenght * 8);
  psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH|PSA_KEY_USAGE_VERIFY_MESSAGE|PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&key_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));


  // Generate a random key.
  ret = psa_generate_key(&key_attr, key_id);
  if(ret == PSA_SUCCESS){
  // Import a volatile plain key
      ret = psa_import_key(&key_attr, hash_key, hash_key_size, key_id);
  }
  printf("\r\n\nKey Attributes:\n");
  print_key_attributes(&key_attr);
  return ret;
}



psa_status_t calculate_mac_message(uint8_t* message_buffer,
                                  size_t message_buffer_size,
                                  psa_key_id_t key_id,
                                  psa_algorithm_t alg,
                                  uint8_t* mac_buffer,
                                  size_t mac_buffer_size,
                                  size_t* mac_length){
  psa_status_t ret;
  psa_mac_operation_t mac_op;

  mac_op = psa_mac_operation_init();
  ret = psa_mac_sign_setup(&mac_op, key_id, alg);
  if (ret == PSA_SUCCESS)
    ret = psa_mac_update(&mac_op, message_buffer, message_buffer_size);
  if (ret == PSA_SUCCESS)
    ret = psa_mac_sign_finish(&mac_op, mac_buffer, mac_buffer_size, mac_length);
  if (ret != PSA_SUCCESS)
    psa_mac_abort(&mac_op);

  print_buffer(mac_buffer, *mac_length);

  return ret;



}


psa_status_t cmac_sign_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length)
{
  printf("\r\n\nMAC for CMAC:\n");
  return calculate_mac_message(message_buffer, message_buffer_size, key_id, PSA_ALG_CMAC, mac_buffer, mac_buffer_size, mac_length);
}

psa_status_t calculate_hmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length){
  printf("\r\n\nMAC for HMAC:\n");
  return calculate_mac_message(message_buffer, message_buffer_size, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), mac_buffer, mac_buffer_size, mac_length);
}

psa_status_t message_mac_authenticate(psa_key_id_t key_id, psa_algorithm_t alg, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size)
{
  psa_mac_operation_t operation;
  psa_status_t ret;
  operation = psa_mac_operation_init();

  ret = psa_mac_verify_setup(&operation, key_id, alg);
  if(ret == PSA_SUCCESS)
    ret = psa_mac_update(&operation, message, message_size); // do not use pas_mac_verify.
  if(ret == PSA_SUCCESS)
     ret = psa_mac_verify_finish(&operation, mac, mac_size);
  if (ret != PSA_SUCCESS)
    psa_mac_abort(&operation);
  return ret;
}


psa_status_t message_cmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size)
{
  return message_mac_authenticate(key_id,PSA_ALG_CMAC,message, message_size, mac, mac_size);
}

psa_status_t message_hmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size)
{
  return message_mac_authenticate(key_id,PSA_ALG_HMAC(PSA_ALG_SHA_256), message, message_size, mac, mac_size);
}


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
#ifdef CMAC
      //Initialise cmac key.
      ret= create_cmac_hash_key(&key_id, hash_key, sizeof(hash_key), &hash_key_size);
      if (ret == PSA_SUCCESS){
      // Sign message.
          ret = cmac_sign_message((uint8_t*)buffer, (size_t)index, key_id, mac, sizeof(mac), &mac_size);

      }

      if(ret == PSA_SUCCESS){

      // Verify the message
          ret = message_cmac_authenticate(key_id, buffer, index, mac, mac_size);
      }


#else
      ret= create_hmac_hash_key(&key_id, hash_key, sizeof(hash_key), &hash_key_size);
      if (ret == PSA_SUCCESS){
      // Sign message.
          ret = calculate_hmac_message((uint8_t*)buffer,(size_t)index,key_id, mac, sizeof(mac), &mac_size);
      }

      if(ret == PSA_SUCCESS){

      // Verify the message
          ret = message_hmac_authenticate(key_id, buffer, index, mac, mac_size);

      }


#endif

      if(ret == PSA_SUCCESS)
        printf("\r\n\nVerification successful\n\n");
      else
        printf("\r\n\nVerification failed #%u\n\n", ret);


      if(ret == PSA_SUCCESS)
        printf("\r\nYou wrote: %s\r\n> ", buffer);
      index = 0;
      psa_destroy_key(key_id);
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
