/*
 * ml_apset.c
 *
 *  Created on: Nov 15, 2021
 *      Author: malafont
 */

#include <stdio.h>
#include <string.h>
#include "ml_apset.h"

#include "psa/crypto.h"

#define COLUMN_PRINT 16

psa_status_t message_mac_authenticate(psa_key_id_t key_id, psa_algorithm_t alg, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size);
int char_occurance_count(const char* str, const char ch);

void print_buffer_memory_header(const int columns_count);
void print_buffer_character(const char* format,  char ch);
void print_char_row(const char* format, char* row, int columns_count);



int char_occurance_count(const char* str, const char ch)
{
  int count = 0;
  char *ret = (char*) str;
  while(*ret != '\0'){
      ret = memchr(ret, ch, strlen(ret));
      if(*ret == ch){
        count++;
      ret++;
      }
  }
  return count;
}

void print_buffer_character(const char* format, char ch)
{
  int count = char_occurance_count(format, '%');
  switch(count){
    case 1:
      printf(format,ch);
      break;
    case 2:
      printf(format,ch,ch);
      break;
    default:
      break;
  }
}

void print_char_row(const char* format, char* row, int columns_count)
{
  for (int i=0; i< columns_count; i++){
      print_buffer_character(format, *(row+i));
  }
}

/*
 * Print a non zero terminated buffer values in hex.
 */

void print_buffer(uint8_t *array, int array_length)
{
  int i;
  for(i=0; i< array_length; i++){
      printf("0x%02X", (unsigned int) (array[i]&0xFF));
      if(i+1 < array_length)
         printf(", ");
  }

}

void print_buffer_memory_header(const int columns_count)
{
  printf("\r\nAddress \t");
  for(int i=0; i<columns_count; i++){
      printf("[%2X]    ", i);
  }
  printf("\r\n");
}

void print_buffer_memory(const char *format, uint8_t *array, int array_lenght, const int columns_count)
{
  uint8_t *end = array + array_lenght;

  print_buffer_memory_header(columns_count);
  while(array < end){
      printf("%X:\t", (unsigned int)array);
      print_char_row(format, (char*)array, columns_count);
      printf("\r\n");
      array += columns_count;
  }
}

void print_buffer_memory_hex_char(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("\"%c\"[%2X] ", array, array_lenght, columns_count);
}

void print_buffer_memory_hex(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("[%2X]    ", array, array_lenght, columns_count);
}

void print_buffer_memory_char(uint8_t *array, int array_lenght, const int columns_count)
{
  print_buffer_memory("\"%c\"     ", array, array_lenght, columns_count);
}

void print_key_hex(uint8_t *array, int array_length)
{
  for(int i=0; i<array_length; i++){
      printf("%02X", array[i]);
      if (i < array_length-1)
        printf("-");
  }
}


/*
 * Print the key attributes values.
 */
void print_key_attributes(psa_key_attributes_t *attributes)
{
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

void clear_terminal_screen()
{
  for(int i=0; i<80; i++)
     printf("\n");
}

/*******************************************************
 * Create a random key
 * @param buffer  Location where to store the key.
 * @param buffer_length Lenght of the buffer to store the generated key.
 * @param key_bits  Number of bits of the key to generate.
 * @return PSA error code.
 */
psa_status_t create_random_key(uint8_t *buffer, size_t buffer_length, const int key_bits)
{
  psa_status_t ret = PSA_SUCCESS;
  int key_byte = key_bits/8;

  if ((int)buffer_length < key_byte)
    ret = PSA_ERROR_INSUFFICIENT_MEMORY;
  if (ret == PSA_SUCCESS)
    ret = psa_crypto_init();
  if (ret == PSA_SUCCESS)
    ret = psa_generate_random(buffer, key_byte);
  return ret;
}

psa_status_t set_up_attributes(psa_key_id_t *key_id,
                               psa_key_attributes_t *attr,
                               psa_key_type_t type,
                               size_t number_bits,
                               psa_key_usage_t flags,
                               psa_algorithm_t alg,
                               int location
                               )
{
  *attr = psa_key_attributes_init();

  psa_key_lifetime_t lifetime;

  psa_set_key_type(attr, type);
  psa_set_key_bits(attr, number_bits);
  psa_set_key_usage_flags(attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH|PSA_KEY_USAGE_VERIFY_MESSAGE|PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(attr, PSA_ALG_CMAC);
  if (key_id == 0){
      lifetime =  PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_VOLATILE, location);
  }
  else {
      lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, location);

  }
  psa_set_key_lifetime(attr, lifetime);


}


psa_status_t create_cmac_hash_key(psa_key_id_t *key_id, uint8_t* hash_key, size_t hash_key_size, size_t* hash_key_lenght)
{
  uint8_t key[256/8];
  psa_key_attributes_t key_attr;
  psa_status_t ret;

  printf("\r\n\n Creating CMAC Hash Key:\n");
  ret = psa_crypto_init();
  ret = psa_generate_random(key, sizeof(key));  // Generate a random key AES-256
  printf("\r\nRandom key: ");
  print_key_hex(key, sizeof(key));

  //print_buffer(key, sizeof(key));
  /* Hash the key */
  ret = psa_hash_compute(PSA_ALG_SHA_256, key, sizeof(key), hash_key, hash_key_size, hash_key_lenght);
  printf("\r\n\nHashing key (%d): ", *hash_key_lenght);
  print_key_hex(hash_key, *hash_key_lenght);


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
  printf("\r\nRandom key: ");
  print_key_hex(key, sizeof(key));

  //print_buffer(key, sizeof(key));


  /* Hash the key */
  ret = psa_hash_compute(PSA_ALG_SHA_256, key, sizeof(key), hash_key, hash_key_size, hash_key_lenght);
  printf("\r\n\nHashing key (%d): ", *hash_key_lenght);
  print_key_hex(hash_key, *hash_key_lenght);



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
                                  size_t* mac_length)
{
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
  print_key_hex(mac_buffer, *mac_length);
  return ret;



}


psa_status_t cmac_sign_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length)
{
  printf("\r\n\nMAC for CMAC: ");
  return calculate_mac_message(message_buffer, message_buffer_size, key_id, PSA_ALG_CMAC, mac_buffer, mac_buffer_size, mac_length);
}

psa_status_t calculate_hmac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length){
  printf("\r\n\nMAC for HMAC: ");
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

