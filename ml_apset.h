/*
 * ml_apset.h
 *
 *  Created on: Nov 15, 2021
 *      Author: malafont
 */

#ifndef ML_APSET_H_
#define ML_APSET_H_

#include "psa/crypto.h"

void clear_terminal_screen();
void print_buffer(uint8_t *array, int array_length);
void print_buffer_memory(const char* format, uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_hex_char(uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_hex(uint8_t *array, int array_lenght, const int columns_count);
void print_buffer_memory_char(uint8_t *array, int array_lenght, const int columns_count);
void print_key_hex(uint8_t *array, int array_length);

void print_key_attributes(psa_key_attributes_t *attributes);


psa_status_t create_random_key(uint8_t *buffer, size_t buffer_length, const int key_bits);



psa_status_t create_cmac_hash_key(psa_key_id_t *key_id, uint8_t* hash_key, size_t hash_key_size, size_t* hash_key_lenght);
psa_status_t create_hmac_hash_key(psa_key_id_t *key_id, uint8_t* hash_key, size_t hash_key_size, size_t* hash_key_lenght);

psa_status_t calculate_mac_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, psa_algorithm_t alg, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length);

psa_status_t cmac_sign_message(uint8_t* message_buffer, size_t message_buffer_size, psa_key_id_t key_id, uint8_t* mac_buffer, size_t mac_buffer_size, size_t* mac_length);

psa_status_t message_cmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size);
psa_status_t message_hmac_authenticate(psa_key_id_t key_id, uint8_t* message, size_t message_size, uint8_t *mac, size_t mac_size);


#endif /* ML_APSET_H_ */
