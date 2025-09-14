#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <stdint.h>

typedef struct string string;
typedef struct freader freader;
typedef struct fwriter fwriter;

typedef enum PROGRAM_MODE { DECRYPT = 0, ENCRYPT = 1 } PROGRAM_MODE;

int get_random_bytes(void *buf, size_t len);
uint32_t ced_hash_fnv1a(const void *key, size_t length);

/*
 * @brief
 *
 * @param password
 * @param source
 * @param output
 *
 * @return
 */
int encrypt(const string *password, freader *source, fwriter *output);

/*
 * @brief
 *
 * @param password
 * @param source
 * @param output
 *
 * @return
 */
int decrypt(const string *password, freader *source, fwriter *output);

#define encrypt_decrypt(password, source, output, mode)                        \
  (mode == DECRYPT) ? decrypt(password, source, output)                        \
                    : encrypt(password, source, output)

#endif // ENCRYPT_H
