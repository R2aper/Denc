#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stddef.h>
#include <stdint.h>

typedef struct string string;
typedef struct freader freader;
typedef struct fwriter fwriter;

typedef enum PROGRAM_MODE { DECRYPT = 0, ENCRYPT = 1 } PROGRAM_MODE;

/**
 * @brief Get len random bytes
 *
 * @param buf Pointer to array where random bytes are write
 * @param len Lenght of buf
 *
 * @return 0 or error
 */
int get_random_bytes(void *buf, int32_t len);

/**
 * @brief Encrypt source's bytes with password and write them to output
 *
 * @param password String containing password
 * @param source Source file
 * @param output Output file
 *
 * @return 0 or error
 */
int encrypt(const string *password, freader *source, fwriter *output,
            int num_threads);

/**
 * @brief Decrypt source's bytes with password and write them to output
 *
 * @param password String containing password
 * @param source Source file
 * @param output Output file
 *
 * @return 0 or error
 */
int decrypt(const string *password, freader *source, fwriter *output,
            int num_threads);

#define encrypt_decrypt(password, source, output, mode, num_threads)           \
  (mode == DECRYPT) ? decrypt(password, source, output, num_threads)           \
                    : encrypt(password, source, output, num_threads)

#endif // ENCRYPT_H
