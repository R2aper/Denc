#ifndef THREAD_PROCES_H
#define THREAD_PROCES_H

#include <estd/eerror.h>
#include <stddef.h>
#include <stdint.h>

typedef struct string string;
typedef struct result_t result_t;

typedef struct thread_data_t {
  unsigned char *buffer;
  size_t start;
  size_t end;
  uint64_t start_pos;
  const string *key;
  const uint8_t *iv;

} thread_data_t;

/** @brief thread function for encrypting given buffer
 *
 * @param arg thread_data_t parametr
 * @return 0 or error code
 */
easy_error process_chunk(void *arg);

/**
 * @brief Create @num_threads threads and process chunks in them
 *
 * @param key Key of encryption/decryption
 * @param buffer Buffer of readed part of file
 * @param num_threads Number of threads(pass 0 to chose number of your cpu
 * threads)
 * @param bytes_read How many bytes are readed
 * @pos Position of pointer in file
 *
 * @return result_t with 0 or with error code
 */
result_t multithreading_processing(const string *key, unsigned char *buffer,
                                   int num_threads, size_t bytes_read,
                                   const uint8_t *iv, uint64_t pos);

#endif // THREAD_PROCES_H
