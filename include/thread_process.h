#ifndef THREAD_PROCES_H
#define THREAD_PROCES_H

#include <stddef.h>
#include <stdint.h>

typedef struct string string;

typedef struct thread_data_t {
  unsigned char *buffer;
  size_t start;
  size_t end;
  uint64_t start_pos;
  const string *key;
  const unsigned char *iv;

} thread_data_t;

/** @brief thread function for encrypting given buffer
 *
 * @param arg thread_data_t parametr
 * @return 0
 */
int process_chunk(void *arg);

/**
 * @brief Create @num_thread threads and process chunks in them
 *
 * @param key Key of encryption/decryption
 * @param buffer Buffer of readed part of file
 * @param num_thread Number of threads
 * @param bytes_read How many bytes are readed
 * @pos Position of pointer in file
 *
 * @return EXIT_SUCCESS or error code
 */
int multithreading_processing(const string *key, unsigned char *buffer,
                              int num_thread, size_t bytes_read,
                              const unsigned char *iv, uint32_t pos);

#endif // THREAD_PROCES_H
