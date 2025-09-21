#ifndef GLOBAL_H
#define GLOBAL_H

typedef struct string string;

// Encrypt macros
#define BUFFER_SIZE (1 << 20) // 1Mb
#define KEY_SIZE 32
#define SALT_SIZE 8
#define IV_SIZE 16
#define SHA256_BLOCK_SIZE 64
#define PBKDF2_ITERATIONS 10000

// Thread macros
#define NUM_THREAD 4

typedef struct result_t {
  int code;
  string *error_msg;

} result_t;

#define SET_RESULT(result, _code_, _error_msg_)                                \
  (result).code = _code_;                                                      \
  (result).error_msg = string_from_cstr(_error_msg_);

#define RETURN_RESULT(result, _code_, _error_msg_)                             \
  SET_RESULT(result, _code_, _error_msg_);                                     \
  return result;

// Exit errors code
#define EXIT_NO_PASSWORD_FILE_PROVIDED 1
#define EXIT_NO_INPUT_FILE_PROVIDED 2
#define EXIT_INIT_SALT_IV 3
#define EXIT_THREAD_CREATE_ERROR 4
#define EXIT_THREAD_JOIN_ERROR 5
#define EXIT_INVALID_MODE 6
#define EXIT_PASSWORD_ERROR 7
#define EXIT_FILE_ERROR 8
#define EXIT_COULDNT_CREATE_KEY 9
#define EXIT_ERROR_WRITING_SALT_IV 10
#define EXIT_ERROR_READING_SALT_IV 11
#define EXIT_INVALID_NUMBER_OF_OUTPUT_FILES 12

#endif // GLOBAL_H
