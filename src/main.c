#include <estd/argparser.h>
#include <estd/efile.h>
#include <stdio.h>
#include <stdlib.h>

#include "encrypt.h"
#include "global.h"
#include "thread_process.h"

#define CHECK_ERROR(error)                                                     \
  if (error != OK) {                                                           \
    fprintf(stderr, "%s\n", easy_error_message(error));                        \
    goto cleanup;                                                              \
  }

inline static void usage(void) {
  puts(
      "Usage: denc [OPTIONS]... [FILE]\n"
      "Encrypt/Decrypt given file with key using xor\n"
      "\n"
      "Options:\n"
      "-p, --password <path to password file>\t Provide key that would be used "
      "for "
      "encryption/decryption\n"
      "-e, --encypt\t\t\t\t Encrypt file\n"
      "-d, --decrypt\t\t\t\t Decrypt file\n"
      "-o, --output\t\t\t\t Set output file\n"
      "-t, --threads\t\t\t\t Set number of threads to use\n"
      "-h, --help\t\t\t\t Display this help and exit");
}

static inline easy_error add_arguments(cmd_parser *parser) {
  easy_error err = OK;

  err = cmd_parser_add(parser, "-h", "--help", FLAG);
  if (err != OK)
    return err;

  err = cmd_parser_add(parser, "-p", "--password", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-o", "--output", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-t", "--threads", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-e", "--encrypt", FLAG);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-d", "--decrypt", FLAG);
  if (err != OK)
    return err;

  return OK;
}

static inline easy_error check_arguments(cmd_parser *parser,
                                         bool *password_flag, bool *output_flag,
                                         bool *help_flag, bool *encrypt_flag,
                                         bool *decrypt_flag,
                                         bool *threads_flag) {
  easy_error err = OK;

  *help_flag = cmd_is_set(parser, "-h", &err);
  if (err != OK)
    return err;

  *encrypt_flag = cmd_is_set(parser, "-e", &err);
  if (err != OK)
    return err;

  *decrypt_flag = cmd_is_set(parser, "-d", &err);
  if (err != OK)
    return err;

  *password_flag = cmd_is_set(parser, "-p", &err);
  if (err != OK)
    return err;

  *output_flag = cmd_is_set(parser, "-o", &err);
  if (err != OK)
    return err;

  *threads_flag = cmd_is_set(parser, "-t", &err);
  if (err != OK)
    return err;

  return OK;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage();
    return EXIT_FAILURE;
  }

  easy_error error = OK;
  string *password = NULL;
  freader *input_file = NULL, *password_file = NULL;
  fwriter *output_file = NULL;

  const string *path_to_password_file = NULL, *path_to_output_file_given = NULL,
               *path_to_input_file = NULL;

  bool password_flag = false, output_flag = false, help_flag = false,
       encrypt_flag = false, decrypt_flag = false, threads_flag = false;

  string *path_to_output_file =
      NULL; // This would be not NULL if user didn't pass output file

  PROGRAM_MODE mode = 0;
  int num_threads = 0;

  // Creating parser
  cmd_parser *parser = cmd_parser_create();
  if (!parser) {
    fprintf(stderr, "Error of creating parser!\n");
    error = ALLOCATION_FAILED;
    goto cleanup;
  }

  // Adding arguments
  error = add_arguments(parser);
  CHECK_ERROR(error);

  // Parse command line
  error = cmd_parser_parse(parser, argc, argv);
  if (error != OK) {
    fprintf(stderr, "Fatal! %s", easy_error_message(error));
    if (parser->arg_error)
      fprintf(stderr, ": %s\n", string_cstr(parser->arg_error));

    goto cleanup;
  }

  error = check_arguments(parser, &password_flag, &output_flag, &help_flag,
                          &encrypt_flag, &decrypt_flag, &threads_flag);
  CHECK_ERROR(error);

  if (help_flag) {
    usage();
    goto cleanup;
  }

  if (encrypt_flag && decrypt_flag) {
    fprintf(stderr, "Fatal! provide both encrypt and decrypt flag mode!\n");
    error = EXIT_INVALID_MODE;
    goto cleanup;

  } else if (!encrypt_flag && !decrypt_flag) {
    fprintf(stderr, "Fatal! No flag mode provide!\n");
    error = EXIT_INVALID_MODE;
    goto cleanup;
  }

  mode = (encrypt_flag) ? ENCRYPT : DECRYPT;

  // Getting input file
  const grow *positional_args = cmd_get_pos_args(parser, &error);
  CHECK_ERROR(error);

  // No input file provided
  if (grow_size(positional_args) == 0) {
    fprintf(stderr, "Fatal! No file to encrypt/decrypt provided!\n");

    error = EXIT_NO_INPUT_FILE_PROVIDED;
    goto cleanup;

    // Provided more that 1 input file
  } else if (grow_size(positional_args) > 1) {
    fprintf(stderr, "Fatal! Too many input files: ");
    for (size_t i = 0; i < grow_size(positional_args) && error == OK; i++) {
      const string *arg = grow_get(positional_args, i, &error);
      fprintf(stderr, " %s, ", string_cstr(arg));
    }

    error = EXIT_MORE_THAN_ONE_INPUT_FILE;
    goto cleanup;
  }

  path_to_input_file = grow_get(positional_args, 0, &error);
  CHECK_ERROR(error);

  // Getting password
  if (password_flag) {
    path_to_password_file = cmd_get_value(parser, "-p", &error);
    CHECK_ERROR(error);

  } else {
    fprintf(stderr, "Fatal! No password file provided!\n");
    error = EXIT_NO_PASSWORD_FILE_PROVIDED;
    goto cleanup;
  }

  // Getting output file
  if (output_flag) {
    path_to_output_file_given = cmd_get_value(parser, "-o", &error);
    CHECK_ERROR(error);

  } else {
    path_to_output_file = string_from_cstr(string_cstr(path_to_input_file));
    error = string_append(path_to_output_file, ".x"); // add .x extension
    CHECK_ERROR(error);
  }

  if (threads_flag) {
#ifdef _MSC_VER
    printf("Setting number of threads doesn't support for MSC!\n Set a default "
           "value:%d\n",
           NUM_THREAD);
#else
    const string *thrds = cmd_get_value(parser, "-t", &error);
    CHECK_ERROR(error);
    num_threads = atoi(string_cstr(thrds));
#endif
  }

  // Opening files
  input_file = openr(string_cstr(path_to_input_file), READ_BIN, &error);
  CHECK_ERROR(error);

  output_file =
      openw(string_cstr((path_to_output_file) ? path_to_output_file
                                              : path_to_output_file_given),
            WRITE_BIN, &error);
  CHECK_ERROR(error);

  password_file = openr(string_cstr(path_to_password_file), READ_BIN, &error);
  CHECK_ERROR(error);

  password = read_file(password_file, &error);
  CHECK_ERROR(error);

  error = encrypt_decrypt(mode, password, input_file, output_file, num_threads);

cleanup: // Goto place to cleanup all allocated stuff
  if (parser)
    cmd_parser_free(parser);
  if (output_file)
    closew(output_file);
  if (input_file)
    closer(input_file);
  if (password_file)
    closer(password_file);
  if (password)
    string_free_(password);
  if (path_to_output_file)
    string_free_(path_to_output_file);

  return error;
}
