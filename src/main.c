#include <estd/argparser.h>
#include <estd/eerror.h>
#include <estd/efile.h>
#include <estd/estring.h>
#include <stdlib.h>

#include "encrypt.h"
#include "global.h"
#include "thread_process.h"

#define CHECK_ERROR(result)                                                    \
  if (result.code != OK) {                                                     \
    result.error_msg = string_from_cstr(easy_error_message(result.code));      \
    goto cleanup;                                                              \
  }

inline static void usage(void) {
  puts(
      "Usage: denc [OPTIONS] ... [FILES]\n"
      "Encrypt/Decrypt given files with password using xor\n"
      "\n"
      "Options:\n"
      "-p, --password <path to password file>\t Provide key that would be used "
      "for "
      "encryption/decryption\n"
      "-e, --encypt\t\t\t\t Encrypt data\n"
      "-d, --decrypt\t\t\t\t Decrypt data\n"
      "-o, --output\t\t\t\t Set output files\n"
      "-t, --threads\t\t\t\t Set number of threads to use\n"
      "-v, --verbose\t\t\t\t Verbosely list files processed\n"
      "-h, --help\t\t\t\t Display this help and exit");
}

static inline easy_error add_arguments(cmd_parser *parser) {
  easy_error err = OK;

  err = cmd_parser_add(parser, "-h", "--help", FLAG);
  if (err != OK)
    return err;

  err = cmd_parser_add(parser, "-v", "--verbose", FLAG);
  if (err != OK)
    return err;

  err = cmd_parser_add(parser, "-p", "--password", SINGLE_OPTION);
  if (err != OK)
    return err;

  cmd_parser_add(parser, "-o", "--output", MULTIPLE_OPTION);
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
                                         bool *decrypt_flag, bool *threads_flag,
                                         bool *verbose_flag) {
  easy_error err = OK;

  *help_flag = cmd_is_set(parser, "-h", &err);
  if (err != OK)
    return err;

  *verbose_flag = cmd_is_set(parser, "-v", &err);
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

static inline easy_error generate_output_files(grow *output_files,
                                               const grow *input_files) {
  easy_error err = OK;
  string *path_to_output_file = NULL;
  for (size_t i = 0; i < grow_size(input_files) && err == OK; i++) {
    const string *input_file = (string *)grow_get(input_files, i, &err);
    path_to_output_file = string_create(string_cstr(input_file));
    err = string_append(path_to_output_file, ".x");
    err = grow_push(output_files, path_to_output_file);
  }

  return err;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage();
    return EXIT_FAILURE;
  }

  result_t result = {0, NULL};
  string *password = NULL;
  freader *input_file = NULL, *password_file = NULL;
  fwriter *output_file = NULL;

  // This would be not NULL, if user didn't specify output_files
  grow *output_files = NULL;

  // Paths(a.k.a. string*)
  const grow *output_files_given = NULL, *input_files = NULL;
  const string *path_to_password_file = NULL;

  bool password_flag = false, output_flag = false, help_flag = false,
       encrypt_flag = false, decrypt_flag = false, threads_flag = false,
       verbose_flag = false;

  PROGRAM_MODE mode = 0;
  int num_threads = 0;

  // Creating parser
  cmd_parser *parser = cmd_parser_create();
  if (!parser) {
    SET_RESULT(result, ALLOCATION_FAILED, "Error of creating parser");
    goto cleanup;
  }

  // Adding arguments
  result.code = add_arguments(parser);
  CHECK_ERROR(result);

  // Parse command line
  result.code = cmd_parser_parse(parser, argc, argv);
  if (result.code != OK) {
    result.error_msg = string_from_cstr(easy_error_message(result.code));
    if (parser->arg_error) {
      string_append(result.error_msg, ": ");
      string_append(result.error_msg, string_cstr(parser->arg_error));
    }

    goto cleanup;
  }

  result.code = check_arguments(parser, &password_flag, &output_flag,
                                &help_flag, &encrypt_flag, &decrypt_flag,
                                &threads_flag, &verbose_flag);
  CHECK_ERROR(result);

  if (help_flag) {
    usage();
    goto cleanup;
  }

  if (encrypt_flag && decrypt_flag) {
    SET_RESULT(result, EXIT_INVALID_MODE,
               "Provide both encrypt and decrypt flag mode");
    goto cleanup;

  } else if (!encrypt_flag && !decrypt_flag) {
    SET_RESULT(result, EXIT_INVALID_MODE, "No flag mode provide");
    goto cleanup;
  }

  mode = (encrypt_flag) ? ENCRYPT : DECRYPT;

  if (threads_flag) {
    const string *thrds = cmd_get_value(parser, "-t", &result.code);
    CHECK_ERROR(result);
    num_threads = atoi(string_cstr(thrds));
  }

  // Getting password
  if (password_flag) {
    path_to_password_file = cmd_get_value(parser, "-p", &result.code);
    CHECK_ERROR(result);

    password_file =
        openr(string_cstr(path_to_password_file), READ_BIN, &result.code);
    CHECK_ERROR(result);

    password = read_file(password_file, &result.code);
    CHECK_ERROR(result);

  } else { // If user didn't provide password file, ask password from user
    puts("Enter password:");
    password = string_from_input();
    if (!password) {
      SET_RESULT(result, ALLOCATION_FAILED,
                 easy_error_message(ALLOCATION_FAILED));
      goto cleanup;
    }
  }

  // Getting input file
  input_files = cmd_get_pos_args(parser, &result.code);
  CHECK_ERROR(result);

  // No input file provided
  if (grow_size(input_files) == 0) {
    SET_RESULT(result, EXIT_NO_INPUT_FILE_PROVIDED,
               "No file to encrypt/decrypt provided")
    goto cleanup;
  }

  // Getting output file
  if (output_flag) {
    output_files_given = cmd_get_values(parser, "-o", &result.code);
    CHECK_ERROR(result);

    if (grow_size(output_files_given) != grow_size(input_files)) {
      result.code = EXIT_INVALID_NUMBER_OF_OUTPUT_FILES;
      result.error_msg = string_from_cstr(
          "Number of input files doesn't equal to output files");
      goto cleanup;
    }

  } else { // If user didn't proived output files, generete them
    output_files = grow_init_empty;
    if (!output_files) {
      SET_RESULT(result, ALLOCATION_FAILED,
                 easy_error_message(ALLOCATION_FAILED));
    }
    result.code = generate_output_files(output_files, input_files);
    CHECK_ERROR(result);
  }

  for (size_t i = 0; i < grow_size(input_files) && result.code == OK; i++) {
    const string *path_to_output_file = NULL, *path_to_input_file = NULL;

    path_to_output_file = grow_get(
        (!output_files) ? output_files_given : output_files, i, &result.code);
    CHECK_ERROR(result);

    path_to_input_file = grow_get(input_files, i, &result.code);
    CHECK_ERROR(result);

    input_file = openr(string_cstr(path_to_input_file), READ_BIN, &result.code);
    CHECK_ERROR(result);

    output_file =
        openw(string_cstr(path_to_output_file), WRITE_BIN, &result.code);
    CHECK_ERROR(result);

    if (verbose_flag)
      printf((mode == ENCRYPT) ? "Encyption %s\n" : "Decryption %s\n",
             string_cstr(path_to_input_file));

    result =
        encrypt_decrypt(mode, password, input_file, output_file, num_threads);

    closew(output_file);
    closer(input_file);
    output_file = NULL;
    input_file = NULL;
  }

cleanup: // Goto place to cleanup all allocated stuff
  if (result.code != OK)
    fprintf(stderr, "Fatal! %s\n", string_cstr((result).error_msg));

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
  if (output_files)
    grow_free_(output_files, string_free_abs);
  if (result.error_msg)
    string_free_(result.error_msg);

  return result.code;
}
