# denc - Simple File Encryption Tool

## ⚠️ Disclaimer

This is an educational project and should **not** be used for serious cryptographic purposes. The primary goal was to implement a simple encryption algorithm to practice C programming and to use my `estd` library in a practical application. The security of the implemented algorithm has not been professionally audited and may contain vulnerabilities.

## Inspiration

The idea for this project was inspired by the [encryption-](https://github.com/Reaper-X-art/encryption-) repository by Reaper-X-art.

## Overview

`denc` is a command-line tool for encrypting and decrypting files using a password. It employs a custom XOR-based cipher combined with a key derivation function (PBKDF2) to generate an encryption key from a user-provided password.

## Features

*   **Encryption & Decryption:** Symmetrically encrypt and decrypt files.
*   **Password-Based Key Derivation:** Uses PBKDF2 with HMAC-SHA256 to derive a secure key from a password.
*   **Salting & IV:** Uses a randomly generated salt and initialization vector (IV) for each encryption to enhance security.
*   **Multi-threading:** Utilizes multiple threads to speed up the processing of large files.
*   **Cross-Platform:** Can be built and run on both Linux and Windows.(Theoretically)

## Dependencies

*   **easystd library:** This project depends on the `estd` library. You must compile and install it before building `denc`.

## Building

You can build the project using either `make` or `CMake`.

### Using Make (Linux)

1.  Ensure the `estd` library is installed on your system (e.g., in `/usr/local/lib` and `/usr/local/include`).
2.  Run `make` to build the executable:
    ```sh
    make
    ```
3.  To build with debugging symbols:
    ```sh
    make debug=1
    ```
4.  To clean the build files:
    ```sh
    make clean
    ```

### Using CMake (Cross-Platform)

1.  First, build and install the `estd` library.
2.  Configure and build the `denc` project:
    ```sh
    mkdir build
    cd build
    cmake ..
    cmake --build .
    ```
    The `denc` executable will be created in the project's root directory.

## Usage

The tool is operated via the command line.

```
Usage: denc [OPTIONS] ... [FILES]
Encrypt/Decrypt given files with password using xor

Options:
-p, --password <path to password file>   Provide key that would be used for encryption/decryption
-e, --encypt                             Encrypt data
-d, --decrypt                            Decrypt data
-o, --output                             Set output files
-t, --threads                            Set number of threads to use
-v, --verbose                            Verbosely list files processed
-h, --help                               Display this help and exit
```

### Examples

**1. Encrypt a file:**

Create a file with a password (e.g., `my_secret.key`).

```sh
# Encrypt file.txt, creating file.txt.x
./denc -e -p my_secret.key file.txt
```

Alternatively, you can omit the password file to enter the password interactively:

```sh
# The program will prompt for a password
./denc -e file.txt
```

**2. Decrypt a file:**

```sh
# Decrypt file.txt.x, creating decrypted_file.txt
./denc -d -p my_secret.key -o decrypted_file.txt file.txt.x
```
