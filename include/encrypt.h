#ifndef ENCRYPT_H
#define ENCRYPT_H

typedef struct string string;
typedef struct freader freader;
typedef struct fwriter fwriter;

int encrypt_decrypt(const string *key, freader *source, fwriter *output);

#endif // ENCRYPT_H
