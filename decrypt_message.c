#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

int main() {
    // private key and n from first task
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BN_hex2bn(&d, "1A87C31CA14E9E34D1CD5B8816A148E3ACD85243B09");
    BN_hex2bn(&n, "1FBF5EEC7EF3A71C2754B2E0EE10767154C2053CDEB");

    // encrypted message c given in task 3
    BIGNUM *c = BN_new();
    BN_hex2bn(&c, "0182c38e75c5a4889ec3c8da3602114b42e1d2cc9e58");

   // decrypt thne encyrpted text with the private key d
    BIGNUM *m = BN_new();
    BN_mod_exp(m, c, d, n, BN_CTX_new());

    // cast from BIGNUM to a hexadecimal string
    char *hex_message = BN_bn2hex(m);

    // get it as an ASCII string
    char ascii_message[500] = {0};
    for (int i = 0, j = 0; i < strlen(hex_message); i += 2, j++) {
        sscanf(hex_message + i, "%2hhx", &ascii_message[j]);
    }

    printf("Decrypted message: %s\n", ascii_message);

    // freem upo the mem
    BN_free(d);
    BN_free(n);
    BN_free(c);
    BN_free(m);
    OPENSSL_free(hex_message);

    return 0;
}
