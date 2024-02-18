#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int main() {
    // use private key d and n from task 1
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BN_hex2bn(&d, "1A87C31CA14E9E34D1CD5B8816A148E3ACD85243B09");
    BN_hex2bn(&n, "1FBF5EEC7EF3A71C2754B2E0EE10767154C2053CDEB");

    // message given in task 4
    char *message = "I owe you $100";
    char hex_message[1000] = {0};

    //loop through hex char array and convert to a ASCII 
    for (int i = 0; i < strlen(message); i++) {
        sprintf(hex_message + strlen(hex_message), "%02X", message[i]);
    }

    // get big num from hex
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, hex_message);

    // sign the message
    BIGNUM *signature = BN_new();
    BN_mod_exp(signature, m, d, n, BN_CTX_new());

    printf("Signature: ");
    BN_print_fp(stdout, signature);
    printf("\n");

    //free the mem
    BN_free(d);
    BN_free(n);
    BN_free(m);
    BN_free(signature);

    return 0;
}

