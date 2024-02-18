#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int main() {
    // use e and n from the task 5 description
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "ae1cd4dc432798d933779fbd46c6e1247f0cf1233595113aa51b450f18116115");

    //message and signature hash
    char *message = "Launch a missile.";
    char *sig_hash = "643d6f34902d9c7ec90cb0b2bca36c47fa37165c0005cab026c0542cbdb6802f";

    // get the signature in BIGNUM
    BIGNUM *sig = BN_new();
    BN_hex2bn(&sig, sig_hash);

    // decrypt the sig
    BIGNUM *decrypted_sig = BN_new();
    BN_mod_exp(decrypted_sig, sig, e, n, BN_CTX_new());

    // get the message into a char array and convert it for comparision
    char sig_arr[1000] = {0};
    for (int i = 0; i < strlen(message); i++) {
        sprintf(sig_arr + strlen(sig_arr), "%02X", message[i]);
    }

    // we can now compare the sigs
    int match = strcmp(sig_arr, BN_bn2hex(decrypted_sig));

    //print if the signature comparison isn 0 then return teh signature is valid
    if (match == 0) {
        printf("This is a valid sig\n");
    } else {
        printf("not a valid sig\n");
    }


    char *corrupted_hash= "643d6f34902d9c7ec90cb0b2bca36c47fa37165c0005cab026c0542cbdb6803f"; //changed to 3f

    // get the corrpetd signature in BIGNUM
    BIGNUM *corrupted_sig = BN_new();
    BN_hex2bn(&corrupted_sig, corrupted_hash);

    // decrypt the corroprted sig
    BIGNUM *decrypted_corrupted_sig = BN_new();
    BN_mod_exp(decrypted_corrupted_sig, corrupted_sig, e, n, BN_CTX_new());


    // we can now compare the sigs
    int corrupted_match= strcmp(sig_arr, BN_bn2hex(decrypted_corrupted_sig));

    //print if the signature comparison isn 0 then return teh signature is valid
    if (corrupted_match == 0) {
        printf("The corrupted sig is valid\n");
    } else {
        printf("corrpted sig is not valid\n");
    }


    // free mem
    BN_free(e);
    BN_free(n);
    BN_free(sig);
    BN_free(decrypted_sig);
    BN_free(corrupted_sig);
    BN_free(decrypted_corrupted_sig);

    return 0;
}
