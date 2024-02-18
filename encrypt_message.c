/**
 * Encrypt the message i<3crypto using thepublickey(e, n) fromTask1.
 * You will first need to convert the message from ASCII to hexadecimal, and then convert the hexadecimal number to a BIGNUM using BN hex2bn().
*/

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int main() {
    // n and e from task 1
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BN_hex2bn(&e, "10001");
    BN_hex2bn(&n, "1FBF5EEC7EF3A71C2754B2E0EE10767154C2053CDEB");

    //message to encrypt
    char *message = "i<3crypto";
    char hex_message[1000] = {0}; //array to store each hex char in

    //loop through and get the hex char for each char
    for (int i = 0; i < strlen(message); i++) {
        sprintf(hex_message + strlen(hex_message), "%02X", message[i]);
    }

    
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, hex_message); //convert to hex

   
   //encrypt the message
    BIGNUM *c = BN_new();
    BN_mod_exp(c, m, e, n, BN_CTX_new());

    // Print the encrypted message
    printf("Encryptoed message: ");
    BN_print_fp(stdout, c);
    printf("\n");

    // free up mem
    BN_free(e);
    BN_free(n);
    BN_free(m);
    BN_free(c);

    return 0;
}
