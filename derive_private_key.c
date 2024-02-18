
/**
 * Let p, q, and e be three prime numbers. Let n = p*q. We will use (e, n) as the public key. 
 * The hexadecimal values of p, q, and e are listed below. 
 * Although the p and q below are quite large, they are not large enough to be secure. 
 * We intentionally make them small for simplicity. In practice, these numbers should be at least 2048 bits long.
 * 
 * What is the bit length of modulus n
 * 
 * Calculate the private key
*/

#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *e;
    BIGNUM *n;
} RSAParams;

RSAParams store_rsa_params(char *p, char *q, char *e) {
    RSAParams params;
    params.p = BN_new();
    params.q = BN_new();
    params.e = BN_new();
    params.n = BN_new();

    //convert to big number
    BN_hex2bn(&params.p, p);
    BN_hex2bn(&params.q, q);
    BN_hex2bn(&params.e, e);

    BN_mul(params.n, params.p, params.q, BN_CTX_new());

    return params;
}

int main() {
    char *p_hex = "879a5ee58ade33942040f";
    char *q_hex = "3bef5e448f18ae4ff08c65";
    char *e_hex = "10001";

    RSAParams params = store_rsa_params(p_hex, q_hex, e_hex);

    //calulte the totient, (p-1)*(q-1)
    BIGNUM *p1 = BN_dup(params.p);
    BIGNUM *q1 = BN_dup(params.q);
    BN_sub_word(p1, 1);
    BN_sub_word(q1, 1);

    BIGNUM *totient_result = BN_new();
    BN_mul(totient_result, p1, q1, BN_CTX_new());

    //calc private key d
    BIGNUM *d = BN_new();
    BN_mod_inverse(d, params.e, totient_result, BN_CTX_new());



    printf("n = ");
    BN_print_fp(stdout, params.n);
    printf("\n");

    //print length of n
    int length = BN_num_bits(params.n);
    printf("Length of n: %d bits\n", length);
    printf("\n");

    printf("The private key is: \nd = ");
    BN_print_fp(stdout, d);
    printf("\n");

    //clean up 
    BN_free(params.p);
    BN_free(params.q);
    BN_free(params.e);
    BN_free(params.n);
    BN_free(p1);
    BN_free(q1);
    BN_free(totient_result);
    BN_free(d);
    BN_CTX_free(BN_CTX_new());

    return 0;
}


