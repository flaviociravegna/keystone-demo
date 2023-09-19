#include <stdbool.h>

#define LAK_PUB_LEN 32
#define MAX_CERT_LEN 512

bool verify_cert_chain(
    unsigned char *sm_cert_par,
    unsigned char *root_cert_par,
    unsigned char *man_cert_par,
    unsigned char *lak_cert_par,
    int sm_cert_len,
    int root_cert_len,
    int man_cert_len,
    int lak_cert_len
);

bool extract_lak_pub_from_x509_crt(unsigned char *lak_cert_par, int lak_cert_len, unsigned char *lak_pub);