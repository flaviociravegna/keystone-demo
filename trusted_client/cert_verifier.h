#include <stdbool.h>

bool verify_cert_chain(unsigned char *sm_cert_par, unsigned char *root_cert_par, unsigned char *man_cert_par, int sm_cert_len, int root_cert_len, int man_cert_len);
