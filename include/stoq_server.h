#ifndef STOQ_SERVER_H
#define STOQ_SERVER_H

#include "network_context.h"
#include "certificate_authority.h"
#include <stdint.h>
#include <ngtcp2/ngtcp2.h>
#include <openssl/ssl.h>

// QUIC server settings
typedef struct {
    const char *bind_address;
    int port;
    ca_context_t *ca_ctx;
    stoq_cert_t *cert;
    falcon_keys_t *keys;
    SSL_CTX *ssl_ctx;        // SSL context for QUIC
    SSL *ssl;                // SSL object for QUIC
    ngtcp2_conn *conn;        // QUIC connection
    ngtcp2_cid dcid;         // Destination Connection ID
    ngtcp2_cid scid;         // Source Connection ID
    int sock;
} stoq_server_config_t;

// Custom certificate verification callback
int verify_falcon_cert_callback(int preverify_ok, X509_STORE_CTX *ctx);

int init_stoq_server(stoq_server_config_t*, network_context_t*);

// Add this function declaration
int stoq_server_process_events(stoq_server_config_t *config);

#endif