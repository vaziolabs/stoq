#ifndef STOQ_CLIENT_H
#define STOQ_CLIENT_H

#include "network_context.h"
#include "certificate_authority.h"
#include <ngtcp2/ngtcp2.h>
#include <stdint.h>

typedef struct {
    ngtcp2_conn *conn;
    int sock;
    char *bind_address;
    uint16_t port;
    ca_context_t *ca_ctx;
    stoq_cert_t *cert;
} stoq_client_config_t;

// Update function declaration to match implementation
int init_stoq_client(network_context_t *net_ctx, const char *remote_addr, 
                    uint16_t port, stoq_client_config_t *config);

int stoq_client_connect(stoq_client_config_t *config);
int stoq_client_process_events(stoq_client_config_t *config);

#endif // STOQ_CLIENT_H