#ifndef STOQ_NODE_H
#define STOQ_NODE_H

#include "stoq_server.h"
#include "stoq_client.h"
#include "network_context.h"
#include "certificate_authority.h"
#include <pthread.h>

typedef struct {
    stoq_server_config_t server_config;
    stoq_client_config_t client_config;
    network_context_t *net_ctx;
    pthread_t server_thread;
    pthread_t client_thread;
    volatile int running;
    volatile int server_connected;
    volatile int client_connected;
} stoq_node_t;

// Initialize node and return the node pointer through the last parameter
int init_node(network_context_t* net_ctx, ca_context_t* ca_ctx, 
             int server_port, int client_port, stoq_node_t** node);

// Add thread function prototypes
void* server_thread_func(void*);
void* client_thread_func(void*);

// Add cleanup function declaration
void cleanup_node(stoq_node_t* node);

#endif