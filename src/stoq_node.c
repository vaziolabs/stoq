#include "stoq_node.h"
#include "stoq_server.h"
#include "stoq_client.h"
#include "network_context.h"
#include "certificate_authority.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>


int init_node(network_context_t *net_ctx, ca_context_t *ca_ctx, 
             int server_port, int client_port, stoq_node_t **out_node) {
    dlog("Starting node initialization");
    
    // Allocate node structure on heap so it persists
    stoq_node_t *node = malloc(sizeof(stoq_node_t));
    if (!node) {
        fprintf(stderr, "Failed to allocate node structure\n");
        return 1;
    }

    dlog("Node structure allocated");

    // Initialize node structure
    *node = (stoq_node_t){
        .server_config = {
            .bind_address = net_ctx->hostname,
            .port = server_port,
        },
        .client_config = {
            .bind_address = net_ctx->hostname,
            .port = client_port
        },
        .net_ctx = net_ctx,
        .running = 1,
        .server_connected = 0,
        .client_connected = 0
    };

    dlog("Node structure initialized");

    // Start server thread
    if (pthread_create(&node->server_thread, NULL, server_thread_func, node) != 0) {
        fprintf(stderr, "Failed to start server thread\n");
        free(node);
        return 1;
    }

    dlog("Server thread started");

    // Start client thread
    if (pthread_create(&node->client_thread, NULL, client_thread_func, node) != 0) {
        fprintf(stderr, "Failed to start client thread\n");
        node->running = 0;
        pthread_join(node->server_thread, NULL);
        free(node);
        return 1;
    }

    dlog("Client thread started");

    // Set output parameter
    *out_node = node;
    dlog("Node initialization complete");
    return 0;
}

void* server_thread_func(void* arg) {
    stoq_node_t* node = (stoq_node_t*)arg;
    
    printf("Starting STOQ server on port %d\n", node->server_config.port);
    
    if (init_stoq_server(&node->server_config, node->net_ctx) != 0) {
        fprintf(stderr, "Failed to initialize QUIC server\n");
        node->running = 0;
        return NULL;
    }

    dlog("Server initialized and listening");
    
    while (node->running) {
        int ret = stoq_server_process_events(&node->server_config);
        if (ret < 0) {
            dlog("Server error processing events");
            break;
        }
        
        // Check connection state
        if (ngtcp2_conn_get_handshake_completed(node->server_config.conn)) {
            if (!node->server_connected) {
                node->server_connected = 1;
                dlog("Server connection established");
            }
        }

        usleep(1000); // Small sleep to prevent CPU spinning
    }

    return NULL;
}


void* client_thread_func(void* arg) {
    stoq_node_t* node = (stoq_node_t*)arg;
    
    printf("Starting STOQ client on port %d\n", node->client_config.port);

    if (strcmp(node->net_ctx->mode, "federated") == 0 || 
        strcmp(node->net_ctx->mode, "private") == 0) {
        
        if (strlen(node->net_ctx->server) > 0 && 
            strcmp(node->net_ctx->server, node->net_ctx->hostname) != 0) {
            
            dlog("Initializing client connection to %s", node->net_ctx->server);
            
            if (init_stoq_client(node->net_ctx, 
                               node->net_ctx->server, 
                               node->server_config.port,
                               &node->client_config) != 0) {
                dlog("Failed to initialize client");
                node->running = 0;
                return NULL;
            }

            dlog("Client initialized, attempting connection");
            
            if (stoq_client_connect(&node->client_config) != 0) {
                dlog("Failed to connect to server");
                node->running = 0;
                return NULL;
            }

            dlog("Client connection initiated");
        }
    }

    while (node->running) {
        int ret = stoq_client_process_events(&node->client_config);
        if (ret < 0) {
            dlog("Client error processing events");
            break;
        }
        
        // Check connection state
        if (ngtcp2_conn_get_handshake_completed(node->client_config.conn)) {
            if (!node->client_connected) {
                node->client_connected = 1;
                dlog("Client connection established");
            }
        }

        usleep(1000);
    }

    return NULL;
}

void cleanup_node(stoq_node_t *node) {
    if (!node) return;

    // Signal threads to stop
    node->running = 0;

    // Wait for threads to finish
    pthread_join(node->server_thread, NULL);
    pthread_join(node->client_thread, NULL);

    // Cleanup server
    if (node->server_config.conn) {
        ngtcp2_conn_del(node->server_config.conn);
    }
    if (node->server_config.sock > 0) {
        close(node->server_config.sock);
    }

    // Cleanup client
    if (node->client_config.conn) {
        ngtcp2_conn_del(node->client_config.conn);
    }
    if (node->client_config.sock > 0) {
        close(node->client_config.sock);
    }

    free(node);
}