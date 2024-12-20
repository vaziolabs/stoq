#ifndef NETWORK_CONTEXT_H
#define NETWORK_CONTEXT_H
#include <stddef.h>
#include <stdint.h>

// Network context structure
typedef struct {
    const char* mode;        // public, private, or federated
    const char* hostname;
    const char* server;
    void* peer_list;        // Will be implemented later
    void* dns_cache;        // Will be implemented later
    void* active_requests;  // Will be implemented later
} network_context_t;


// STOQ packet structure
typedef struct {
    uint8_t version;
    uint8_t type;
    uint64_t session_id;
    uint8_t* data;
    size_t data_len;
} stoq_packet_t;

void check_connection_status(network_context_t *);


#endif