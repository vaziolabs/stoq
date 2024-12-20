#include "network_context.h"
#include "debug.h"
#include <string.h>
// Add connection status check
void check_connection_status(network_context_t *net_ctx) {
    dlog("Starting connection check...");
    
    // Print basic node info
    dlog("Node Status:");
    dlog("Mode: %s", net_ctx->mode);
    dlog("Hostname: %s", net_ctx->hostname);
    dlog("Server: %s", net_ctx->server);
    
    // Add connection test
    if (strcmp(net_ctx->mode, "private") == 0) {
        dlog("Private mode - listening for incoming connections");
    } else if (strcmp(net_ctx->mode, "public") == 0) {
        dlog("Public mode - attempting to connect to known peers");
    } else if (strcmp(net_ctx->mode, "federated") == 0) {
        dlog("Federated mode - connecting to federation network");
    }
}