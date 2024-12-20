#include <ngtcp2/ngtcp2.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "system.h"
#include <getopt.h>
#include <sys/stat.h>
#include "certificate_authority.h"
#include "stoq_node.h"
#include <signal.h>

// Add global variable for clean shutdown
static volatile int global_running = 1;

// Add signal handler
static void handle_signal(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        global_running = 0;
    }
}

// Add these new definitions
#define STOQ_SERVER_PORT 10053
#define STOQ_CLIENT_PORT 10443
#define MAX_PENDING_CONNECTIONS 10

void print_usage() {
    printf("Usage: stoq [OPTIONS]\n");
    printf("Options:\n");
    printf("  --mode      <public|private|federated>  Node mode (default: private)\n");
    printf("  --hostname  <hostname>                  Node hostname (default: localhost)\n");
    printf("  --server  <server>                  Server server (default: localhost)\n");
    printf("  --help                                  Show this help message\n");
}

int main(int argc, char *argv[]) {
    // Default values
    const char* node_mode = "private";
    const char* node_hostname = "localhost";
    const char* node_server = "localhost";

    // Define long options
    static struct option long_options[] = {
        {"mode",     required_argument, 0, 'm'},
        {"hostname", required_argument, 0, 'h'},
        {"server", required_argument, 0, 'e'},
        {"help",     no_argument,       0, '?'},
        {0, 0, 0, 0}
    };

    // Parse command line arguments
    int opt;
    while ((opt = getopt_long(argc, argv, "m:h:e:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "public") == 0 || 
                    strcmp(optarg, "private") == 0 || 
                    strcmp(optarg, "federated") == 0) {
                    node_mode = optarg;
                } else {
                    fprintf(stderr, "Invalid mode: %s\n", optarg);
                    print_usage();
                    return 1;
                }
                break;
            case 'h':
                node_hostname = optarg;
                break;
            case 'e':
                node_server = optarg;
                break;
            case '?':
                print_usage();
                return 0;
            default:
                print_usage();
                return 1;
        }
    }

    // Update the network context initialization
    network_context_t net_ctx = {
        .mode = node_mode,
        .hostname = node_hostname,
        .server = node_server,
        .peer_list = NULL,
        .dns_cache = NULL,
        .active_requests = NULL
    };

    printf("Initializing STOQ node\n");
    printf("Mode: %s\n", node_mode);
    printf("Hostname: %s\n", node_hostname);
    printf("Server: %s\n", node_server);

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Initialize CA before starting network threads
    ca_context_t* ca_ctx;
    if (init_certificate_authority(&net_ctx, &ca_ctx) != 0) {
        fprintf(stderr, "Failed to initialize certificate authority\n");
        return 1;
    }

    printf("Initializing node\n");
    stoq_node_t *node;
    int status = init_node(&net_ctx, ca_ctx, STOQ_SERVER_PORT, STOQ_CLIENT_PORT, &node);
    if (status != 0) {
        fprintf(stderr, "Failed to initialize node\n");
        return 1;
    }

    printf("Node running. Press Ctrl+C to stop.\n");

    // Keep main thread running until signal received
    while (global_running) {
        sleep(1);
    }

    printf("\nShutting down...\n");
    cleanup_node(node);

    return 0;
}

