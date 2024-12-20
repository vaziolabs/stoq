#include "stoq_client.h"
#include "stoq_server.h"
#include "network_context.h"
#include "certificate_authority.h"
#include "debug.h"
#include "system.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

// Add these callback declarations at the top
static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Client handshake completed");
    return 0;
}

static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Sending client initial packet");
    return 0;
}

int init_stoq_client(network_context_t *net_ctx, const char *remote_addr, uint16_t port, 
                    stoq_client_config_t *config) {
    if (!remote_addr || !net_ctx || !config) return -1;
    dlog("Initializing client");

    // Initialize the provided config structure
    memset(config, 0, sizeof(stoq_client_config_t));

    // For private mode, clients also need a certificate
    ca_context_t *ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        dlog("Failed to initialize certificate authority");
        return -1;
    }

    // Request client certificate from CA
    stoq_cert_t *client_cert = NULL;
    if (handle_cert_request(ca_ctx, net_ctx->hostname, &client_cert) != 0) {
        dlog("Failed to obtain client certificate");
        return -1;
    }

    // Initialize QUIC settings
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);

    // Setup QUIC callbacks
    ngtcp2_callbacks callbacks = {0};
    callbacks.client_initial = on_client_initial;
    callbacks.handshake_completed = on_handshake_completed;
    
    // Generate connection IDs
    uint8_t dcid_data[NGTCP2_MAX_CIDLEN];
    uint8_t scid_data[NGTCP2_MAX_CIDLEN];
    size_t dcid_len = 18;  // Typical QUIC CID length
    size_t scid_len = 18;
    ngtcp2_cid dcid, scid;
    
    // Initialize CIDs with random data
    RAND_bytes(dcid_data, dcid_len);
    RAND_bytes(scid_data, scid_len);
    
    // Properly initialize CIDs with data and length
    ngtcp2_cid_init(&dcid, dcid_data, dcid_len);
    ngtcp2_cid_init(&scid, scid_data, scid_len);

    // Set up QUIC connection with custom cert handling
    ngtcp2_conn *conn = NULL;
    if (ngtcp2_conn_client_new(&conn,          // Connection object
                              &dcid,           // Destination Connection ID
                              &scid,           // Source Connection ID
                              NULL,            // Path (ngtcp2 will handle this)
                              NGTCP2_PROTO_VER_MAX, // QUIC version
                              &callbacks,      // Callbacks
                              &settings,       // Settings
                              NULL,           // Transport params
                              NULL,           // Memory allocator
                              NULL) != 0) {    // User data
        dlog("Failed to create QUIC connection");
        return -1;
    }

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        dlog("Failed to create client socket");
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Connect to server
    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(remote_addr)
    };

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        dlog("Failed to connect to server");
        close(sock);
        return -1;
    }

    dlog("Client socket connected to %s:%d", remote_addr, port);

    // Store values directly in the provided config
    config->conn = conn;
    config->sock = sock;
    config->bind_address = strdup(remote_addr);
    config->port = port;
    config->ca_ctx = ca_ctx;
    config->cert = client_cert;

    dlog("Client initialization complete");
    return 0;
}

int stoq_client_connect(stoq_client_config_t *config) {
    if (!config) return -1;
    dlog("Starting QUIC handshake");

    // Prepare initial packet
    uint8_t buf[65535];
    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    
    ngtcp2_pkt_info pi = {0};
    
    // Write initial packet
    ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pi,
                                     buf, sizeof(buf), get_timestamp());
    
    if (n > 0) {
        // Send initial packet
        struct sockaddr_in server_addr = {
            .sin_family = AF_INET,
            .sin_port = htons(config->port),
            .sin_addr.s_addr = inet_addr(config->bind_address)
        };
        
        ssize_t sent = sendto(config->sock, buf, n, 0,
                             (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        if (sent < 0) {
            dlog("Failed to send initial packet");
            return -1;
        }
        
        dlog("Sent initial handshake packet (%zd bytes)", sent);
    }

    return 0;
}

int stoq_client_process_events(stoq_client_config_t *config) {
    if (!config) return -1;

    // Handle incoming packets
    uint8_t buf[65535];
    struct sockaddr_in server_addr;
    socklen_t server_len = sizeof(server_addr);
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&server_addr, &server_len);
    
    if (nread > 0) {
        ngtcp2_path path = {
            .local = {
                .addr = (struct sockaddr*)&server_addr,
                .addrlen = server_len
            },
            .remote = {
                .addr = (struct sockaddr*)&server_addr,
                .addrlen = server_len
            }
        };

        ngtcp2_pkt_info pi = {0};
        ngtcp2_conn_read_pkt(config->conn, &path, &pi, buf, nread, get_timestamp());

        // Send any pending data
        uint8_t send_buf[65535];
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        
        ngtcp2_pkt_info pktinfo = {0};
        
        // Try to send data
        ssize_t n = ngtcp2_conn_write_pkt(config->conn, &ps.path, &pktinfo,
                                         send_buf, sizeof(send_buf), get_timestamp());
        
        if (n > 0) {
            sendto(config->sock, send_buf, n, 0,
                   (struct sockaddr*)&server_addr, server_len);
        }
    }

    return 0;
}

