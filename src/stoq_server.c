#include "stoq_server.h"
#include "certificate_authority.h"
#include "network_context.h"
#include "debug.h"
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>


// Forward declarations with correct return types and parameters
static int on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
    (void)conn;      // Suppress unused parameter warning
    (void)user_data; // Suppress unused parameter warning
    dlog("New stream opened: %ld", stream_id);
    return 0;  // Return success
}

static int on_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t offset, const uint8_t *data, 
                         size_t datalen, void *user_data, void *stream_user_data) {
    (void)conn;              // Suppress unused parameter warning
    (void)flags;            // Suppress unused parameter warning
    (void)offset;           // Suppress unused parameter warning
    (void)user_data;        // Suppress unused parameter warning
    (void)stream_user_data; // Suppress unused parameter warning
    
    dlog("Received %zu bytes on stream %ld", datalen, stream_id);
    return 0;  // Return success
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
    (void)conn;
    (void)user_data;
    dlog("Server handshake completed");
    return 0;
}

static int on_receive_client_initial(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data) {
    (void)conn;
    (void)dcid;
    (void)user_data;
    dlog("Received client initial packet");
    return 0;
}

// Custom certificate verification that uses our Falcon certs
int verify_falcon_cert_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    (void)preverify_ok;  // Suppress unused parameter warning
    stoq_cert_t *falcon_cert = X509_STORE_CTX_get_ex_data(ctx, 0);
    ca_context_t *ca_ctx = X509_STORE_CTX_get_ex_data(ctx, 1);
    
    // Verify using Falcon instead of X509
    return verify_certificate(falcon_cert, ca_ctx);
}

int init_stoq_server(stoq_server_config_t *config, network_context_t *net_ctx) {
    if (!config || !net_ctx) return -1;

    // Initialize certificate authority
    ca_context_t *ca_ctx = NULL;
    if (init_certificate_authority(net_ctx, &ca_ctx) != 0) {
        dlog("Failed to initialize certificate authority");
        return -1;
    }

    // Request server certificate from CA
    stoq_cert_t *server_cert = NULL;
    if (handle_cert_request(ca_ctx, net_ctx->hostname, &server_cert) != 0) {
        dlog("Failed to obtain server certificate");
        return -1;
    }

    // Store certificate in config
    config->ca_ctx = ca_ctx;
    config->cert = server_cert;
    
    // Generate or load Falcon-1024 keys
    falcon_keys_t *keys = malloc(sizeof(falcon_keys_t));
    if (!keys) {
        free_certificate(server_cert);
        return -1;
    }
    
    // Copy keys from certificate
    memcpy(keys, &server_cert->keys, sizeof(falcon_keys_t));
    config->keys = keys;

    dlog("Server certificate initialized (serial: %u)", server_cert->serial);

    // Initialize QUIC settings
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    
    // Setup QUIC callbacks
    ngtcp2_callbacks callbacks = {0};
    callbacks.stream_open = on_stream_open;
    callbacks.recv_stream_data = on_stream_data;
    callbacks.handshake_completed = on_handshake_completed;
    callbacks.recv_client_initial = on_receive_client_initial;
    
    // Generate connection IDs
    uint8_t dcid_data[NGTCP2_MAX_CIDLEN];
    uint8_t scid_data[NGTCP2_MAX_CIDLEN];
    size_t dcid_len = 18;
    size_t scid_len = 18;
    
    // Initialize CIDs with random data
    if (RAND_bytes(dcid_data, dcid_len) != 1 ||
        RAND_bytes(scid_data, scid_len) != 1) {
        dlog("Failed to generate random CID data");
        return -1;
    }
    
    ngtcp2_cid_init(&config->dcid, dcid_data, dcid_len);
    ngtcp2_cid_init(&config->scid, scid_data, scid_len);
    
    // Set up QUIC connection
    if (ngtcp2_conn_server_new(&config->conn,          // Connection object
                              &config->dcid,           // Destination Connection ID
                              &config->scid,           // Source Connection ID
                              NULL,                    // Path (ngtcp2 handles this)
                              NGTCP2_PROTO_VER_MAX,    // QUIC version
                              &callbacks,              // Callbacks
                              &settings,               // Settings
                              NULL,                    // Transport params
                              NULL,                    // Memory allocator
                              NULL) != 0) {            // User data
        dlog("Failed to create QUIC connection");
        return -1;
    }

    // Create UDP socket
    config->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (config->sock < 0) {
        dlog("Failed to create server socket");
        return -1;
    }

    // Set non-blocking
    int flags = fcntl(config->sock, F_GETFL, 0);
    fcntl(config->sock, F_SETFL, flags | O_NONBLOCK);

    // Bind socket
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(config->port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(config->sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        dlog("Failed to bind server socket");
        close(config->sock);
        return -1;
    }

    dlog("Server socket bound to port %d", config->port);
    return 0;
}

int stoq_server_process_events(stoq_server_config_t *config) {
    if (!config) return -1;

    // Handle incoming packets
    uint8_t buf[65535];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    ssize_t nread = recvfrom(config->sock, buf, sizeof(buf), 0,
                            (struct sockaddr*)&client_addr, &client_len);
    
    if (nread > 0) {
        ngtcp2_path path = {
            .local = {
                .addr = (struct sockaddr*)&client_addr,
                .addrlen = client_len
            },
            .remote = {
                .addr = (struct sockaddr*)&client_addr,
                .addrlen = client_len
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
                   (struct sockaddr*)&client_addr, client_len);
        }
    }

    return 0;
}
