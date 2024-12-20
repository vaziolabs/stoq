#ifndef CERTIFICATE_AUTHORITY_H
#define CERTIFICATE_AUTHORITY_H

#include <stdint.h>
#include "system.h"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "network_context.h"  // For network_context_t definition

// Certificate types
typedef enum {
    CERT_TYPE_SELF_SIGNED,    // For private networks
    CERT_TYPE_FEDERATED,      // For nodes in federated networks
    CERT_TYPE_PUBLIC          // For public network CAs
} cert_type_t;

// Falcon-1024 key structure
typedef struct {
    uint8_t public_key[1793];  // Falcon-1024 public key size
    uint8_t private_key[2305]; // Falcon-1024 private key size
    uint8_t signature[1330];   // Falcon-1024 signature size
} falcon_keys_t;

// Certificate structure
typedef struct {
    uint64_t serial;
    time_t created;
    time_t expires;
    cert_type_t type;
    char* subject;            // Usually hostname
    char* issuer;            // CA or self for private
    falcon_keys_t keys;
    uint8_t* parent_sig;     // NULL for self-signed
    size_t sig_count;        // Number of federation signatures
    uint8_t** fed_sigs;      // Array of federation signatures
} stoq_cert_t;

// CA context structure
typedef struct {
    stoq_cert_t* ca_cert;    // The CA's own certificate
    stoq_cert_t** issued;    // Array of issued certificates
    size_t issued_count;
    pthread_mutex_t lock;     // Thread safety for cert operations
} ca_context_t;

// Function declarations
int init_certificate_authority(network_context_t* net_ctx, ca_context_t** ca_ctx);
int handle_cert_request(ca_context_t* ca, const char* hostname, stoq_cert_t** cert);
int save_certificate(stoq_cert_t* cert, const char* filename);
stoq_cert_t* load_certificate(const char* filename);
void free_certificate(stoq_cert_t* cert);
int verify_certificate(stoq_cert_t* cert, ca_context_t* ca);
int sign_certificate(stoq_cert_t* cert, ca_context_t* ca);
int add_federation_signature(stoq_cert_t* cert, const uint8_t* signature);

#endif