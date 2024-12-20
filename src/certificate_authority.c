#include "certificate_authority.h"
#include "debug.h"
#include <stdio.h>

// Initialize certificate authority
int init_certificate_authority(network_context_t* net_ctx, ca_context_t** ca_ctx) {
    *ca_ctx = malloc(sizeof(ca_context_t));
    if (!*ca_ctx) return -1;
    
    ca_context_t* ca = *ca_ctx;
    pthread_mutex_init(&ca->lock, NULL);
    ca->issued = NULL;
    ca->issued_count = 0;
    
    // Check for existing CA certificate
    if (access("ca.cert", F_OK) != 0) {
        dlog(net_ctx->mode, "No existing CA certificate found. Creating new CA...");
        
        // Generate new Falcon-1024 keypair
        ca->ca_cert = malloc(sizeof(stoq_cert_t));
        if (!ca->ca_cert) {
            free(*ca_ctx);
            return -1;
        }
        
        // Initialize new CA certificate
        memset(&ca->ca_cert->keys, 0, sizeof(falcon_keys_t));
        ca->ca_cert->serial = 1;
        ca->ca_cert->created = time(NULL);
        ca->ca_cert->expires = ca->ca_cert->created + (365 * 24 * 60 * 60);
        ca->ca_cert->subject = strdup(net_ctx->hostname);
        ca->ca_cert->issuer = strdup(net_ctx->hostname);
        ca->ca_cert->parent_sig = NULL;
        ca->ca_cert->sig_count = 0;
        ca->ca_cert->fed_sigs = NULL;
        
        // Set certificate type based on mode
        if (strcmp(net_ctx->mode, "private") == 0) {
            ca->ca_cert->type = CERT_TYPE_SELF_SIGNED;
        } else if (strcmp(net_ctx->mode, "federated") == 0) {
            ca->ca_cert->type = CERT_TYPE_FEDERATED;
        } else {
            ca->ca_cert->type = CERT_TYPE_PUBLIC;
        }
        
        if (save_certificate(ca->ca_cert, "ca.cert") != 0) {
            free_certificate(ca->ca_cert);
            free(*ca_ctx);
            return -1;
        }
    } else {
        dlog(net_ctx->mode, "Loading existing CA certificate...");
        ca->ca_cert = load_certificate("ca.cert");
        if (!ca->ca_cert) {
            free(*ca_ctx);
            return -1;
        }
    }
    
    return 0;
}

// Handle certificate requests
int handle_cert_request(ca_context_t* ca, const char* hostname, stoq_cert_t** cert) {
    if (!ca || !hostname || !cert) return -1;
    
    pthread_mutex_lock(&ca->lock);
    
    *cert = malloc(sizeof(stoq_cert_t));
    if (!*cert) {
        pthread_mutex_unlock(&ca->lock);
        return -1;
    }
    
    stoq_cert_t* new_cert = *cert;
    memset(new_cert, 0, sizeof(stoq_cert_t));
    
    // Initialize certificate fields
    new_cert->serial = ca->ca_cert->serial + 1;
    new_cert->created = time(NULL);
    new_cert->expires = new_cert->created + (30 * 24 * 60 * 60);
    new_cert->subject = strdup(hostname);
    new_cert->issuer = strdup(ca->ca_cert->subject);
    new_cert->type = ca->ca_cert->type;
    
    // Sign the certificate
    if (sign_certificate(new_cert, ca) != 0) {
        free_certificate(new_cert);
        pthread_mutex_unlock(&ca->lock);
        return -1;
    }
    
    // Add to issued certificates list
    ca->issued = realloc(ca->issued, (ca->issued_count + 1) * sizeof(stoq_cert_t*));
    if (!ca->issued) {
        free_certificate(new_cert);
        pthread_mutex_unlock(&ca->lock);
        return -1;
    }
    
    ca->issued[ca->issued_count++] = new_cert;
    
    pthread_mutex_unlock(&ca->lock);
    return 0;
}

// Save certificate to file
int save_certificate(stoq_cert_t* cert, const char* filename) {
    if (!cert || !filename) return -1;
    
    FILE* f = fopen(filename, "wb");
    if (!f) return -1;
    
    // Write certificate data
    fwrite(&cert->serial, sizeof(uint32_t), 1, f);
    fwrite(&cert->created, sizeof(time_t), 1, f);
    fwrite(&cert->expires, sizeof(time_t), 1, f);
    fwrite(&cert->type, sizeof(int), 1, f);
    
    // Write strings
    size_t len;
    len = strlen(cert->subject) + 1;
    fwrite(&len, sizeof(size_t), 1, f);
    fwrite(cert->subject, 1, len, f);
    
    len = strlen(cert->issuer) + 1;
    fwrite(&len, sizeof(size_t), 1, f);
    fwrite(cert->issuer, 1, len, f);
    
    fclose(f);
    return 0;
}

// Load certificate from file
stoq_cert_t* load_certificate(const char* filename) {
    if (!filename) return NULL;
    
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    
    stoq_cert_t* cert = malloc(sizeof(stoq_cert_t));
    if (!cert) {
        fclose(f);
        return NULL;
    }
    
    // Read certificate data
    fread(&cert->serial, sizeof(uint32_t), 1, f);
    fread(&cert->created, sizeof(time_t), 1, f);
    fread(&cert->expires, sizeof(time_t), 1, f);
    fread(&cert->type, sizeof(int), 1, f);
    
    // Read strings
    size_t len;
    fread(&len, sizeof(size_t), 1, f);
    cert->subject = malloc(len);
    fread(cert->subject, 1, len, f);
    
    fread(&len, sizeof(size_t), 1, f);
    cert->issuer = malloc(len);
    fread(cert->issuer, 1, len, f);
    
    // Initialize other fields
    cert->parent_sig = NULL;
    cert->sig_count = 0;
    cert->fed_sigs = NULL;
    memset(&cert->keys, 0, sizeof(falcon_keys_t));
    
    fclose(f);
    return cert;
}

// Free certificate memory
void free_certificate(stoq_cert_t* cert) {
    if (!cert) return;
    
    free(cert->subject);
    free(cert->issuer);
    free(cert->parent_sig);
    if (cert->fed_sigs) {
        for (size_t i = 0; i < cert->sig_count; i++) {
            free(cert->fed_sigs[i]);
        }
        free(cert->fed_sigs);
    }
    free(cert);
}

// Sign a certificate using the CA's key
int sign_certificate(stoq_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca) return -1;
    
    // TODO: Implement actual Falcon-1024 signing
    // For now, just increment the CA's serial number
    ca->ca_cert->serial++;
    
    return 0;
}

// Verify a certificate against the CA
int verify_certificate(stoq_cert_t* cert, ca_context_t* ca) {
    if (!cert || !ca) return -1;
    
    // Check expiration
    time_t now = time(NULL);
    if (now > cert->expires) {
        dlog("Certificate expired");
        return -1;
    }
    
    // For self-signed certificates
    if (cert->type == CERT_TYPE_SELF_SIGNED) {
        // Verify the certificate is its own issuer
        if (strcmp(cert->subject, cert->issuer) != 0) {
            dlog("Self-signed certificate has mismatched subject/issuer");
            return -1;
        }
        return 0;
    }
    
    // For CA-issued certificates
    if (strcmp(cert->issuer, ca->ca_cert->subject) != 0) {
        dlog("Certificate issuer doesn't match CA");
        return -1;
    }
    
    // TODO: Implement actual Falcon-1024 signature verification
    // For now, just check that the certificate is in our issued list
    for (size_t i = 0; i < ca->issued_count; i++) {
        if (cert->serial == ca->issued[i]->serial) {
            return 0;
        }
    }
    
    dlog("Certificate not found in CA's issued list");
    return -1;
}