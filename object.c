// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stor>
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_he>
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// ─── PROVIDED ───────────────────────────────────────────────────────────>

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}
void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────>

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return>
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    // Convert enum → string
    const char *type_str;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else type_str = "commit";

    // Header
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    header[header_len] = '\0';
    header_len += 1;

    // Combine header + data
    size_t total_size = header_len + len;
    unsigned char *full = malloc(total_size);

    memcpy(full, header, header_len);
 memcpy(full + header_len, data, len);

    // SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(full, total_size, hash);

    // Convert hash → hex
    char hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[64] = '\0';

    // Create directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hex);
    mkdir(dir, 0755);

    // File path
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, hex + 2);

    // Temp file
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        free(full);
        return -1;
    }

    fwrite(full, 1, total_size, f);
    fclose(f);
    return 0;
}
//
// Returns 0 on success, -1 on error.
// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    // Convert hash → hex
    char hash[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash + i * 2, "%02x", id->hash[i]);
    }
    hash[64] = '\0';
  // Build path
    char path[512];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(size);
    fread(buf, 1, size, f);
    fclose(f);

    // Find header end
    char *null_pos = memchr(buf, '\0', size);
    if (!null_pos) {
        free(buf);
        return -1;
    }

    size_t header_len = null_pos - (char*)buf;

    // Parse type
    if (strncmp((char*)buf, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char*)buf, "tree", 4) == 0) *type_out = OBJ_TREE;
    else *type_out = OBJ_COMMIT;

    // Extract data
    unsigned char *data = buf + header_len + 1;
    size_t data_size = size - header_len - 1;

    // Verify hash
    unsigned char new_hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, size, new_hash);
 for (int i = 0; i < 32; i++) {
        if (new_hash[i] != id->hash[i]) {
            free(buf);
            return -1;
        }
    }

    // Output
    *data_out = malloc(data_size);
    memcpy(*data_out, data, data_size);
    *len_out = data_size;

    free(buf);
    return 0;
}
