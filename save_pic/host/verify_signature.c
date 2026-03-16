#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "verify_signature.h"

#define MAX_PATH 512

int verify_signature(const char *image_path, const char *sig_path,
                     const char *mod_path, const char *exp_path) {
    FILE *fp = NULL;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    fp = fopen(image_path, "rb");
    if (!fp) {
        perror("fopen image");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long img_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *img_buf = malloc(img_size);
    fread(img_buf, 1, img_size, fp);
    fclose(fp);

    SHA256(img_buf, img_size, hash);
    free(img_buf);

    fp = fopen(sig_path, "rb");
    if (!fp) {
        perror("fopen sig");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long sig_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *sig = malloc(sig_size);
    fread(sig, 1, sig_size, fp);
    fclose(fp);

    fp = fopen(mod_path, "rb");
    if (!fp) {
        perror("fopen modulus");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long mod_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *mod_buf = malloc(mod_size);
    fread(mod_buf, 1, mod_size, fp);
    fclose(fp);

    fp = fopen(exp_path, "rb");
    if (!fp) {
        perror("fopen exponent");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long exp_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *exp_buf = malloc(exp_size);
    fread(exp_buf, 1, exp_size, fp);
    fclose(fp);

    RSA *rsa = RSA_new();
    BIGNUM *n = BN_bin2bn(mod_buf, mod_size, NULL);
    BIGNUM *e = BN_bin2bn(exp_buf, exp_size, NULL);
    RSA_set0_key(rsa, n, e, NULL);

    int ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, sig_size, rsa);
    RSA_free(rsa);
    free(mod_buf);
    free(exp_buf);
    free(sig);

    if (ret == 1) {
        printf("[✔] Signature OK: %s\n", image_path);
        return 0;
    } else {
        printf("[✘] Signature FAIL: %s\n", image_path);
        return 1;
    }
}

void verify_all_images(const char *img_dir, const char *sig_dir,
                       const char *mod_path, const char *exp_path) {
    DIR *dir = opendir(img_dir);
    if (!dir) {
        perror("opendir img_dir");
        return;
    }

    struct dirent *entry;
    char img_path[MAX_PATH];
    char sig_path[MAX_PATH];

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG)
            continue;

        const char *name = entry->d_name;
        snprintf(img_path, MAX_PATH, "%s/%s", img_dir, name);
        snprintf(sig_path, MAX_PATH, "%s/%s.sig", sig_dir, name);
        verify_signature(img_path, sig_path, mod_path, exp_path);
    }

    closedir(dir);
}

void verify_one_image(const char *img_path, const char *sig_path,
                      const char *mod_path, const char *exp_path) {
    int result = verify_signature(img_path, sig_path, mod_path, exp_path);
    if (result != 0) {
        // printf("[!] Failed to verify: %s\n", img_path);
    }
}

