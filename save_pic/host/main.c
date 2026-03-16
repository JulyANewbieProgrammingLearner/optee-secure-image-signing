#include <err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>
#include <save_pic_ta.h>
#include <dirent.h>
#include <sys/stat.h>

#include "verify_signature.h"

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SAVE_PIC_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

/*
void call_hash_photo(struct test_ctx *ctx) {
	const char *photo_path = "photo_sample/photo0.jpeg";
	FILE *fp = fopen(photo_path, "rb");
	if (!fp) {
		perror("Failed to open photo");
		return;
	}
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint8_t *photo_data = malloc(file_size);
	fread(photo_data, 1, file_size, fp);
	fclose(fp);

	uint8_t hash_out[32];
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = photo_data;
	op.params[0].tmpref.size = file_size;
	op.params[1].tmpref.buffer = hash_out;
	op.params[1].tmpref.size = sizeof(hash_out);

	res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_HASH_PHOTO, &op, &origin);

	if (res == TEEC_SUCCESS) {
		printf("SHA-256 hash:\n");
		for (size_t i = 0; i < op.params[1].tmpref.size; i++)
			printf("%02X", hash_out[i]);
		printf("\n");
	} else {
		printf("HASH command failed: 0x%x\n", res);
	}

	free(photo_data);
}
*/

/*
void call_hash_photo_from_buffer(struct test_ctx *ctx, const uint8_t *data, size_t data_len) {
	uint8_t hash_out[32];
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)data;
	op.params[0].tmpref.size = data_len;
	op.params[1].tmpref.buffer = hash_out;
	op.params[1].tmpref.size = sizeof(hash_out);

	res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_HASH_PHOTO, &op, &origin);

	if (res == TEEC_SUCCESS) {
		printf("SHA-256 hash (input = \"%.*s\"):\n", (int)data_len, data);
		for (size_t i = 0; i < op.params[1].tmpref.size; i++)
			printf("%02X", hash_out[i]);
			printf("\n");
	}
	else {
		printf("HASH command failed: 0x%x / origin 0x%x\n", res, origin);
	}
}

*/

void call_hash_photo_from_file(struct test_ctx *ctx, const char *path) {
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		perror("Failed to open image file");
		return;
	}

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	uint8_t *data = malloc(file_size);
	if (!data) {
		fclose(fp);
		fprintf(stderr, "Failed to allocate memory\n");
		return;
	}

	fread(data, 1, file_size, fp);
	fclose(fp);

	uint8_t hash_out[32];
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = file_size;
	op.params[1].tmpref.buffer = hash_out;
	op.params[1].tmpref.size = sizeof(hash_out);

	res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_HASH_PHOTO, &op, &origin);

	if (res == TEEC_SUCCESS) {
		printf("SHA-256 of %s:\n", path);
		for (size_t i = 0; i < op.params[1].tmpref.size; i++)
			printf("%02X", hash_out[i]);
		printf("\n");
	} else {
		printf("HASH command failed: 0x%x / origin 0x%x\n", res, origin);
	}

	free(data);
}

void scan_and_hash_all_photos(struct test_ctx *ctx, const char *dir_path) {
	DIR *dir = opendir(dir_path);
	if (!dir) {
		perror("Failed to open photo directory");
		return;
	}

	struct dirent *entry;
	char filepath[256];

	while ((entry = readdir(dir)) != NULL) {
		// 忽略 . 和 ..
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);

		// 確保是 regular file
		struct stat st;
		if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
			call_hash_photo_from_file(ctx, filepath);
		}
	}

	closedir(dir);
}

// 整個資料夾內的每張圖片執行簽章並產生對應 .sig 檔案 -P1
void sign_photo_and_save(struct test_ctx *ctx, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("Failed to open image file");
        return;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    uint8_t *data = malloc(file_size);
    if (!data) {
        fclose(fp);
        fprintf(stderr, "Failed to allocate memory\n");
        return;
    }

    fread(data, 1, file_size, fp);
    fclose(fp);

    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    uint8_t sig[256];
    uint32_t sig_len = sizeof(sig);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = data;
    op.params[0].tmpref.size = file_size;
    op.params[1].tmpref.buffer = sig;
    op.params[1].tmpref.size = sig_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_SIGN_PHOTO, &op, &origin);
    if (res != TEEC_SUCCESS) {
        printf("SIGN command failed: 0x%x / origin 0x%x\n", res, origin);
        free(data);
        return;
    }

    sig_len = op.params[1].tmpref.size;
    
    // --- 改存到 /host ---
    const char *filename = strrchr(path, '/');
    if (!filename) filename = path;
    else filename++;  // 跳過 '/'


    // char sig_path[300];
    char sig_path[512];
    // snprintf(sig_path, sizeof(sig_path), "%s.sig", path);
    snprintf(sig_path, sizeof(sig_path), "/host/%s.sig", filename);

    FILE *sf = fopen(sig_path, "wb");
    if (!sf) {
        perror("Failed to write signature file");
        free(data);
        return;
    }

    fwrite(sig, 1, sig_len, sf);
    fclose(sf);
    printf("Signed %s => %s\n", path, sig_path);
    free(data);
}





// 整個資料夾內的每張圖片執行簽章並產生對應 .sig 檔案
void scan_and_sign_all_photos(struct test_ctx *ctx, const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("Failed to open photo directory");
        return;
    }

    struct dirent *entry;
    char filepath[256];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", dir_path, entry->d_name);

        struct stat st;
        if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
            sign_photo_and_save(ctx, filepath);
        }
    }

    closedir(dir);
}


void call_export_pubkey(struct test_ctx *ctx) {
    TEEC_Operation op;
    uint32_t origin;
    TEEC_Result res;

    uint8_t modulus[256];
    uint32_t modulus_len = sizeof(modulus);
    uint8_t exponent[8];
    uint32_t exponent_len = sizeof(exponent);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = modulus;
    op.params[0].tmpref.size = modulus_len;
    op.params[1].tmpref.buffer = exponent;
    op.params[1].tmpref.size = exponent_len;

    res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_EXPORT_PUBKEY, &op, &origin);
    if (res != TEEC_SUCCESS) {
        printf("EXPORT_PUBKEY failed: 0x%x / origin 0x%x\n", res, origin);
        return;
    }

    modulus_len = op.params[0].tmpref.size;
    exponent_len = op.params[1].tmpref.size;

    // 建立 openssl 格式 PEM
    FILE *fp = fopen("/host/pubkey.pem", "w");
    if (!fp) {
        perror("Failed to open pubkey.pem");
        return;
    }

    // 將 DER 格式轉換為 PEM 使用 openssl 命令會更方便
    // 所以我們儲存為純 binary 格式方便後續使用
    FILE *fp_mod = fopen("/host/modulus.bin", "wb");
    FILE *fp_exp = fopen("/host/exponent.bin", "wb");
    if (fp_mod && fp_exp) {
        fwrite(modulus, 1, modulus_len, fp_mod);
        fwrite(exponent, 1, exponent_len, fp_exp);
        fclose(fp_mod);
        fclose(fp_exp);
        printf("Exported public key modulus/exponent to /host/\n");
    } else {
        perror("Failed to write key files");
    }
}


void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}




TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000

int main(int argc, char *argv[]) {
	/*
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SAVE_PIC_UUID;
	uint32_t err_origin;
	*/
	struct test_ctx ctx;
	
	char obj1_id[] = "object#1";		/* string identification for the object */
	char obj2_id[] = "object#2";		/* string identification for the object */
	char obj1_data[TEST_OBJECT_SIZE];
	char read_data[TEST_OBJECT_SIZE];
	TEEC_Result res;
	
	/*
	// 1. 初始化 TEE 上下文
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext failed: 0x%x\n", res);
		return 1;
	}

	// 2. 打開 TA 會話
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
		TEEC_FinalizeContext(&ctx);
		return 1;
	}

	// 3. 讀取照片文件
	FILE *fp = fopen("photo_sample/photo0.jpeg", "rb");
	if (!fp) {
		perror("Failed to open photo");
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		return 1;
	}

	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint8_t *photo_data = malloc(file_size);
	fread(photo_data, 1, file_size, fp);
	fclose(fp);

	// 4. 分配共享記憶體（輸入：照片，輸出：簽名）
	TEEC_SharedMemory shm_in = { .size = file_size, .flags = TEEC_MEM_INPUT };
	TEEC_SharedMemory shm_out = { .size = 256, .flags = TEEC_MEM_OUTPUT }; // 簽名緩衝區

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) goto cleanup;
	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) goto cleanup;

	memcpy(shm_in.buffer, photo_data, file_size);

	// 5. 調用 TA 命令
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_WHOLE,  // 照片輸入
		TEEC_MEMREF_WHOLE,  // 簽名輸出
		TEEC_NONE,
		TEEC_NONE
	);
	op.params[0].memref.parent = &shm_in;
	op.params[1].memref.parent = &shm_out;

	res = TEEC_InvokeCommand(&sess, TA_CMD_PROCESS_PHOTO, &op, NULL);
	if (res == TEEC_SUCCESS) {
		// 將簽名保存到文件
		FILE *sig_file = fopen("photo.sig", "wb");
		fwrite(shm_out.buffer, 1, shm_out.size, sig_file);
		fclose(sig_file);scan_and_sign_all_photos
		printf("Signature saved to photo.sig\n");
	} else {
        	fprintf(stderr, "TA command failed: 0x%x\n", res);
	}

cleanup:
	TEEC_ReleaseSharedMemory(&shm_in);
	TEEC_ReleaseSharedMemory(&shm_out);
	free(photo_data);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return res == TEEC_SUCCESS ? 0 : 1;
	*/
	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);
	
	delete_secure_object(&ctx, "rsa_key");
	
	
	// call_hash_photo(&ctx);
	// const char *test_msg = "Hello OP-TEE Secure Hash!";
	// call_hash_photo_from_buffer(&ctx, (const uint8_t*)test_msg, strlen(test_msg));
	
	scan_and_hash_all_photos(&ctx, "/usr/share/photo_samples");
	scan_and_sign_all_photos(&ctx, "/usr/share/photo_samples");
	
	call_export_pubkey(&ctx);
	
	// /usr/share/photo_samples 才是 Buildroot rootfs 內部路徑。
	printf("\n[VERIFY] Begin signature verification phase...\n");
	verify_all_images(
	    "/usr/share/photo_samples",
	    "/host",
	    "/host/modulus.bin",
	    "/host/exponent.bin"
	);
	
	// add
	// 透過 verify_one_image(...) 這個函式來驗證單張圖片（fake 圖片）的簽章結果。
	printf("\n[VERIFY] Testing tampered image...\n");
	verify_one_image(
	    "/usr/share/fake_photo/fake.jpg",       // 假照片
	    "/host/fake.jpg.sig",                   // 對應簽章檔 (從原圖複製的簽章)
	    "/host/modulus.bin",
	    "/host/exponent.bin"
	);


	/*
	 * Create object, read it, delete it.
	 */
	printf("\nTest on object \"%s\"\n", obj1_id);

	printf("- Create and load object in the TA secure storage\n");

	memset(obj1_data, 0xA1, sizeof(obj1_data));

	res = write_secure_object(&ctx, obj1_id,
				  obj1_data, sizeof(obj1_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to create an object in the secure storage");

	printf("- Read back the object\n");

	res = read_secure_object(&ctx, obj1_id,
				 read_data, sizeof(read_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to read an object from the secure storage");
	if (memcmp(obj1_data, read_data, sizeof(obj1_data)))
		errx(1, "Unexpected content found in secure storage");

	printf("- Delete the object\n");

	res = delete_secure_object(&ctx, obj1_id);
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to delete the object: 0x%x", res);

	/*
	 * Non volatile storage: create object2 if not found, delete it if found
	 */
	printf("\nTest on object \"%s\"\n", obj2_id);

	res = read_secure_object(&ctx, obj2_id,
				  read_data, sizeof(read_data));
	if (res != TEEC_SUCCESS && res != TEEC_ERROR_ITEM_NOT_FOUND)
		errx(1, "Unexpected status when reading an object : 0x%x", res);

	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		char data[] = "This is data stored in the secure storage.\n";

		printf("- Object not found in TA secure storage, create it.\n");

		res = write_secure_object(&ctx, obj2_id,
					  data, sizeof(data));
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to create/load an object");

	} else if (res == TEEC_SUCCESS) {
		printf("- Object found in TA secure storage, delete it.\n");

		res = delete_secure_object(&ctx, obj2_id);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to delete an object");
	}

	printf("\nWe're done, close and release TEE resources\n");
	terminate_tee_session(&ctx);
	return 0;
}

