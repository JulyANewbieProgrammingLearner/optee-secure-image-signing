#ifndef TA_SAVE_PIC_H
#define TA_SAVE_PIC_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_SAVE_PIC_UUID \
	{ 0xf72a5176, 0x5352, 0x4a07, \
		{ 0x97, 0x9f, 0xe5, 0x3b, 0xbf, 0xb0, 0x8c, 0xdf} }

/* The function IDs implemented in this TA */

// 定義命令：處理照片並簽名
#define TA_CMD_PROCESS_PHOTO			0
#define TA_SECURE_STORAGE_CMD_READ_RAW		1
#define TA_SECURE_STORAGE_CMD_WRITE_RAW		2
#define TA_SECURE_STORAGE_CMD_DELETE		3
#define TA_CMD_HASH_PHOTO			4
#define TA_CMD_SIGN_PHOTO			5
#define TA_CMD_EXPORT_PUBKEY  			6

#endif /*TA_SAVE_PIC_H*/
