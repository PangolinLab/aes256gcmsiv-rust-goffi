#ifndef AES_256_GCM_SIV_INTERFACE_H
#define AES_256_GCM_SIV_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

/**
 * @brief AES-256-GCM-SIV 加密函数
 * 
 * @param key_hex 64字符十六进制格式的32字节密钥
 * @param nonce_hex 24字符十六进制格式的12字节nonce
 * @param plaintext_hex 十六进制格式的明文数据
 * @return 成功时返回十六进制格式的密文字符串指针，失败时返回NULL
 */
char* aes_256_gcm_siv_encrypt(const char* key_hex, const char* nonce_hex, const char* plaintext_hex);

/**
 * @brief AES-256-GCM-SIV 解密函数
 * 
 * @param key_hex 64字符十六进制格式的32字节密钥
 * @param nonce_hex 24字符十六进制格式的12字节nonce
 * @param ciphertext_hex 十六进制格式的密文数据
 * @return 成功时返回十六进制格式的明文字符串指针，失败时返回NULL
 */
char* aes_256_gcm_siv_decrypt(const char* key_hex, const char* nonce_hex, const char* ciphertext_hex);

/**
 * @brief 释放由Rust分配的字符串内存
 * 
 * @param ptr 需要释放的字符串指针
 */
void aes_256_gcm_siv_free(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // AES_256_GCM_SIV_INTERFACE_H
