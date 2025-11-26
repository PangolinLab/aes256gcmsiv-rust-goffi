use aes_gcm_siv::aead::{Aead, KeyInit, Nonce};
use aes_gcm_siv::Aes256GcmSiv;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// 验证字符串是否为有效的十六进制格式
fn is_valid_hex(sc: &str) -> bool {
    sc.chars().all(|c| c.is_ascii_hexdigit())
}

/// AES-256-GCM-SIV 加密函数
///
/// # 参数
/// * `key_hex` - 64字符十六进制格式的32字节密钥
/// * `nonce_hex` - 24字符十六进制格式的12字节nonce
/// * `plaintext_hex` - 十六进制格式的明文数据
///
/// # 返回值
/// 成功时返回十六进制格式的密文CString指针，失败时返回空指针
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_encrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    plaintext_hex: *const c_char,
) -> *mut c_char {
    // 输入参数检查
    if key_hex.is_null() || nonce_hex.is_null() || plaintext_hex.is_null() {
        return std::ptr::null_mut();
    }

    // 将C字符串转换为Rust字符串
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let pt_cstr = unsafe { CStr::from_ptr(plaintext_hex) };

    let key_str = match key_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_str = match nonce_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let pt_str = match pt_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // 长度验证
    if key_str.len() != 64 || nonce_str.len() != 24 || pt_str.len() % 2 != 0 {
        return std::ptr::null_mut();
    }

    // 十六进制格式验证
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(pt_str) {
        return std::ptr::null_mut();
    }

    // 解码十六进制字符串
    let key = match hex::decode(key_str) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce = match hex::decode(nonce_str) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };
    let plaintext = match hex::decode(pt_str) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    // 长度二次验证
    if key.len() != 32 || nonce.len() != 12 {
        return std::ptr::null_mut();
    }

    // 初始化加密器
    let cipher = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // 创建nonce对象
    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_obj = Nonce::<Aes256GcmSiv>::from_slice(&nonce_arr);

    // 执行加密
    let ciphertext = match cipher.encrypt(nonce_obj, plaintext.as_ref()) {
        Ok(ct) => ct,
        Err(_) => return std::ptr::null_mut(),
    };

    // 编码为十六进制并返回CString
    let out = hex::encode(ciphertext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    cstr.into_raw()
}

/// AES-256-GCM-SIV 解密函数
///
/// # 参数
/// * `key_hex` - 64字符十六进制格式的32字节密钥
/// * `nonce_hex` - 24字符十六进制格式的12字节nonce
/// * `ciphertext_hex` - 十六进制格式的密文数据
///
/// # 返回值
/// 成功时返回十六进制格式的明文CString指针，失败时返回空指针
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_decrypt(
    key_hex: *const c_char,
    nonce_hex: *const c_char,
    ciphertext_hex: *const c_char,
) -> *mut c_char {
    // 输入参数检查
    if key_hex.is_null() || nonce_hex.is_null() || ciphertext_hex.is_null() {
        return std::ptr::null_mut();
    }

    // 将C字符串转换为Rust字符串
    let key_cstr = unsafe { CStr::from_ptr(key_hex) };
    let nonce_cstr = unsafe { CStr::from_ptr(nonce_hex) };
    let ct_cstr = unsafe { CStr::from_ptr(ciphertext_hex) };

    let key_str = match key_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_str = match nonce_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let ct_str = match ct_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    // 长度验证
    if key_str.len() != 64 || nonce_str.len() != 24 || ct_str.len() % 2 != 0 {
        return std::ptr::null_mut();
    }

    // 十六进制格式验证
    if !is_valid_hex(key_str) || !is_valid_hex(nonce_str) || !is_valid_hex(ct_str) {
        return std::ptr::null_mut();
    }

    // 解码十六进制字符串
    let key = match hex::decode(key_str) {
        Ok(k) => k,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce = match hex::decode(nonce_str) {
        Ok(n) => n,
        Err(_) => return std::ptr::null_mut(),
    };
    let ciphertext = match hex::decode(ct_str) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // 长度二次验证
    if key.len() != 32 || nonce.len() != 12 {
        return std::ptr::null_mut();
    }

    // 初始化解密器
    let cipher = match Aes256GcmSiv::new_from_slice(&key) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    // 创建nonce对象
    let nonce_arr: [u8; 12] = match nonce.try_into() {
        Ok(arr) => arr,
        Err(_) => return std::ptr::null_mut(),
    };
    let nonce_obj = Nonce::<Aes256GcmSiv>::from_slice(&nonce_arr);

    // 执行解密
    let plaintext = match cipher.decrypt(nonce_obj, ciphertext.as_ref()) {
        Ok(pt) => pt,
        Err(_) => return std::ptr::null_mut(),
    };

    // 编码为十六进制并返回CString
    let out = hex::encode(plaintext);
    let cstr = match CString::new(out) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };
    cstr.into_raw()
}

/// 释放由Rust分配的CString内存
///
/// # 参数
/// * `ptr` - 需要释放的CString指针
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_256_gcm_siv_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
