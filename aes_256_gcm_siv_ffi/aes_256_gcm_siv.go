package aes_256_gcm_siv_ffi

/*
	#cgo CFLAGS: -I${SRCDIR}/include
	#cgo LDFLAGS: -lkernel32 -lntdll -luserenv -lws2_32 -ldbghelp -L${SRCDIR}/bin -laes_256_gcm_siv
	#include <stdlib.h>
	#include <aes_256_gcm_siv_interface.h>
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"unsafe"
)

// 定义标准错误类型
var (
	ErrInvalidKeyLength     = errors.New("invalid aes-256-gcm-siv key length: expected 32 bytes")
	ErrInvalidNonceLength   = errors.New("invalid aes-256-gcm-siv nonce length: expected 12 bytes")
	ErrInvalidPlaintext     = errors.New("invalid aes-256-gcm-siv plaintext: cannot be nil")
	ErrInvalidCiphertext    = errors.New("invalid aes-256-gcm-siv ciphertext: insufficient length")
	ErrEncryptionFailed     = errors.New("aes-256-gcm-siv encryption failed")
	ErrDecryptionFailed     = errors.New("aes-256-gcm-siv decryption failed")
	ErrInvalidHexOutput     = errors.New("invalid hex output from aes-256-gcm-siv operation")
	ErrEmptyHexString       = errors.New("empty hex string")
	ErrOddLengthHexString   = errors.New("odd length hex string")
	ErrInvalidHexCharacters = errors.New("invalid hex characters")
)

func init() {
	// 动态库最终路径
	var libFile string
	switch runtime.GOOS {
	case "windows":
		libFile = "bin/aes_256_gcm_siv.dll"
	case "darwin":
		libFile = "bin/libaes_256_gcm_siv.dylib"
	default:
		libFile = "bin/libaes_256_gcm_siv.so"
	}

	// 如果库不存在，则编译 Rust 并复制到 bin/
	if _, err := os.Stat(libFile); os.IsNotExist(err) {
		// Rust 源码目录（Cargo.toml 所在目录）
		rustDir := "../" // 根据你的目录结构调整
		buildCmd := exec.Command("cargo", "build", "--release")
		buildCmd.Dir = rustDir
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			panic("Failed to build Rust library: " + err.Error())
		}

		// 源文件路径（默认 target/release/）
		var srcLib string
		switch runtime.GOOS {
		case "windows":
			srcLib = filepath.Join(rustDir, "target", "release", "aes_256_gcm_siv.dll")
		case "darwin":
			srcLib = filepath.Join(rustDir, "target", "release", "libaes_256_gcm_siv.dylib")
		default:
			srcLib = filepath.Join(rustDir, "target", "release", "libaes_256_gcm_siv.so")
		}

		// 确保 bin 目录存在
		_ = os.MkdirAll("bin", 0755)

		// 复制库到 bin/
		input, err := os.ReadFile(srcLib)
		if err != nil {
			panic("Failed to read Rust library: " + err.Error())
		}
		if err := os.WriteFile(libFile, input, 0644); err != nil {
			panic("Failed to write library to bin/: " + err.Error())
		}
	}
}

// isValidHex 验证字符串是否为有效的十六进制格式
func isValidHex(s string) (bool, error) {
	if s == "" {
		return false, ErrEmptyHexString
	}
	if len(s)%2 != 0 {
		return false, ErrOddLengthHexString
	}
	matched, _ := regexp.MatchString("^[0-9a-fA-F]+$", s)
	if !matched {
		return false, ErrInvalidHexCharacters
	}
	_, err := hex.DecodeString(s)
	return err == nil, err
}

// safeCString 安全地创建和释放C字符串
func safeCString(s string) (*C.char, func()) {
	cStr := C.CString(s)
	return cStr, func() { C.free(unsafe.Pointer(cStr)) }
}

// validateInputs 验证加密输入参数
func validateInputs(key, nonce, plaintext []byte) error {
	keyLen := len(key)
	if keyLen != 32 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKeyLength, keyLen)
	}

	nonceLen := len(nonce)
	if nonceLen != 12 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidNonceLength, nonceLen)
	}

	if plaintext == nil {
		return ErrInvalidPlaintext
	}

	return nil
}

// validateDecryptInputs 验证解密输入参数
func validateDecryptInputs(key, nonceCt []byte) error {
	keyLen := len(key)
	if keyLen != 32 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidKeyLength, keyLen)
	}

	nonceCtLen := len(nonceCt)
	if nonceCtLen <= 12 {
		return fmt.Errorf("%w: got %d bytes, need more than 12 bytes", ErrInvalidCiphertext, nonceCtLen)
	}

	return nil
}

// Encrypt 使用AES-256-GCM-SIV算法加密数据
//
// 参数:
//   - key: 32字节密钥
//   - nonce: 12字节随机数
//   - plaintext: 待加密明文
//
// 返回:
//   - nonce和密文的组合([]byte)
//   - 错误信息(error)
func Encrypt(key, nonce, plaintext []byte) ([]byte, error) {
	// 验证输入参数
	if err := validateInputs(key, nonce, plaintext); err != nil {
		return nil, err
	}

	// 转换为十六进制字符串
	keyHex := hex.EncodeToString(key)
	nonceHex := hex.EncodeToString(nonce)
	ptHex := hex.EncodeToString(plaintext)

	// 创建C字符串并确保释放
	cKey, freeKey := safeCString(keyHex)
	defer freeKey()

	cNonce, freeNonce := safeCString(nonceHex)
	defer freeNonce()

	cPt, freePt := safeCString(ptHex)
	defer freePt()

	// 调用Rust加密函数
	res := C.aes_256_gcm_siv_encrypt(cKey, cNonce, cPt)
	if res == nil {
		return nil, ErrEncryptionFailed
	}
	defer C.aes_256_gcm_siv_free(res)

	// 处理返回结果
	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidHexOutput
	}

	ct, err := hex.DecodeString(outHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex ciphertext: %w", err)
	}

	// 合并nonce和密文
	result := make([]byte, 0, len(nonce)+len(ct))
	result = append(result, nonce...)
	result = append(result, ct...)

	return result, nil
}

// Decrypt 使用AES-256-GCM-SIV算法解密数据
//
// 参数:
//   - key: 32字节密钥
//   - nonceCt: nonce和密文的组合数据
//
// 返回:
//   - 解密后的明文([]byte)
//   - 错误信息(error)
func Decrypt(key, nonceCt []byte) ([]byte, error) {
	// 验证输入参数
	if err := validateDecryptInputs(key, nonceCt); err != nil {
		return nil, err
	}

	// 分离nonce和密文
	nonce := nonceCt[:12]
	ct := nonceCt[12:]

	// 转换为十六进制字符串
	keyHex := hex.EncodeToString(key)
	nonceHex := hex.EncodeToString(nonce)
	ctHex := hex.EncodeToString(ct)

	// 创建C字符串并确保释放
	cKey, freeKey := safeCString(keyHex)
	defer freeKey()

	cNonce, freeNonce := safeCString(nonceHex)
	defer freeNonce()

	cCt, freeCt := safeCString(ctHex)
	defer freeCt()

	// 调用Rust解密函数
	res := C.aes_256_gcm_siv_decrypt(cKey, cNonce, cCt)
	if res == nil {
		return nil, ErrDecryptionFailed
	}
	defer C.aes_256_gcm_siv_free(res)

	// 处理返回结果
	outHex := C.GoString(res)
	ok, err := isValidHex(outHex)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidHexOutput
	}

	plaintext, err := hex.DecodeString(outHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex plaintext: %w", err)
	}

	return plaintext, nil
}
