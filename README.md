# AES-256-GCM-SIV FFI Library

高性能、安全的 AES-256-GCM-SIV 加密库，用于 Pangolin Lab 的项目。采用 Rust 实现核心算法，通过 FFI 接口提供给 Go 使用。

## 特性

- **安全性优先**：使用 `aes-gcm-siv` crate，无 unsafe 加密操作
- **高性能**：利用 AES-NI 指令集加速，零拷贝输入切片
- **标准合规**：符合 RFC 8452 标准
- **抗侧信道攻击**：AES-NI 提供时间攻击防护
- **线程安全**：无共享状态，支持并发使用

## Go 语言使用

### Go API 参考

```go
Encrypt(key, nonce, plaintext []byte) ([]byte, error)
Decrypt(key, ciphertextWithNonce []byte) ([]byte, error)
```


### 参数要求

- `key`: 32 字节 AES-256 密钥
- `nonce`: 12 字节 GCM-SIV nonce
- `plaintext`: 任意长度明文

### Go 示例代码

```go
import "github.com/PangolinLab/aes256gcmsiv-rust-goffi"

// 加密
ciphertext, err := tools.Encrypt(key, nonce, plaintext) 

// 解密
plaintext, err := tools.Decrypt(key, ciphertextWithNonce)
```
