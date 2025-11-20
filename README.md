# AC3: Anonymous Credentials Library

一个用Rust实现的n次匿名凭证系统，支持三种签名方案：CL（Camenisch-Lysyanskaya）、BBS（Boneh-Boyen-Shacham）和RSA盲签名。

## 项目概述

AC3（Anonymous Credentials with Controlled Consumption）是一个现代化的匿名凭证库，允许用户在不泄露身份信息的情况下多次使用凭证。该系统特别适用于需要隐私保护的场景，如匿名投票、隐私支付、匿名认证等。

### 核心特性

- **多方案支持**：实现了三种主流的匿名凭证方案
  - **CL签名**：基于RSA困难问题，支持高效的选择性披露
  - **BBS签名**：基于配对友好曲线BLS12-381，支持短签名和批量验证
  - **RSA盲签名**：传统RSA盲签名方案，简单高效

- **使用次数限制**：每个凭证可配置使用次数上限L，支持1-N次使用
- **防重放攻击**：通过tag池机制防止凭证被重复使用
- **盲发行**：发行者无法将凭证与用户身份关联
- **零知识证明**：用户展示凭证时不泄露秘密信息
- **类型安全**：采用现代Rust trait设计，避免类型擦除

## 技术架构

### 统一Trait接口

所有方案均实现`AnonymousCredentialScheme` trait，提供统一的接口：

```rust
pub trait AnonymousCredentialScheme {
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;
    type UserSecretKey;
    type Credential;
    type IssueRequest;
    type IssueResponse;
    type CredentialShow;
    type IndexType;
    type UsageLimitType;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn generate_user_sk() -> Self::UserSecretKey;
    fn issue_request(...) -> Result<Self::IssueRequest>;
    fn issue_response(...) -> Result<Self::IssueResponse>;
    fn issue_update(...) -> Result<Self::Credential>;
    fn show_credential(...) -> Result<Self::CredentialShow>;
    fn verify_credential(...) -> Result<bool>;
}
```

### 完整流程

```
  用户（User）                  发行者（Issuer）              验证者（Verifier）
      │                              │                            │
      │  1. generate_user_sk()       │                            │
      ├───────────────────────────►  │                            │
      │                              │                            │
      │  2. issue_request(pk, sk, L) │                            │
      ├───────────────────────────►  │                            │
      │                              │                            │
      │                              │  3. issue_response(sk,req) │
      │  ◄───────────────────────────┤                            │
      │                              │                            │
      │  4. issue_update(req,resp)   │                            │
      │  (生成最终凭证)               │                            │
      │                              │                            │
      │  5. show_credential(i)       │                            │
      ├──────────────────────────────────────────────────────────►│
      │                              │                            │
      │                              │         6. verify_credential│
      │                              │                            │
```

## 三种方案详解

### 1. BBS方案（推荐）

基于BLS12-381配对友好曲线实现，提供最佳的安全性和效率平衡。

**算法原理**：
- **密钥生成**：Issuer私钥 `sk ∈ Zp`，公钥 `pk = w^sk`
- **签名结构**：`(A, e, s)` 其中 `A = (g·g0^s·g1^r)^{1/(sk+e)}`
- **Tag计算**：`tag = h^{1/(r+i)}`（i为使用次数索引）
- **零知识证明**：统一的Sigma协议证明签名有效性和索引范围

### 2. CL方案

基于RSA困难问题的经典匿名凭证方案，广泛应用于Hyperledger Indy等项目。

**算法原理**：
- **密钥生成**：RSA模数 `n = pq`，生成元 `a, b, c`
- **签名结构**：`(e, s, v)` 其中 `A = v^e = a^m·b^s·c (mod n)`
- **Tag计算**：`tag = g^{1/(m+i)}`
- **零知识证明**：Schnorr协议证明签名知识


### 3. RSA盲签名方案

最简单直接的匿名凭证实现，基于RSA盲签名协议。

**算法原理**：
- **密钥生成**：RSA 3072位密钥对
- **盲化**：用户生成随机消息 `msg`，计算盲化消息 `blind_msg`
- **签名**：Issuer对盲化消息签名，用户去盲化得到真实签名
- **Tag计算**：`tag = msg`（直接使用消息作为tag）


## 快速开始

### 依赖项

在 `Cargo.toml` 中添加：

```toml
[dependencies]
anonymous_credentials = { path = "." }
```

### 示例代码

#### BBS方案示例

```rust
use anonymous_credentials::{
    bbs::BBSScheme,
    AnonymousCredentialScheme,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Issuer生成密钥对
    let (issuer_pk, issuer_sk) = BBSScheme::keygen()?;

    // 2. 用户生成私钥
    let user_sk = BBSScheme::generate_user_sk();

    // 3. 用户请求凭证（使用次数L=10）
    let request = BBSScheme::issue_request(&issuer_pk, &user_sk, 10)?;

    // 4. Issuer签发凭证
    let response = BBSScheme::issue_response(&issuer_pk, &issuer_sk, &request)?;

    // 5. 用户生成最终凭证
    let credential = BBSScheme::issue_update(&issuer_pk, &request, &response, &user_sk)?;

    // 6. 用户展示凭证（第1次使用）
    let show = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, 1)?;

    // 7. 验证者验证凭证
    let valid = BBSScheme::verify_credential(&issuer_pk, &show)?;
    assert!(valid);

    println!("✓ 凭证验证成功！");
    Ok(())
}
```

#### 序列化与网络传输

所有需要传输的数据类型都支持序列化：

```rust
use serde_json;

// 序列化发行请求
let request_json = serde_json::to_string(&request)?;
// 通过网络发送...

// 接收方反序列化
let received_request: BBSIssueRequest = serde_json::from_str(&request_json)?;
```

## 测试

运行完整测试套件：

```bash
# 测试BBS方案
cargo test --test bbs_integration_test

# 测试CL方案
cargo test --test cl_integration_test

# 测试RSA方案
cargo test --test rsa_integration_test

# 运行所有测试
cargo test
```


## 性能指标

**测试环境**：Linux 6.14.0-29-generic, Rust Release模式优化

| 方案 | 密钥生成 | 发行请求 | 签发响应 | 凭证更新 | 展示凭证 | 验证凭证 |
|------|---------|---------|---------|---------|---------|---------|
| BBS  | 0.35ms   | 1.99ms   | 1.85ms   | 10.20ms  | 17.86ms  | 18.99ms  |
| CL   | 2.94ms   | 649.75ms | 87.57ms  | 30.53ms  | 72.55ms  | 36.98ms  |
| RSA  | 770.45ms| 8.32ms   | 77.77ms  | 6.09ms   | 0.001ms  | 0.79ms   |

注：
- 所有时间单位为毫秒(ms)，保留2位小数
- 测试运行3次取最快值，使用10次使用限制(L=10)
- RSA方案的发行请求和签发响应时间与L成正比

## 项目结构

```
AC3/
├── src/
│   ├── lib.rs              # 库入口，导出公共接口
│   ├── traits.rs           # 核心trait定义
│   ├── error.rs            # 错误类型定义
│   ├── tag_pool.rs         # Tag池实现（防重放）
│   ├── bbs/
│   │   └── mod.rs          # BBS方案实现
│   ├── cl/
│   │   └── mod.rs          # CL方案实现
│   └── rsa/
│       └── mod.rs          # RSA方案实现
├── tests/
│   ├── bbs_integration_test.rs
│   ├── cl_integration_test.rs
│   └── rsa_integration_test.rs
├── Cargo.toml              # 项目配置和依赖
└── README.md               # 本文档
```

## 依赖库

### 核心加密库

- **bbs_plus** (0.19): BBS+签名实现
- **ark-bls12-381** (0.4): BLS12-381曲线运算
- **cl-signature-rust**: CL签名实现（GitHub）
- **blind-rsa-signatures**: RSA盲签名实现（GitHub）
- **rsa** (0.9): RSA基础运算

### 辅助库

- **serde/serde_json**: 序列化支持
- **sha2**: 哈希函数（Fiat-Shamir变换）
- **rand**: 随机数生成
- **thiserror**: 错误处理

## 许可证

本项目采用MIT许可证 - 详见LICENSE文件

## 参考文献

1. **BBS签名**:
   - Boneh, D., Boyen, X., & Shacham, H. (2004). "Short Group Signatures"
   - BBS+ 增强方案支持多消息签名

2. **CL签名**:
   - Camenisch, J., & Lysyanskaya, A. (2003). "A Signature Scheme with Efficient Protocols"


3. **RSA盲签名**:
   - Chaum, D. (1983). "Blind Signatures for Untraceable Payments"
   - IETF Draft: RSA Blind Signatures

**⚠️ 安全提醒**：本项目仅供学习和研究使用。在生产环境部署前，请进行充分的安全审计和测试。
