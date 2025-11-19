use crate::error::Result;
use serde::{Deserialize, Serialize};

/// 公钥trait（不要求序列化，由具体方案决定）
pub trait PublicKey {}

/// 私钥trait（不要求序列化，由具体方案决定）
pub trait SecretKey {}

/// 匿名凭证系统的通用trait
///
/// 新设计特点：
/// 1. 类型安全：各方案定义自己的数据类型，避免Vec<u8>类型擦除
/// 2. 无序列化：trait层面不处理序列化，由上层调用者控制
/// 3. 泛型参数：支持不同方案的IndexType和UsageLimitType需求
///
/// 完整流程：
/// 1. Issuer: keygen() 生成公私钥
/// 2. User: issue_request() 创建请求 (序列化后发送给Issuer)
/// 3. Issuer: issue_response() 返回响应 (序列化后发送给User)  
/// 4. User: issue_update() 生成凭证 (本地操作，无需序列化)
/// 5. User: show_credential() 生成凭证展示 (序列化后发送给Verifier)
/// 6. Verifier: verify_credential() 验证凭证 (接收序列化数据)
pub trait AnonymousCredentialScheme {
    /// 发行者公钥类型
    type PublicKey: PublicKey;
    /// 发行者私钥类型  
    type SecretKey: SecretKey;
    /// 用户私钥类型 (RSA: Vec<u8>, BBS: Fr, CL: BigInt)
    type UserSecretKey;
    /// 凭证类型 (各方案自定义)
    type Credential;
    /// 发行请求类型 (各方案自定义)
    type IssueRequest;
    /// 发行响应类型 (各方案自定义)  
    type IssueResponse;
    /// 凭证展示类型 (各方案自定义)
    type CredentialShow;
    /// 使用次数索引类型 (RSA: u32, BBS: Fr, CL: BigInt)
    type IndexType;
    /// 使用次数上限类型 (RSA: u32, BBS: u64, CL: BigInt)  
    type UsageLimitType;

    /// 1. 密钥生成
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)>;

    /// 2. 生成用户私钥
    fn generate_user_sk() -> Self::UserSecretKey;

    /// 3. 用户请求发行凭证
    /// 输入：发行者公钥，用户私钥，使用次数上限
    /// 输出：发行请求 (需要序列化发送给Issuer)
    fn issue_request(
        pk: &Self::PublicKey, 
        user_sk: &Self::UserSecretKey, 
        usage_limit: Self::UsageLimitType
    ) -> Result<Self::IssueRequest>;

    /// 4. 发行者响应请求  
    /// 输入：发行者公钥（用于验证POK），发行者私钥，发行请求 (从序列化数据反序列化得到)
    /// 输出：发行响应 (需要序列化发送给User)
    fn issue_response(
        pk: &Self::PublicKey,
        issuer_sk: &Self::SecretKey,
        request: &Self::IssueRequest,
    ) -> Result<Self::IssueResponse>;

    /// 5. 用户生成最终凭证
    /// 输入：公钥，请求，响应，用户私钥 (本地数据，无需序列化)
    /// 输出：凭证 (本地保存，无需序列化)
    fn issue_update(
        pk: &Self::PublicKey,
        request: &Self::IssueRequest,
        response: &Self::IssueResponse,
        user_sk: &Self::UserSecretKey,
    ) -> Result<Self::Credential>;

    /// 6. 展示凭证
    /// 输入：公钥，用户私钥，凭证，使用次数索引 (本地数据)
    /// 输出：凭证展示 (需要序列化发送给Verifier)
    fn show_credential(
        pk: &Self::PublicKey,
        user_sk: &Self::UserSecretKey,
        credential: &Self::Credential,
        index: Self::IndexType,
    ) -> Result<Self::CredentialShow>;

    /// 7. 验证凭证展示
    /// 输入：公钥，凭证展示 (从序列化数据反序列化得到)
    /// 输出：验证结果
    fn verify_credential(
        pk: &Self::PublicKey,
        show: &Self::CredentialShow,
    ) -> Result<bool>;
}

// 为了向后兼容，保留旧的数据结构定义，但标记为deprecated
#[deprecated(note = "Use scheme-specific types instead")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueRequest {
    pub blinded_message: Vec<u8>,
    pub usage_limit: u32,
}

#[deprecated(note = "Use scheme-specific types instead")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueResponse {
    pub blinded_signatures: Vec<Vec<u8>>,
    pub blinding_factors: Vec<Vec<u8>>,
}

#[deprecated(note = "Use scheme-specific types instead")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialShow {
    pub tag: Vec<u8>,
    pub proof: Vec<u8>,
}