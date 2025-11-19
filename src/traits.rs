use crate::error::Result;
use serde::{Deserialize, Serialize};

/// 公钥trait，用于序列化
pub trait PublicKey: Serialize + for<'a> Deserialize<'a> {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> Result<Self> where Self: Sized;
}

/// 私钥trait
pub trait SecretKey {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> Result<Self> where Self: Sized;
}

/// 发行请求
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueRequest {
    pub blinded_message: Vec<u8>,
    pub usage_limit: u32,  // L次使用限制
}

/// 发行响应（Issuer返回盲签名）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssueResponse {
    pub blinded_signatures: Vec<Vec<u8>>,  // L个盲签名
    pub blinding_factors: Vec<Vec<u8>>,    // L个盲化因子（用户用于去盲化）
}

/// 凭证展示（包含tag/签名和证明）
/// 注意：对于RSA方案，tag就是签名；对于BBS/CL方案，tag是g^{1/(sk+i)}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredentialShow {
    pub tag: Vec<u8>,      // RSA: 签名, BBS/CL: tag = g^{1/(sk+i)}
    pub proof: Vec<u8>,    // 范围证明
}

/// 匿名凭证系统的通用trait
///
/// 完整流程：
/// 1. Issuer: keygen() 生成公私钥
/// 2. User: issue_request() 创建盲化请求
/// 3. Issuer: issue_response() 返回盲签名
/// 4. User: issue_update() 去盲化得到真实签名/凭证
/// 5. User: show_credential() 每次使用时生成tag（RSA发签名，BBS/CL生成tag）
/// 6. Verifier: verify_credential() 验证tag
pub trait AnonymousCredentialScheme {
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;

    /// 密钥生成
    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)>;

    /// 生成用户私钥（用于tag计算）
    fn generate_user_sk() -> Vec<u8>;

    /// 用户请求发行（包含sk和使用次数限制L）
    /// 返回盲化的请求
    /// pk: 发行者公钥（盲化需要）
    fn issue_request(pk: &Self::PublicKey, user_sk: &[u8], usage_limit: u32) -> Result<IssueRequest>;

    /// 发行者响应（返回L个盲签名）
    fn issue_response(
        issuer_sk: &Self::SecretKey,
        request: &IssueRequest,
    ) -> Result<IssueResponse>;

    /// 用户去盲化（获得真实的L个签名/凭证）
    /// 对于RSA：去盲化得到L个真实签名
    /// 对于BBS/CL：去盲化得到凭证参数
    fn issue_update(
        pk: &Self::PublicKey,
        request: &IssueRequest,
        response: &IssueResponse,
        user_sk: &[u8],
    ) -> Result<Vec<Vec<u8>>>;

    /// 展示凭证（生成tag/签名和证明）
    /// 对于RSA：返回第i个签名作为tag
    /// 对于BBS/CL：计算tag = g^{1/(sk+i)}
    fn show_credential(
        pk: &Self::PublicKey,
        user_sk: &[u8],
        credential: &[u8],
        index: u32,  // 第几次使用，i ∈ [1, L]
    ) -> Result<CredentialShow>;

    /// 验证凭证展示
    /// 对于RSA：验证签名
    /// 对于BBS/CL：验证tag和范围证明
    fn verify_credential(
        pk: &Self::PublicKey,
        show: &CredentialShow,
    ) -> Result<bool>;
}
