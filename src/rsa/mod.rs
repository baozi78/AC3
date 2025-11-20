//! RSA 盲签名方案实现
//!
//! 使用 blind-rsa-signatures 库实现真正的盲签名
//! tag = msg（随机消息）用于防重放
//!
//! 流程：
//! 1. keygen: 生成RSA密钥对
//! 2. issue_request: 生成L个随机msg并盲化
//! 3. issue_response: Issuer对盲化消息签名
//! 4. issue_update: 去盲化得到真实签名
//! 5. show_credentials: 返回(msg_i, sig_i)，tag=msg_i
//! 6. verify_credentials: 验证签名并检查msg重复

use crate::error::{Result, CredentialError};
use crate::traits::{AnonymousCredentialScheme, PublicKey, SecretKey};
use crate::TagPool;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use blind_rsa_signatures::{
    KeyPair, Options,
    PublicKey as BlindRSAPublicKey,
    SecretKey as BlindRSASecretKey,
    BlindedMessage, BlindSignature, Signature,
    Secret, MessageRandomizer,
};
use rand::thread_rng;
use std::sync::Mutex;
use std::collections::HashMap;

/// RSA公钥（3072位）
#[derive(Clone, Debug)]
pub struct RSAPublicKey {
    pub inner: BlindRSAPublicKey,
}

impl Serialize for RSAPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        let json = serde_json::to_string(&self.inner)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&json)
    }
}

impl<'de> Deserialize<'de> for RSAPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        let json = String::deserialize(deserializer)?;
        let inner = serde_json::from_str(&json)
            .map_err(serde::de::Error::custom)?;
        Ok(RSAPublicKey { inner })
    }
}

impl PublicKey for RSAPublicKey {}

/// RSA私钥
#[derive(Clone, Debug)]
pub struct RSASecretKey {
    pub inner: BlindRSASecretKey,
}

// 自定义序列化
impl Serialize for RSASecretKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        // 使用 blind-rsa-signatures 库的内置序列化
        let json = serde_json::to_string(&self.inner)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&json)
    }
}

impl<'de> Deserialize<'de> for RSASecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        let json = String::deserialize(deserializer)?;
        let inner = serde_json::from_str(&json)
            .map_err(serde::de::Error::custom)?;
        Ok(RSASecretKey { inner })
    }
}

impl SecretKey for RSASecretKey {}

/// RSA用户私钥（RSA方案中用户没有真正的私钥，只是占位符）
#[derive(Clone, Debug)]
pub struct RSAUserSecretKey;

/// RSA凭证（包含L个(msg, sig)对）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSACredential {
    pub messages: Vec<Vec<u8>>,              // L个随机消息（用作tag）
    pub signatures: Vec<Signature>,          // L个签名（原始类型）
    pub msg_randomizers: Vec<Option<MessageRandomizer>>, // L个msg_randomizer（原始类型）
    pub usage_count: u32,
    pub usage_limit: u32,
}

/// RSA发行请求
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSAIssueRequest {
    pub blind_messages: Vec<BlindedMessage>, // L个盲化消息（原始类型）
    pub blinding_infos: Vec<BlindingInfo>,   // L个盲化信息（用户保留）
    pub usage_limit: u32,
}

/// RSA发行响应
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSAIssueResponse {
    pub blind_signatures: Vec<BlindSignature>, // L个盲签名（原始类型）
}

/// RSA凭证展示
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSACredentialShow {
    pub tag: Vec<u8>,                        // msg_i（用作tag）
    pub signature: Signature,                // sig_i（原始类型）
    pub msg_randomizer: Option<MessageRandomizer>, // msg_randomizer_i（原始类型）
}

/// 盲化数据（用户保存用于去盲化）
#[derive(Clone, Debug)]
pub struct BlindingInfo {
    pub msg: Vec<u8>,
    pub secret: Secret,                      // 原始类型
    pub msg_randomizer: Option<MessageRandomizer>, // 原始类型
}

// 自定义序列化
impl Serialize for BlindingInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BlindingInfo", 3)?;
        state.serialize_field("msg", &self.msg)?;
        state.serialize_field("secret", AsRef::<[u8]>::as_ref(&self.secret))?;
        state.serialize_field("msg_randomizer", &self.msg_randomizer.as_ref().map(|mr| AsRef::<[u8]>::as_ref(mr).to_vec()))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BlindingInfo {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            msg: Vec<u8>,
            secret: Vec<u8>,
            msg_randomizer: Option<Vec<u8>>,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        let msg_randomizer = helper.msg_randomizer.map(|bytes| {
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom(format!("MessageRandomizer must be 32 bytes, got {}", bytes.len())));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(MessageRandomizer::new(arr))
        }).transpose()?;
        
        Ok(BlindingInfo {
            msg: helper.msg,
            secret: Secret::new(helper.secret),
            msg_randomizer,
        })
    }
}

/// 全局tag池（用于verify内部检查重复）
static TAG_POOLS: Mutex<Option<HashMap<Vec<u8>, TagPool>>> = Mutex::new(None);

pub struct RSAScheme;

impl RSAScheme {
    /// 获取tag池
    fn get_tag_pool(pk: &RSAPublicKey) -> TagPool {
        let pk_bytes = serde_json::to_vec(&pk.inner).unwrap_or_default();
        let mut pools = TAG_POOLS.lock().unwrap();
        if pools.is_none() {
            *pools = Some(HashMap::new());
        }
        pools.as_mut().unwrap()
            .entry(pk_bytes)
            .or_insert_with(TagPool::new)
            .clone()
    }

    /// 更新tag池
    fn update_tag_pool(pk: &RSAPublicKey, pool: TagPool) {
        let pk_bytes = serde_json::to_vec(&pk.inner).unwrap_or_default();
        let mut pools = TAG_POOLS.lock().unwrap();
        if let Some(pools_map) = pools.as_mut() {
            pools_map.insert(pk_bytes, pool);
        }
    }
}

impl AnonymousCredentialScheme for RSAScheme {
    type PublicKey = RSAPublicKey;
    type SecretKey = RSASecretKey;
    type UserSecretKey = RSAUserSecretKey;
    type Credential = RSACredential;
    type IssueRequest = RSAIssueRequest;
    type IssueResponse = RSAIssueResponse;
    type CredentialShow = RSACredentialShow;
    type IndexType = u32;                    // RSA使用u32作为索引
    type UsageLimitType = u32;               // RSA使用u32作为使用次数上限

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = thread_rng();

        // 生成RSA 3072位密钥对
        let kp = KeyPair::generate(&mut rng, 3072)
            .map_err(|e| CredentialError::KeyGenError(e.to_string()))?;

        Ok((
            RSAPublicKey { inner: kp.pk },
            RSASecretKey { inner: kp.sk },
        ))
    }

    fn generate_user_sk() -> Self::UserSecretKey {
        RSAUserSecretKey // RSA方案中用户没有真正的私钥
    }

    fn issue_request(
        pk: &Self::PublicKey, 
        _user_sk: &Self::UserSecretKey, 
        usage_limit: Self::UsageLimitType
    ) -> Result<Self::IssueRequest> {
        let mut rng = thread_rng();
        let options = Options::default();

        // 生成L个随机消息并盲化
        let mut blind_messages = Vec::new();
        let mut blinding_infos = Vec::new();

        for _ in 0..usage_limit {
            // 生成随机消息（32字节）
            use rand::RngCore;
            let mut msg = vec![0u8; 32];
            rng.fill_bytes(&mut msg);

            // 盲化消息
            let blinding_result = pk.inner.blind(&mut rng, &msg, true, &options)
                .map_err(|e| CredentialError::SignatureError(format!("盲化失败: {}", e)))?;

            blind_messages.push(blinding_result.blind_msg);

            blinding_infos.push(BlindingInfo {
                msg,
                secret: blinding_result.secret,
                msg_randomizer: blinding_result.msg_randomizer,
            });
        }

        Ok(RSAIssueRequest {
            blind_messages,
            blinding_infos,
            usage_limit,
        })
    }

    fn issue_response(
        _pk: &Self::PublicKey,
        issuer_sk: &Self::SecretKey,
        request: &Self::IssueRequest,
    ) -> Result<Self::IssueResponse> {
        let mut rng = thread_rng();
        let options = Options::default();

        // 对每个盲化消息签名
        let mut blind_signatures = Vec::new();
        for blind_msg in &request.blind_messages {
            let blind_sig = issuer_sk.inner.blind_sign(&mut rng, blind_msg, &options)
                .map_err(|e| CredentialError::SignatureError(format!("盲签名失败: {}", e)))?;

            blind_signatures.push(blind_sig);
        }

        Ok(RSAIssueResponse {
            blind_signatures,
        })
    }

    fn issue_update(
        pk: &Self::PublicKey,
        request: &Self::IssueRequest,
        response: &Self::IssueResponse,
        _user_sk: &Self::UserSecretKey,
    ) -> Result<Self::Credential> {
        // 去盲化得到真实签名
        let options = Options::default();

        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut msg_randomizers = Vec::new();

        for (i, blind_sig) in response.blind_signatures.iter().enumerate() {
            let info = &request.blinding_infos[i];

            // 去盲化
            let sig = pk.inner.finalize(blind_sig, &info.secret, info.msg_randomizer, &info.msg, &options)
                .map_err(|e| CredentialError::SignatureError(format!("去盲化失败: {}", e)))?;

            messages.push(info.msg.clone());
            signatures.push(sig);
            msg_randomizers.push(info.msg_randomizer);
        }

        Ok(RSACredential {
            messages,
            signatures,
            msg_randomizers,
            usage_count: 0,
            usage_limit: request.usage_limit,
        })
    }

    fn show_credential(
        _pk: &Self::PublicKey,
        _user_sk: &Self::UserSecretKey,
        credential: &Self::Credential,
        index: Self::IndexType,
    ) -> Result<Self::CredentialShow> {
        if index == 0 || index > credential.usage_limit {
            return Err(CredentialError::InvalidParameter(
                format!("index {} 超出范围 [1, {}]", index, credential.usage_limit)
            ));
        }

        let idx = (index - 1) as usize;

        Ok(RSACredentialShow {
            tag: credential.messages[idx].clone(),
            signature: credential.signatures[idx].clone(),
            msg_randomizer: credential.msg_randomizers[idx].clone(),
        })
    }

    fn verify_credential(
        pk: &Self::PublicKey,
        show: &Self::CredentialShow,
    ) -> Result<bool> {
        let options = Options::default();

        let msg = &show.tag;

        // 验证签名
        show.signature.verify(&pk.inner, show.msg_randomizer, msg, &options)
            .map_err(|e| CredentialError::VerificationError(e.to_string()))?;

        // 检查tag（msg）是否重复
        let mut tag_pool = Self::get_tag_pool(pk);
        tag_pool.check_and_record_tag(msg)?;
        Self::update_tag_pool(pk, tag_pool);

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_keygen() {
        let result = RSAScheme::keygen();
        assert!(result.is_ok());

        let (_pk, _sk) = result.unwrap();
        // 密钥生成成功即可
    }

    #[test]
    fn test_rsa_secret_key_serialization() {
        // 生成密钥对
        let (pk, sk) = RSAScheme::keygen().unwrap();
        
        // 序列化私钥
        let serialized = serde_json::to_string(&sk).unwrap();
        
        // 反序列化私钥
        let deserialized: RSASecretKey = serde_json::from_str(&serialized).unwrap();
        
        // 验证反序列化的私钥可以正常使用
        let user_sk = RSAScheme::generate_user_sk();
        let request = RSAScheme::issue_request(&pk, &user_sk, 2).unwrap();
        let response = RSAScheme::issue_response(&pk, &deserialized, &request).unwrap();
        let credential = RSAScheme::issue_update(&pk, &request, &response, &user_sk).unwrap();
        
        // 验证凭证可以正常展示和验证
        let show = RSAScheme::show_credential(&pk, &user_sk, &credential, 1).unwrap();
        let valid = RSAScheme::verify_credential(&pk, &show).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_rsa_basic_flow() {
        // 1. keygen
        let (issuer_pk, issuer_sk) = RSAScheme::keygen().unwrap();
        let user_sk = RSAScheme::generate_user_sk();

        // 2. issue_request
        let request = RSAScheme::issue_request(&issuer_pk, &user_sk, 3).unwrap();
        assert_eq!(request.usage_limit, 3);
        assert_eq!(request.blind_messages.len(), 3);
        assert_eq!(request.blinding_infos.len(), 3);

        // 3. issue_response
        let response = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &request).unwrap();
        assert_eq!(response.blind_signatures.len(), 3);

        // 4. issue_update
        let credential = RSAScheme::issue_update(&issuer_pk, &request, &response, &user_sk).unwrap();
        assert_eq!(credential.messages.len(), 3);
        assert_eq!(credential.signatures.len(), 3);
        assert_eq!(credential.usage_limit, 3);

        // 5. show_credential
        let show = RSAScheme::show_credential(&issuer_pk, &user_sk, &credential, 1).unwrap();
        assert!(!show.tag.is_empty());
        assert!(!show.signature.is_empty());

        // 6. verify_credential
        let valid = RSAScheme::verify_credential(&issuer_pk, &show).unwrap();
        assert!(valid);
    }
}