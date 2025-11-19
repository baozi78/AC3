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
use crate::traits::{
    AnonymousCredentialScheme, PublicKey, SecretKey,
    IssueRequest, IssueResponse, CredentialShow
};
use crate::TagPool;
use serde::{Deserialize, Serialize};
use blind_rsa_signatures::{KeyPair, Options};
use rand::thread_rng;
use std::sync::Mutex;
use std::collections::HashMap;

/// RSA公钥（3072位）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSAPublicKey {
    data: Vec<u8>,  // CBOR格式
}

impl PublicKey for RSAPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

/// RSA私钥
#[derive(Clone, Debug)]
pub struct RSASecretKey {
    data: Vec<u8>,  // CBOR格式
}

impl SecretKey for RSASecretKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

/// 用户凭证（包含L个(msg, sig)对）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RSACredential {
    pub messages: Vec<Vec<u8>>,              // L个随机消息（用作tag）
    pub signatures: Vec<Vec<u8>>,            // L个签名
    pub msg_randomizers: Vec<Option<Vec<u8>>>, // L个msg_randomizer（验证时需要）
    pub usage_count: u32,
    pub usage_limit: u32,
}

/// 盲化数据（用户保存用于去盲化）
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlindingInfo {
    msg: Vec<u8>,
    secret_bytes: Vec<u8>,
    msg_randomizer_bytes: Option<Vec<u8>>,
}

/// 全局tag池（用于verify内部检查重复）
static TAG_POOLS: Mutex<Option<HashMap<Vec<u8>, TagPool>>> = Mutex::new(None);

pub struct RSAScheme;

impl RSAScheme {
    /// 获取tag池
    fn get_tag_pool(pk_bytes: &[u8]) -> TagPool {
        let mut pools = TAG_POOLS.lock().unwrap();
        if pools.is_none() {
            *pools = Some(HashMap::new());
        }
        pools.as_mut().unwrap()
            .entry(pk_bytes.to_vec())
            .or_insert_with(TagPool::new)
            .clone()
    }

    /// 更新tag池
    fn update_tag_pool(pk_bytes: &[u8], pool: TagPool) {
        let mut pools = TAG_POOLS.lock().unwrap();
        if let Some(pools_map) = pools.as_mut() {
            pools_map.insert(pk_bytes.to_vec(), pool);
        }
    }
}

impl AnonymousCredentialScheme for RSAScheme {
    type PublicKey = RSAPublicKey;
    type SecretKey = RSASecretKey;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let mut rng = thread_rng();

        // 生成RSA 3072位密钥对
        let kp = KeyPair::generate(&mut rng, 3072)
            .map_err(|e| CredentialError::KeyGenError(e.to_string()))?;

        // 序列化为字节（使用serde）
        let pk_bytes = serde_json::to_vec(&kp.pk)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        let sk_bytes = serde_json::to_vec(&kp.sk)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;

        Ok((
            RSAPublicKey { data: pk_bytes },
            RSASecretKey { data: sk_bytes },
        ))
    }

    fn generate_user_sk() -> Vec<u8> {
        vec![]
    }

    fn issue_request(pk: &Self::PublicKey, _user_sk: &[u8], usage_limit: u32) -> Result<IssueRequest> {
        let mut rng = thread_rng();
        let options = Options::default();

        // 从字节反序列化公钥
        let public_key: blind_rsa_signatures::PublicKey = serde_json::from_slice(&pk.data)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 生成L个随机消息并盲化
        let mut blind_messages = Vec::new();
        let mut blinding_infos = Vec::new();

        for _ in 0..usage_limit {
            // 生成随机消息（32字节）
            use rand::RngCore;
            let mut msg = vec![0u8; 32];
            rng.fill_bytes(&mut msg);

            // 盲化消息
            let blinding_result = public_key.blind(&mut rng, &msg, true, &options)
                .map_err(|e| CredentialError::SignatureError(format!("盲化失败: {}", e)))?;

            blind_messages.push(blinding_result.blind_msg.clone());

            // 保存盲化信息（使用AsRef转换为字节）
            let secret_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&blinding_result.secret).to_vec();

            let msg_randomizer_bytes = blinding_result.msg_randomizer.as_ref()
                .map(|mr| AsRef::<[u8]>::as_ref(mr).to_vec());

            blinding_infos.push(BlindingInfo {
                msg,
                secret_bytes,
                msg_randomizer_bytes,
            });
        }

        // 序列化请求数据（盲化消息和盲化信息）
        let request_data = serde_json::to_vec(&(blind_messages, blinding_infos))
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;

        Ok(IssueRequest {
            blinded_message: request_data,
            usage_limit,
        })
    }

    fn issue_response(
        issuer_sk: &Self::SecretKey,
        request: &IssueRequest,
    ) -> Result<IssueResponse> {
        let mut rng = thread_rng();
        let options = Options::default();

        // 从字节反序列化私钥
        let secret_key: blind_rsa_signatures::SecretKey = serde_json::from_slice(&issuer_sk.data)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 解析盲化消息
        let (blind_messages, _): (Vec<Vec<u8>>, Vec<BlindingInfo>) =
            serde_json::from_slice(&request.blinded_message)
                .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 对每个盲化消息签名
        let mut blind_sigs_cbor = Vec::new();
        for blind_msg in blind_messages {
            let blind_sig = secret_key.blind_sign(&mut rng, &blind_msg, &options)
                .map_err(|e| CredentialError::SignatureError(format!("盲签名失败: {}", e)))?;

            // 转换为字节
            let sig_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&blind_sig).to_vec();
            blind_sigs_cbor.push(sig_bytes);
        }

        Ok(IssueResponse {
            blinded_signatures: blind_sigs_cbor,
            blinding_factors: vec![],
        })
    }

    fn issue_update(
        pk: &Self::PublicKey,
        request: &IssueRequest,
        response: &IssueResponse,
        _user_sk: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        // 客户端：恢复最终签名 (对应 2.txt 的 pk.finalize)
        // 注意：不需要 rng，只是去盲化操作
        let options = Options::default();

        // 从字节反序列化公钥
        let public_key: blind_rsa_signatures::PublicKey = serde_json::from_slice(&pk.data)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 解析盲化信息
        let (_, blinding_infos): (Vec<Vec<u8>>, Vec<BlindingInfo>) =
            serde_json::from_slice(&request.blinded_message)
                .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        let mut signatures = Vec::new();

        for (i, blind_sig_bytes) in response.blinded_signatures.iter().enumerate() {
            // 从字节创建盲签名
            let blind_sig = blind_rsa_signatures::BlindSignature::new(blind_sig_bytes.clone());

            let info = &blinding_infos[i];

            // 从字节创建secret和msg_randomizer
            let secret = blind_rsa_signatures::Secret::new(info.secret_bytes.clone());

            let msg_randomizer = info.msg_randomizer_bytes.as_ref()
                .map(|mr_bytes| {
                    if mr_bytes.len() != 32 {
                        panic!("MessageRandomizer length must be 32, got {}", mr_bytes.len());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(mr_bytes);
                    blind_rsa_signatures::MessageRandomizer::new(arr)
                });

            // 去盲化：对应 2.txt 的 pk.finalize(&blind_sig, &secret, msg_randomizer, msg, &options)
            let sig = public_key.finalize(&blind_sig, &secret, msg_randomizer, &info.msg, &options)
                .map_err(|e| CredentialError::SignatureError(format!("去盲化失败: {}", e)))?;

            // 转换签名为字节
            let sig_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&sig).to_vec();
            signatures.push(sig_bytes);
        }

        Ok(signatures)
    }

    fn show_credential(
        _pk: &Self::PublicKey,
        _user_sk: &[u8],
        credential: &[u8],
        index: u32,
    ) -> Result<CredentialShow> {
        let cred: RSACredential = serde_json::from_slice(credential)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        if index == 0 || index > cred.usage_limit {
            return Err(CredentialError::InvalidParameter(
                format!("index {} 超出范围 [1, {}]", index, cred.usage_limit)
            ));
        }

        let idx = (index - 1) as usize;

        // tag=msg, proof=(sig, msg_randomizer) 序列化
        let proof_data = (&cred.signatures[idx], &cred.msg_randomizers[idx]);
        let proof_bytes = serde_json::to_vec(&proof_data)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;

        Ok(CredentialShow {
            tag: cred.messages[idx].clone(),
            proof: proof_bytes,
        })
    }

    fn verify_credential(
        pk: &Self::PublicKey,
        show: &CredentialShow,
    ) -> Result<bool> {
        // 对应 2.txt 的 sig.verify(&pk, msg_randomizer, msg, &options)
        let options = Options::default();

        // 从字节反序列化公钥
        let public_key: blind_rsa_signatures::PublicKey = serde_json::from_slice(&pk.data)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 反序列化 proof: (sig_bytes, msg_randomizer_bytes)
        let (sig_bytes, msg_randomizer_bytes): (Vec<u8>, Option<Vec<u8>>) =
            serde_json::from_slice(&show.proof)
                .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 从字节创建签名
        let signature = blind_rsa_signatures::Signature::new(sig_bytes);

        // 从字节创建 msg_randomizer
        let msg_randomizer = msg_randomizer_bytes.as_ref()
            .map(|mr_bytes| {
                if mr_bytes.len() != 32 {
                    panic!("MessageRandomizer length must be 32, got {}", mr_bytes.len());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(mr_bytes);
                blind_rsa_signatures::MessageRandomizer::new(arr)
            });

        let msg = &show.tag;

        // 验证签名：对应 2.txt 的 sig.verify(&pk, msg_randomizer, msg, &options)
        signature.verify(&public_key, msg_randomizer, msg, &options)
            .map_err(|e| CredentialError::VerificationError(e.to_string()))?;

        // 检查tag（msg）是否重复
        let mut tag_pool = Self::get_tag_pool(&pk.data);
        tag_pool.check_and_record_tag(msg)?;
        Self::update_tag_pool(&pk.data, tag_pool);

        Ok(true)
    }
}

/// 辅助方法
impl RSAScheme {
    /// 从request和response创建凭证（执行去盲化）
    pub fn create_credential(
        pk: &RSAPublicKey,
        request: &IssueRequest,
        response: &IssueResponse,
    ) -> Result<RSACredential> {
        let options = Options::default();

        // 从字节反序列化公钥
        let public_key: blind_rsa_signatures::PublicKey = serde_json::from_slice(&pk.data)
            .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        // 解析盲化信息
        let (_, blinding_infos): (Vec<Vec<u8>>, Vec<BlindingInfo>) =
            serde_json::from_slice(&request.blinded_message)
                .map_err(|e| CredentialError::DeserializationError(e.to_string()))?;

        let mut messages = Vec::new();
        let mut signatures = Vec::new();
        let mut msg_randomizers = Vec::new();

        for (i, blind_sig_cbor) in response.blinded_signatures.iter().enumerate() {
            // 从字节创建盲签名
            let blind_sig = blind_rsa_signatures::BlindSignature::new(blind_sig_cbor.clone());

            let info = &blinding_infos[i];

            // 从字节创建secret和msg_randomizer
            let secret = blind_rsa_signatures::Secret::new(info.secret_bytes.clone());

            let msg_randomizer = info.msg_randomizer_bytes.as_ref()
                .map(|mr_bytes| {
                    if mr_bytes.len() != 32 {
                        panic!("MessageRandomizer length must be 32, got {}", mr_bytes.len());
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(mr_bytes);
                    blind_rsa_signatures::MessageRandomizer::new(arr)
                });

            // 去盲化
            let sig = public_key.finalize(&blind_sig, &secret, msg_randomizer, &info.msg, &options)
                .map_err(|e| CredentialError::SignatureError(format!("去盲化失败: {}", e)))?;

            // 转换签名为字节
            let sig_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&sig).to_vec();

            messages.push(info.msg.clone());
            signatures.push(sig_bytes);
            msg_randomizers.push(info.msg_randomizer_bytes.clone());
        }

        Ok(RSACredential {
            messages,
            signatures,
            msg_randomizers,
            usage_count: 0,
            usage_limit: request.usage_limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_keygen() {
        let result = RSAScheme::keygen();
        assert!(result.is_ok());

        let (pk, sk) = result.unwrap();
        assert!(pk.to_bytes().unwrap().len() > 0);
        assert!(sk.to_bytes().unwrap().len() > 0);
    }
}
