//! BBS匿名凭证实现
//!
//! 基于BBS+签名的匿名凭证系统，支持：
//! - 盲化发行（blind issue）
//! - n次使用限制（usage_limit）
//! - tag = h^{1/(r+i)} 防重放
//! - 统一零知识证明
//!
//! 流程：
//! 1. keygen - Issuer生成BLS12-381密钥对
//! 2. issue_request - 用户生成承诺C和POK证明
//! 3. issue_response - Issuer验证POK并签发
//! 4. issue_update - 用户获取最终凭证
//! 5. show_credential - 用户生成tag和零知识证明
//! 6. verify_credential - 验证者验证并检查tag重复


use crate::error::{Result, CredentialError};
use crate::traits::{AnonymousCredentialScheme, PublicKey, SecretKey};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::collections::HashSet;
use std::sync::{Mutex, LazyLock};

// BBS+库导入
use bbs_plus::setup::SecretKey as BBSPlusSecretKey;
use ark_bls12_381::{Bls12_381, G1Projective, G2Projective, Fr, G1Affine, G2Affine};
use ark_ec::{Group, CurveGroup};
use ark_ff::{Field, UniformRand, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

// Sigma-protocol range proof (replacing Bulletproofs)
// We implement a custom range proof based on bit decomposition and Schnorr OR proofs

// ========== Sigma-protocol范围证明数据结构 ==========

/// 比特证明：证明承诺的值是0或1（使用Schnorr OR证明）
#[derive(Clone, Debug, Serialize, Deserialize)]
struct BitProof {
    c0: Vec<u8>,  // 挑战值c0（假设bit=0）
    c1: Vec<u8>,  // 挑战值c1（假设bit=1）
    z0: Vec<u8>,  // 响应z0（假设bit=0）
    z1: Vec<u8>,  // 响应z1（假设bit=1）
    zr: Vec<u8>,  // 盲化因子响应
}

/// Sigma-protocol范围证明
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SigmaRangeProof {
    bit_commitments: Vec<Vec<u8>>,  // 每个比特的Pedersen承诺
    bit_proofs: Vec<BitProof>,       // 每个比特的0/1证明
}

// 全局tag池，用于防重放攻击
static TAG_POOL: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// BBS公钥
#[derive(Clone, Debug)]
pub struct BBSPublicKey {
    pub issuer_pk: G2Projective,     // pk = w^sk（Issuer公钥）
    pub w: G2Projective,             // G2生成元
    pub g: G1Projective,             // 基础生成元
    pub g0: G1Projective,            // 承诺生成元1（用于s）
    pub g1: G1Projective,            // 承诺生成元2（用于r）
    pub h: G1Projective,             // Tag生成元
    pub h0: G1Projective,            // ZK证明辅助生成元
    pub g_commit: G1Projective,      // Pedersen承诺生成元（用于i）
    pub h_commit: G1Projective,      // Pedersen承诺盲化生成元
}

// 自定义序列化
impl Serialize for BBSPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BBSPublicKey", 9)?;
        state.serialize_field("issuer_pk", &serialize_g2(&self.issuer_pk))?;
        state.serialize_field("w", &serialize_g2(&self.w))?;
        state.serialize_field("g", &serialize_g1(&self.g))?;
        state.serialize_field("g0", &serialize_g1(&self.g0))?;
        state.serialize_field("g1", &serialize_g1(&self.g1))?;
        state.serialize_field("h", &serialize_g1(&self.h))?;
        state.serialize_field("h0", &serialize_g1(&self.h0))?;
        state.serialize_field("g_commit", &serialize_g1(&self.g_commit))?;
        state.serialize_field("h_commit", &serialize_g1(&self.h_commit))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BBSPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            issuer_pk: Vec<u8>,
            w: Vec<u8>,
            g: Vec<u8>,
            g0: Vec<u8>,
            g1: Vec<u8>,
            h: Vec<u8>,
            h0: Vec<u8>,
            g_commit: Vec<u8>,
            h_commit: Vec<u8>,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(BBSPublicKey {
            issuer_pk: deserialize_g2(&helper.issuer_pk).map_err(serde::de::Error::custom)?,
            w: deserialize_g2(&helper.w).map_err(serde::de::Error::custom)?,
            g: deserialize_g1(&helper.g).map_err(serde::de::Error::custom)?,
            g0: deserialize_g1(&helper.g0).map_err(serde::de::Error::custom)?,
            g1: deserialize_g1(&helper.g1).map_err(serde::de::Error::custom)?,
            h: deserialize_g1(&helper.h).map_err(serde::de::Error::custom)?,
            h0: deserialize_g1(&helper.h0).map_err(serde::de::Error::custom)?,
            g_commit: deserialize_g1(&helper.g_commit).map_err(serde::de::Error::custom)?,
            h_commit: deserialize_g1(&helper.h_commit).map_err(serde::de::Error::custom)?,
        })
    }
}

impl PublicKey for BBSPublicKey {}

/// BBS私钥
#[derive(Clone, Debug)]
pub struct BBSSecretKey {
    pub inner: BBSPlusSecretKey<Fr>,  // BBS+私钥（可以通过.0访问Fr）
}

// 自定义序列化
impl Serialize for BBSSecretKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        // 将 Fr 标量序列化为字节数组
        serialize_fr(&self.inner.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BBSSecretKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        // 从字节数组反序列化 Fr 标量
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let fr = deserialize_fr(&bytes).map_err(serde::de::Error::custom)?;
        Ok(BBSSecretKey {
            inner: BBSPlusSecretKey(fr)
        })
    }
}

impl SecretKey for BBSSecretKey {}

/// BBS用户私钥
#[derive(Clone, Debug)]
pub struct BBSUserSecretKey {
    pub s_prime: Fr,  // 用户秘密s'
    pub r: Fr,        // 随机数r（在generate_user_sk时生成）
}

/// 承诺POK证明
#[derive(Clone, Debug)]
pub struct CommitmentPOK {
    pub t: G1Projective,      // 承诺值
    pub z_s: Fr,              // 响应值（对应s'）
    pub z_r: Fr,              // 响应值（对应r）
    pub challenge: Fr,        // 挑战值
}

// 自定义序列化
impl Serialize for CommitmentPOK {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CommitmentPOK", 4)?;
        state.serialize_field("t", &serialize_g1(&self.t))?;
        state.serialize_field("z_s", &serialize_fr(&self.z_s))?;
        state.serialize_field("z_r", &serialize_fr(&self.z_r))?;
        state.serialize_field("challenge", &serialize_fr(&self.challenge))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CommitmentPOK {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            t: Vec<u8>,
            z_s: Vec<u8>,
            z_r: Vec<u8>,
            challenge: Vec<u8>,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(CommitmentPOK {
            t: deserialize_g1(&helper.t).map_err(serde::de::Error::custom)?,
            z_s: deserialize_fr(&helper.z_s).map_err(serde::de::Error::custom)?,
            z_r: deserialize_fr(&helper.z_r).map_err(serde::de::Error::custom)?,
            challenge: deserialize_fr(&helper.challenge).map_err(serde::de::Error::custom)?,
        })
    }
}

/// BBS发行请求
#[derive(Clone, Debug)]
pub struct BBSIssueRequest {
    pub commitment: G1Projective,    // C = g0^s' · g1^r
    pub pok_proof: CommitmentPOK,    // POK{(s',r): C = g0^s' · g1^r}
    pub usage_limit: u32,
}

// 自定义序列化
impl Serialize for BBSIssueRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BBSIssueRequest", 3)?;
        state.serialize_field("commitment", &serialize_g1(&self.commitment))?;
        state.serialize_field("pok_proof", &self.pok_proof)?;
        state.serialize_field("usage_limit", &self.usage_limit)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BBSIssueRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            commitment: Vec<u8>,
            pok_proof: CommitmentPOK,
            usage_limit: u32,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(BBSIssueRequest {
            commitment: deserialize_g1(&helper.commitment).map_err(serde::de::Error::custom)?,
            pok_proof: helper.pok_proof,
            usage_limit: helper.usage_limit,
        })
    }
}

/// BBS发行响应
#[derive(Clone, Debug)]
pub struct BBSIssueResponse {
    pub signature_A: G1Projective,   // A = (g·C·g0^s'')^{1/(sk+e)}
    pub exponent_e: Fr,              // 随机指数e
    pub s_double_prime: Fr,          // Issuer生成的s''
}

// 自定义序列化
impl Serialize for BBSIssueResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BBSIssueResponse", 3)?;
        state.serialize_field("signature_A", &serialize_g1(&self.signature_A))?;
        state.serialize_field("exponent_e", &serialize_fr(&self.exponent_e))?;
        state.serialize_field("s_double_prime", &serialize_fr(&self.s_double_prime))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BBSIssueResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            signature_A: Vec<u8>,
            exponent_e: Vec<u8>,
            s_double_prime: Vec<u8>,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(BBSIssueResponse {
            signature_A: deserialize_g1(&helper.signature_A).map_err(serde::de::Error::custom)?,
            exponent_e: deserialize_fr(&helper.exponent_e).map_err(serde::de::Error::custom)?,
            s_double_prime: deserialize_fr(&helper.s_double_prime).map_err(serde::de::Error::custom)?,
        })
    }
}

/// BBS凭证（用户本地保存）
#[derive(Clone, Debug)]
pub struct BBSCredential {
    pub signature_A: G1Projective,   // BBS签名A
    pub exponent_e: Fr,              // 指数e
    pub secret_s: Fr,                // s = s' + s''
    pub secret_r: Fr,                // 随机数r
    pub usage_limit: u32,            // 使用次数L
}

/// 统一零知识证明
#[derive(Clone, Debug)]
pub struct UnifiedProof {
    // 随机化的签名
    pub A_prime: G1Projective,
    pub A_bar: G1Projective,
    pub d: G1Projective,
    
    // 承诺值
    pub T1: G1Projective,
    pub T2: G1Projective,
    pub T_tag: G1Projective,
    pub T_commit: G1Projective,
    
    // i的Pedersen承诺
    pub committed_i: G1Projective,
    
    // 响应值
    pub z_z: Fr,
    pub z_r: Fr,
    pub z_e: Fr,
    pub z_r2: Fr,
    pub z_r3: Fr,
    pub z_i: Fr,
    pub z_blinding_i: Fr,
    
    // Sigma范围证明（序列化字节）
    pub range_proof: Vec<u8>,
    
    // usage_limit（用于范围证明验证）
    pub usage_limit: u32,
    
    // 挑战值
    pub challenge: Fr,
}

impl Serialize for UnifiedProof {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("UnifiedProof", 16)?;
        state.serialize_field("A_prime", &serialize_g1(&self.A_prime))?;
        state.serialize_field("A_bar", &serialize_g1(&self.A_bar))?;
        state.serialize_field("d", &serialize_g1(&self.d))?;
        state.serialize_field("T1", &serialize_g1(&self.T1))?;
        state.serialize_field("T2", &serialize_g1(&self.T2))?;
        state.serialize_field("T_tag", &serialize_g1(&self.T_tag))?;
        state.serialize_field("T_commit", &serialize_g1(&self.T_commit))?;
        state.serialize_field("committed_i", &serialize_g1(&self.committed_i))?;
        state.serialize_field("z_z", &serialize_fr(&self.z_z))?;
        state.serialize_field("z_r", &serialize_fr(&self.z_r))?;
        state.serialize_field("z_e", &serialize_fr(&self.z_e))?;
        state.serialize_field("z_r2", &serialize_fr(&self.z_r2))?;
        state.serialize_field("z_r3", &serialize_fr(&self.z_r3))?;
        state.serialize_field("z_i", &serialize_fr(&self.z_i))?;
        state.serialize_field("z_blinding_i", &serialize_fr(&self.z_blinding_i))?;
        state.serialize_field("range_proof", &self.range_proof)?;
        state.serialize_field("usage_limit", &self.usage_limit)?;
        state.serialize_field("challenge", &serialize_fr(&self.challenge))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for UnifiedProof {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            A_prime: Vec<u8>,
            A_bar: Vec<u8>,
            d: Vec<u8>,
            T1: Vec<u8>,
            T2: Vec<u8>,
            T_tag: Vec<u8>,
            T_commit: Vec<u8>,
            committed_i: Vec<u8>,
            z_z: Vec<u8>,
            z_r: Vec<u8>,
            z_e: Vec<u8>,
            z_r2: Vec<u8>,
            z_r3: Vec<u8>,
            z_i: Vec<u8>,
            z_blinding_i: Vec<u8>,
            range_proof: Vec<u8>,
            usage_limit: u32,
            challenge: Vec<u8>,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(UnifiedProof {
            A_prime: deserialize_g1(&helper.A_prime).map_err(serde::de::Error::custom)?,
            A_bar: deserialize_g1(&helper.A_bar).map_err(serde::de::Error::custom)?,
            d: deserialize_g1(&helper.d).map_err(serde::de::Error::custom)?,
            T1: deserialize_g1(&helper.T1).map_err(serde::de::Error::custom)?,
            T2: deserialize_g1(&helper.T2).map_err(serde::de::Error::custom)?,
            T_tag: deserialize_g1(&helper.T_tag).map_err(serde::de::Error::custom)?,
            T_commit: deserialize_g1(&helper.T_commit).map_err(serde::de::Error::custom)?,
            committed_i: deserialize_g1(&helper.committed_i).map_err(serde::de::Error::custom)?,
            z_z: deserialize_fr(&helper.z_z).map_err(serde::de::Error::custom)?,
            z_r: deserialize_fr(&helper.z_r).map_err(serde::de::Error::custom)?,
            z_e: deserialize_fr(&helper.z_e).map_err(serde::de::Error::custom)?,
            z_r2: deserialize_fr(&helper.z_r2).map_err(serde::de::Error::custom)?,
            z_r3: deserialize_fr(&helper.z_r3).map_err(serde::de::Error::custom)?,
            z_i: deserialize_fr(&helper.z_i).map_err(serde::de::Error::custom)?,
            z_blinding_i: deserialize_fr(&helper.z_blinding_i).map_err(serde::de::Error::custom)?,
            range_proof: helper.range_proof,
            usage_limit: helper.usage_limit,
            challenge: deserialize_fr(&helper.challenge).map_err(serde::de::Error::custom)?,
        })
    }
}

/// BBS凭证展示
#[derive(Clone, Debug)]
pub struct BBSCredentialShow {
    pub tag: G1Projective,       // tag = h^{1/(r+i)}
    pub proof: UnifiedProof,     // 统一的零知识证明
}

// 自定义序列化
impl Serialize for BBSCredentialShow {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where S: Serializer {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BBSCredentialShow", 2)?;
        state.serialize_field("tag", &serialize_g1(&self.tag))?;
        state.serialize_field("proof", &self.proof)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for BBSCredentialShow {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        struct Helper {
            tag: Vec<u8>,
            proof: UnifiedProof,
        }
        
        let helper = Helper::deserialize(deserializer)?;
        Ok(BBSCredentialShow {
            tag: deserialize_g1(&helper.tag).map_err(serde::de::Error::custom)?,
            proof: helper.proof,
        })
    }
}

pub struct BBSScheme;

// ========== 辅助函数 ==========

fn serialize_g1(point: &G1Projective) -> Vec<u8> {
    let mut bytes = Vec::new();
    point.into_affine().serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1Projective> {
    let affine = G1Affine::deserialize_compressed(bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
    Ok(affine.into())
}

fn serialize_g2(point: &G2Projective) -> Vec<u8> {
    let mut bytes = Vec::new();
    point.into_affine().serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn deserialize_g2(bytes: &[u8]) -> Result<G2Projective> {
    let affine = G2Affine::deserialize_compressed(bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
    Ok(affine.into())
}

fn serialize_fr(scalar: &Fr) -> Vec<u8> {
    let mut bytes = Vec::new();
    scalar.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn deserialize_fr(bytes: &[u8]) -> Result<Fr> {
    Fr::deserialize_compressed(bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))
}

fn hash_to_fr(inputs: &[&[u8]]) -> Fr {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input);
    }
    let hash = hasher.finalize();
    
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Fr::from_be_bytes_mod_order(&bytes)
}

// ========== Trait实现 ==========

impl AnonymousCredentialScheme for BBSScheme {
    type PublicKey = BBSPublicKey;
    type SecretKey = BBSSecretKey;
    type UserSecretKey = BBSUserSecretKey;
    type Credential = BBSCredential;
    type IssueRequest = BBSIssueRequest;
    type IssueResponse = BBSIssueResponse;
    type CredentialShow = BBSCredentialShow;
    type IndexType = u32;
    type UsageLimitType = u32;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        // 1. 生成Issuer私钥
        let sk = Fr::rand(&mut OsRng);
        let secret_key = BBSSecretKey {
            inner: BBSPlusSecretKey(sk),
        };
        
        // 2. 生成系统参数
        let w = G2Projective::generator();
        let issuer_pk = w * sk;  // pk = w^sk
        
        let g = G1Projective::rand(&mut OsRng);
        let g0 = G1Projective::rand(&mut OsRng);
        let g1 = G1Projective::rand(&mut OsRng);
        let h = G1Projective::rand(&mut OsRng);
        let h0 = G1Projective::rand(&mut OsRng);
        let g_commit = G1Projective::rand(&mut OsRng);
        let h_commit = G1Projective::rand(&mut OsRng);
        
        let public_key = BBSPublicKey {
            issuer_pk,
            w,
            g,
            g0,
            g1,
            h,
            h0,
            g_commit,
            h_commit,
        };
        
        Ok((public_key, secret_key))
    }

    fn generate_user_sk() -> Self::UserSecretKey {
        BBSUserSecretKey {
            s_prime: Fr::rand(&mut OsRng),
            r: Fr::rand(&mut OsRng),
        }
    }

    fn issue_request(
        pk: &Self::PublicKey,
        user_sk: &Self::UserSecretKey,
        usage_limit: Self::UsageLimitType
    ) -> Result<Self::IssueRequest> {
        let s_prime = user_sk.s_prime;
        let r = user_sk.r;
        
        // 1. 计算承诺 C = g0^s' · g1^r
        let commitment = pk.g0 * s_prime + pk.g1 * r;
        
        // 2. 生成POK证明
        let pok_proof = generate_commitment_pok(pk, &commitment, &s_prime, &r)?;
        
        Ok(BBSIssueRequest {
            commitment,
            pok_proof,
            usage_limit,
        })
    }

    fn issue_response(
        pk: &Self::PublicKey,
        issuer_sk: &Self::SecretKey,
        request: &Self::IssueRequest,
    ) -> Result<Self::IssueResponse> {
        // 1. 获取issuer私钥
        let sk = issuer_sk.inner.0;
        
        // 2. 验证POK证明
        if !verify_commitment_pok(pk, &request.commitment, &request.pok_proof)? {
            return Err(CredentialError::VerificationError("POK证明验证失败".to_string()));
        }
        
        // 3. 生成随机数
        let s_double_prime = Fr::rand(&mut OsRng);
        let e = Fr::rand(&mut OsRng);
        
        // 4. 计算签名：b = g · C · g0^s''
        let b = pk.g + request.commitment + pk.g0 * s_double_prime;
        
        // 5. 计算 A = b^{1/(sk+e)}
        let exponent_inv = (sk + e).inverse()
            .ok_or_else(|| CredentialError::SignatureError("无法计算逆元".to_string()))?;
        let signature_A = b * exponent_inv;
        
        Ok(BBSIssueResponse {
            signature_A,
            exponent_e: e,
            s_double_prime,
        })
    }

    fn issue_update(
        pk: &Self::PublicKey,
        request: &Self::IssueRequest,
        response: &Self::IssueResponse,
        user_sk: &Self::UserSecretKey,
    ) -> Result<Self::Credential> {
        // 1. 获取用户秘密
        let s_prime = user_sk.s_prime;
        let r = user_sk.r;
        
        // 2. 计算最终秘密值
        let s = s_prime + response.s_double_prime;
        
        // 3. （可选）验证签名正确性
        // 验证 e(A, pk · w^e) = e(g · g0^s · g1^r, w)
        use ark_ec::pairing::Pairing;
        use ark_bls12_381::Bls12_381;
        
        let lhs = Bls12_381::pairing(response.signature_A, pk.issuer_pk + pk.w * response.exponent_e);
        let b_verify = pk.g + pk.g0 * s + pk.g1 * r;
        let rhs = Bls12_381::pairing(b_verify, pk.w);
        
        if lhs != rhs {
            return Err(CredentialError::VerificationError("签名验证失败".to_string()));
        }
        
        Ok(BBSCredential {
            signature_A: response.signature_A,
            exponent_e: response.exponent_e,
            secret_s: s,
            secret_r: r,
            usage_limit: request.usage_limit,
        })
    }

    fn show_credential(
        pk: &Self::PublicKey,
        _user_sk: &Self::UserSecretKey,
        credential: &Self::Credential,
        index: Self::IndexType,
    ) -> Result<Self::CredentialShow> {
        // 1. 检查索引范围
        if index < 1 || index > credential.usage_limit {
            return Err(CredentialError::InvalidParameter(
                format!("index {} 超出范围 [1, {}]", index, credential.usage_limit)
            ));
        }
        
        // 2. 计算tag = h^{1/(r+i)}
        let i_fr = Fr::from(index as u64);
        let exponent = (credential.secret_r + i_fr).inverse()
            .ok_or_else(|| CredentialError::SignatureError("无法计算tag".to_string()))?;
        let tag = pk.h * exponent;
        
        // 3. 生成完整的统一零知识证明
        let proof = generate_unified_proof(pk, credential, &tag, index)?;
        
        Ok(BBSCredentialShow { tag, proof })
    }

    fn verify_credential(
        pk: &Self::PublicKey,
        show: &Self::CredentialShow,
    ) -> Result<bool> {
        // 1. 检查tag重复（防重放攻击）
        {
            let mut tag_pool = TAG_POOL.lock().unwrap();
            let tag_bytes = serialize_g1(&show.tag);
            if tag_pool.contains(&tag_bytes) {
                return Err(CredentialError::TagAlreadyUsed);
            }
            tag_pool.insert(tag_bytes);
        }
        
        // 2. 检查tag ≠ 单位元（零元素）
        if show.tag == G1Projective::default() {
            return Err(CredentialError::InvalidParameter("tag不能为零".to_string()));
        }
        
        // 3. 验证完整的统一零知识证明
        let valid = verify_unified_proof(pk, &show.tag, &show.proof)?;
        
        Ok(valid)
    }
}

// ========== POK辅助函数 ==========

fn generate_commitment_pok(
    pk: &BBSPublicKey,
    commitment: &G1Projective,
    s_prime: &Fr,
    r: &Fr,
) -> Result<CommitmentPOK> {
    // 1. 生成随机数
    let alpha_s = Fr::rand(&mut OsRng);
    let alpha_r = Fr::rand(&mut OsRng);
    
    // 2. 计算承诺
    let t = pk.g0 * alpha_s + pk.g1 * alpha_r;
    
    // 3. 计算挑战
    let challenge = hash_to_fr(&[
        &serialize_g1(commitment),
        &serialize_g1(&t),
        &serialize_g1(&pk.g0),
        &serialize_g1(&pk.g1),
    ]);
    
    // 4. 计算响应
    let z_s = alpha_s + challenge * s_prime;
    let z_r = alpha_r + challenge * r;
    
    Ok(CommitmentPOK { t, z_s, z_r, challenge })
}

fn verify_commitment_pok(
    pk: &BBSPublicKey,
    commitment: &G1Projective,
    pok: &CommitmentPOK,
) -> Result<bool> {
    // 1. 重新计算挑战
    let challenge_verify = hash_to_fr(&[
        &serialize_g1(commitment),
        &serialize_g1(&pok.t),
        &serialize_g1(&pk.g0),
        &serialize_g1(&pk.g1),
    ]);
    
    if challenge_verify != pok.challenge {
        return Ok(false);
    }
    
    // 2. 验证等式 g0^z_s · g1^z_r = t · C^c
    let lhs = pk.g0 * pok.z_s + pk.g1 * pok.z_r;
    let rhs = pok.t + *commitment * pok.challenge;
    
    Ok(lhs == rhs)
}

// ========== 完整的统一零知识证明 ==========

fn generate_unified_proof(
    pk: &BBSPublicKey,
    credential: &BBSCredential,
    tag: &G1Projective,
    index: u32,
) -> Result<UnifiedProof> {
    let mut rng = OsRng;
    
    let A = &credential.signature_A;
    let e = &credential.exponent_e;
    let s = &credential.secret_s;
    let r = &credential.secret_r;
    let i_fr = Fr::from(index as u64);
    
    // 1. 随机化
    let r1 = Fr::rand(&mut rng);
    let r2 = Fr::rand(&mut rng);
    let r3 = r1.inverse()
        .ok_or_else(|| CredentialError::SignatureError("无法计算r3 = 1/r1".to_string()))?;
    
    let A_prime = *A * r1;
    
    // 2. 计算承诺与相关值
    let b = pk.g + pk.g0 * s + pk.g1 * r;
    let A_bar = A_prime * (Fr::ZERO - *e) + b * r1;
    let d = b * r1 - pk.g0 * r2;
    let z = *s - r2 * r3;
    
    // 3. 计算i的比特分解和承诺
    let bit_length = compute_bit_length(credential.usage_limit);
    let bits = decompose_to_bits(index, bit_length);  // 比特分解index（不减1）
    
    // 为每个比特分配blinding
    let mut bit_blindings = Vec::new();
    
    for _ in 0..bit_length {
        bit_blindings.push(Fr::rand(&mut rng));
    }
    
    // 生成每个比特的承诺
    let mut bit_commitments_for_proof = Vec::new();
    let mut committed_i = G1Projective::default();
    let mut blinding_i = Fr::ZERO;
    
    for (j, &bit) in bits.iter().enumerate() {
        let bit_val = if bit { Fr::ONE } else { Fr::ZERO };
        let bit_blinding = bit_blindings[j];
        let bit_commitment = pk.g_commit * bit_val + pk.h_commit * bit_blinding;
        
        // 重构committed_i：committed_i = Σ(C_j · 2^j)
        let power_of_two = Fr::from(1u64 << j);
        committed_i = committed_i + bit_commitment * power_of_two;
        
        // 计算总blinding：blinding_i = Σ(r_j · 2^j)
        blinding_i = blinding_i + bit_blinding * power_of_two;
        
        bit_commitments_for_proof.push(bit_commitment);
    }
    
    // 4. 生成Sigma范围证明（传递已生成的比特承诺和blinding）
    let range_proof = generate_sigma_range_proof_with_commitments(
        pk,
        &bits,
        &bit_commitments_for_proof,
        &bit_blindings,
    )?;
    
    // 5. Schnorr协议 - 承论阶段
    let alpha_z = Fr::rand(&mut rng);
    let alpha_r = Fr::rand(&mut rng);
    let alpha_e = Fr::rand(&mut rng);
    let alpha_r2 = Fr::rand(&mut rng);
    let alpha_r3 = Fr::rand(&mut rng);
    let alpha_i = Fr::rand(&mut rng);
    let alpha_blinding_i = Fr::rand(&mut rng);
    
    // T1 = A'^(-alpha_e) * g0^alpha_r2 （用于关系1：Ā/d = A'^(-e) * g0^r2）
    let T1 = A_prime * (Fr::ZERO - alpha_e) + pk.g0 * alpha_r2;
    
    // T2 = d^alpha_r3 * g0^(-alpha_z) * g1^(-alpha_r) （用于关系2）
    let T2 = d * alpha_r3 - pk.g0 * alpha_z - pk.g1 * alpha_r;
    
    // T_tag = tag^alpha_r * tag^alpha_i （用于关系3：tag^r * tag^i = h）
    let T_tag = *tag * alpha_r + *tag * alpha_i;
    
    // T_commit = g_commit^alpha_i * h_commit^alpha_blinding_i （i的承诺）
    let T_commit = pk.g_commit * alpha_i + pk.h_commit * alpha_blinding_i;
    
    // 6. 计算Fiat-Shamir挑战
    let challenge = hash_to_fr(&[
        &serialize_g1(&A_prime),
        &serialize_g1(&A_bar),
        &serialize_g1(&d),
        &serialize_g1(tag),
        &serialize_g1(&committed_i),
        &serialize_g1(&T1),
        &serialize_g1(&T2),
        &serialize_g1(&T_tag),
        &serialize_g1(&T_commit),
        &range_proof,
    ]);
    
    // 7. 计算响应值
    let z_z = alpha_z + challenge * z;
    let z_r = alpha_r + challenge * r;
    let z_e = alpha_e + challenge * e;
    let z_r2 = alpha_r2 + challenge * r2;
    let z_r3 = alpha_r3 + challenge * r3;
    let z_i = alpha_i + challenge * i_fr;
    let z_blinding_i = alpha_blinding_i + challenge * blinding_i;
    
    Ok(UnifiedProof {
        A_prime,
        A_bar,
        d,
        T1,
        T2,
        T_tag,
        T_commit,
        committed_i,
        z_z,
        z_r,
        z_e,
        z_r2,
        z_r3,
        z_i,
        z_blinding_i,
        range_proof,
        usage_limit: credential.usage_limit,
        challenge,
    })
}

fn verify_unified_proof(
    pk: &BBSPublicKey,
    tag: &G1Projective,
    proof: &UnifiedProof,
) -> Result<bool> {
    // 1. 检查 A' ≠ 1（单位元）
    if proof.A_prime == G1Projective::default() {
        return Err(CredentialError::VerificationError("A'不能为单位元".to_string()));
    }
    
    // 2. 验证配对等式 e(A', pk) = e(Ā, w)
    use ark_ec::pairing::Pairing;
    use ark_bls12_381::Bls12_381;
    
    let lhs = Bls12_381::pairing(proof.A_prime, pk.issuer_pk);
    let rhs = Bls12_381::pairing(proof.A_bar, pk.w);
    
    if lhs != rhs {
        return Err(CredentialError::VerificationError("配对验证失败".to_string()));
    }
    
    // 3. 重新计算挑战
    let challenge_verify = hash_to_fr(&[
        &serialize_g1(&proof.A_prime),
        &serialize_g1(&proof.A_bar),
        &serialize_g1(&proof.d),
        &serialize_g1(tag),
        &serialize_g1(&proof.committed_i),
        &serialize_g1(&proof.T1),
        &serialize_g1(&proof.T2),
        &serialize_g1(&proof.T_tag),
        &serialize_g1(&proof.T_commit),
        &proof.range_proof,
    ]);
    
    if challenge_verify != proof.challenge {
        return Err(CredentialError::VerificationError("挑战值不匹配".to_string()));
    }
    
    // 4. 验证Schnorr响应
    
    // 验证关系1：Ā/d = A'^(-e) * g0^r2
    // => A'^(-z_e) * g0^z_r2 = T1 * (Ā/d)^c
    let lhs1 = proof.A_prime * (Fr::ZERO - proof.z_e) + pk.g0 * proof.z_r2;
    let A_bar_div_d = proof.A_bar - proof.d;
    let rhs1 = proof.T1 + A_bar_div_d * proof.challenge;
    
    if lhs1 != rhs1 {
        return Err(CredentialError::VerificationError("关系1验证失败".to_string()));
    }
    
    // 验证关系2：g = d^r3 * g0^(-z) * g1^(-r)
    // 推导：d = b*r1 - g0*r2 => d*r3 = b - g0*r2*r3 = g + g0*s + g1*r - g0*r2*r3
    //      = g + g0*(s - r2*r3) + g1*r = g + g0*z + g1*r
    // 所以：g = d*r3 - g0*z - g1*r ✓
    // Schnorr验证：d^z_r3 - g0^z_z - g1^z_r = T2 + g^c
    let lhs2 = proof.d * proof.z_r3 - pk.g0 * proof.z_z - pk.g1 * proof.z_r;
    let rhs2 = proof.T2 + pk.g * proof.challenge;
    
    if lhs2 != rhs2 {
        return Err(CredentialError::VerificationError("关系2验证失败".to_string()));
    }
    
    // 验证关系3：tag^r * tag^i = h
    // => tag^z_r * tag^z_i = T_tag * h^c
    let lhs3 = *tag * proof.z_r + *tag * proof.z_i;
    let rhs3 = proof.T_tag + pk.h * proof.challenge;
    
    if lhs3 != rhs3 {
        return Err(CredentialError::VerificationError("tag关系验证失败".to_string()));
    }
    
    // 验证承诺：g_commit^z_i * h_commit^z_blinding_i = T_commit * committed_i^c
    let lhs4 = pk.g_commit * proof.z_i + pk.h_commit * proof.z_blinding_i;
    let rhs4 = proof.T_commit + proof.committed_i * proof.challenge;
    
    if lhs4 != rhs4 {
        return Err(CredentialError::VerificationError("承诺验证失败".to_string()));
    }
    
    // 5. 验证Sigma范围证明
    verify_range_proof(&proof.range_proof, &proof.committed_i, pk, proof.usage_limit)?;
    
    Ok(true)
}

// ========== Sigma-protocol范围证明辅助函数 ==========

/// 计算比特长度
fn compute_bit_length(usage_limit: u32) -> usize {
    if usage_limit <= 1 {
        return 1;
    }
    (usage_limit as f64).log2().ceil() as usize
}

/// 将值分解为比特数组（小端序）
fn decompose_to_bits(value: u32, bit_length: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bit_length);
    let mut v = value;
    for _ in 0..bit_length {
        bits.push((v & 1) == 1);
        v >>= 1;
    }
    bits
}

/// 生成单个比特的0/1证明（Schnorr OR证明）
/// 证明：承诺C满足 C = g^0·h^r 或 C = g^1·h^r（即承诺的值是0或1）
fn generate_bit_proof(
    g: &G1Projective,
    h: &G1Projective,
    commitment: &G1Projective,
    bit: bool,
    blinding: &Fr,
) -> Result<BitProof> {
    let mut rng = OsRng;
    
    // Schnorr OR证明：证明者知道(b, r)使得 C = g^b·h^r 且 b ∈ {0,1}
    // 如果bit=0，我们模拟bit=1的分支；反之亦然
    
    let (c0, c1, z0, z1, zr) = if !bit {
        // 实际bit=0，模拟bit=1分支
        // 真实分支（bit=0）：C = h^r
        let alpha_r = Fr::rand(&mut rng);
        let t0 = *h * alpha_r;  // t0 = h^alpha_r
        
        // 模拟分支（bit=1）：C/g = h^r，选择随机c1, z1
        let c1_sim = Fr::rand(&mut rng);
        let z1_sim = Fr::rand(&mut rng);
        let t1 = *h * z1_sim - (*commitment - g) * c1_sim;  // t1 = h^z1 / (C/g)^c1
        
        // 计算总挑战
        let challenge_total = hash_to_fr(&[
            &serialize_g1(commitment),
            &serialize_g1(&t0),
            &serialize_g1(&t1),
        ]);
        
        // 实际挑战 c0 = challenge_total - c1
        let c0_real = challenge_total - c1_sim;
        
        // 计算响应 z0 = alpha_r + c0 * r
        let z0_real = alpha_r + c0_real * blinding;
        
        (c0_real, c1_sim, z0_real, z1_sim, alpha_r + c0_real * blinding)
    } else {
        // 实际bit=1，模拟bit=0分支
        // 真实分支（bit=1）：C = g·h^r
        let alpha_r = Fr::rand(&mut rng);
        let t1 = *h * alpha_r;  // t1 = h^alpha_r
        
        // 模拟分支（bit=0）：C = h^r，选择随机c0, z0
        let c0_sim = Fr::rand(&mut rng);
        let z0_sim = Fr::rand(&mut rng);
        let t0 = *h * z0_sim - *commitment * c0_sim;  // t0 = h^z0 / C^c0
        
        // 计算总挑战
        let challenge_total = hash_to_fr(&[
            &serialize_g1(commitment),
            &serialize_g1(&t0),
            &serialize_g1(&t1),
        ]);
        
        // 实际挑战 c1 = challenge_total - c0
        let c1_real = challenge_total - c0_sim;
        
        // 计算响应 z1 = alpha_r + c1 * r
        let z1_real = alpha_r + c1_real * blinding;
        
        (c0_sim, c1_real, z0_sim, z1_real, alpha_r + c1_real * blinding)
    };
    
    Ok(BitProof {
        c0: serialize_fr(&c0),
        c1: serialize_fr(&c1),
        z0: serialize_fr(&z0),
        z1: serialize_fr(&z1),
        zr: serialize_fr(&zr),
    })
}

/// 验证单个比特的0/1证明
fn verify_bit_proof(
    g: &G1Projective,
    h: &G1Projective,
    commitment: &G1Projective,
    proof: &BitProof,
) -> Result<bool> {
    let c0 = deserialize_fr(&proof.c0)?;
    let c1 = deserialize_fr(&proof.c1)?;
    let z0 = deserialize_fr(&proof.z0)?;
    let z1 = deserialize_fr(&proof.z1)?;
    let zr = deserialize_fr(&proof.zr)?;
    let _ = zr;  // 暂时未使用
    
    // 重新计算承诺
    // 分支0（bit=0）：C = h^r => h^z0 = t0·C^c0
    let t0 = *h * z0 - *commitment * c0;
    
    // 分支1（bit=1）：C = g·h^r => h^z1 = t1·(C/g)^c1
    let t1 = *h * z1 - (*commitment - g) * c1;
    
    // 重新计算总挑战
    let challenge_total = hash_to_fr(&[
        &serialize_g1(commitment),
        &serialize_g1(&t0),
        &serialize_g1(&t1),
    ]);
    
    // 验证 c0 + c1 = challenge_total
    if c0 + c1 != challenge_total {
        return Ok(false);
    }
    
    Ok(true)
}

/// 生成Sigma范围证明：使用预先生成的比特承诺
fn generate_sigma_range_proof_with_commitments(
    pk: &BBSPublicKey,
    bits: &[bool],
    bit_commitments: &[G1Projective],
    bit_blindings: &[Fr],
) -> Result<Vec<u8>> {
    let mut bit_proofs = Vec::new();
    
    for (i, &bit) in bits.iter().enumerate() {
        let bit_commitment = &bit_commitments[i];
        let bit_blinding = &bit_blindings[i];
        
        // 生成0/1证明
        let bit_proof = generate_bit_proof(
            &pk.g_commit,
            &pk.h_commit,
            bit_commitment,
            bit,
            bit_blinding,
        )?;
        
        bit_proofs.push(bit_proof);
    }
    
    // 序列化比特承诺
    let bit_commitments_serialized: Vec<Vec<u8>> = bit_commitments
        .iter()
        .map(|c| serialize_g1(c))
        .collect();
    
    let sigma_proof = SigmaRangeProof {
        bit_commitments: bit_commitments_serialized,
        bit_proofs,
    };
    
    // 序列化为字节
    serde_json::to_vec(&sigma_proof)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))
}

/// 验证Sigma范围证明
fn verify_sigma_range_proof(
    pk: &BBSPublicKey,
    committed_i: &G1Projective,
    usage_limit: u32,
    proof: &SigmaRangeProof,
) -> Result<bool> {
    let bit_length = compute_bit_length(usage_limit);
    
    // 1. 检查证明长度
    if proof.bit_commitments.len() != bit_length || proof.bit_proofs.len() != bit_length {
        return Err(CredentialError::VerificationError("范围证明比特数量不匹配".to_string()));
    }
    
    // 2. 验证每个比特的0/1证明
    let mut reconstructed_commitment = G1Projective::default();  // 单位元
    
    for (i, bit_proof) in proof.bit_proofs.iter().enumerate() {
        let bit_commitment = deserialize_g1(&proof.bit_commitments[i])?;
        
        // 验证比特证明
        if !verify_bit_proof(&pk.g_commit, &pk.h_commit, &bit_commitment, bit_proof)? {
            return Err(CredentialError::VerificationError(
                format!("比特{}的0/1证明验证失败", i)
            ));
        }
        
        // 重构承诺：committed_i = Σ(C_i · 2^i)
        // 即 committed_i = g_commit^(Σ b_i·2^i) · h_commit^(Σ r_i)
        let power_of_two = Fr::from(1u64 << i);
        reconstructed_commitment = reconstructed_commitment + bit_commitment * power_of_two;
    }
    
    // 3. 验证重构的承诺匹配
    if reconstructed_commitment != *committed_i {
        return Err(CredentialError::VerificationError("重构承诺不匹配".to_string()));
    }
    
    // 注意：我们证明的是 index ∈ [0, 2^bit_length-1]
    // 调用者需要确保 usage_limit ≤ 2^bit_length 且 index ∈ [1, usage_limit]
    
    Ok(true)
}

/// 验证Sigma范围证明（包装函数）
fn verify_range_proof(
    proof_bytes: &[u8],
    committed_i: &G1Projective,
    pk: &BBSPublicKey,
    usage_limit: u32,
) -> Result<bool> {
    // 反序列化Sigma证明
    let sigma_proof: SigmaRangeProof = serde_json::from_slice(proof_bytes)
        .map_err(|e| CredentialError::VerificationError(format!("范围证明反序列化失败: {:?}", e)))?;
    
    // 验证Sigma范围证明
    verify_sigma_range_proof(pk, committed_i, usage_limit, &sigma_proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbs_secret_key_serialization() {
        // 生成密钥对
        let (pk, sk) = BBSScheme::keygen().unwrap();
        
        // 序列化私钥
        let serialized = serde_json::to_string(&sk).unwrap();
        
        // 反序列化私钥
        let deserialized: BBSSecretKey = serde_json::from_str(&serialized).unwrap();
        
        // 验证反序列化的私钥与原私钥相等
        assert_eq!(sk.inner.0, deserialized.inner.0);
        
        // 验证反序列化的私钥可以正常使用
        let user_sk = BBSScheme::generate_user_sk();
        let request = BBSScheme::issue_request(&pk, &user_sk, 3).unwrap();
        let response = BBSScheme::issue_response(&pk, &deserialized, &request).unwrap();
        let credential = BBSScheme::issue_update(&pk, &request, &response, &user_sk).unwrap();
        
        // 验证凭证可以正常展示和验证
        let show = BBSScheme::show_credential(&pk, &user_sk, &credential, 1).unwrap();
        let valid = BBSScheme::verify_credential(&pk, &show).unwrap();
        assert!(valid);
    }
}
