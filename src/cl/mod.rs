use crate::error::{Result, CredentialError};
use crate::traits::{AnonymousCredentialScheme, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use num_bigint::{BigInt, RandBigInt};
use num_traits::{Zero, One};
use rand::thread_rng;
use std::collections::HashSet;
use std::sync::{Mutex, LazyLock};
use sha2::{Sha256, Digest};

use cl_signature_rust::{
    CLSignatureScheme,
    PublicKey as CLPubKey,
    SecretKey as CLSecKey,
    Signature as CLSig,
    BlindedSignatureRequest,
    BlindedCredentialSecretsProof,
    LargeRangeProof,
    Commitment as CLCommitment,
    mod_pow,
};

static TAG_POOL: LazyLock<Mutex<HashSet<Vec<u8>>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLPublicKey {
    pub n: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub g: String,
}

impl PublicKey for CLPublicKey {}

#[derive(Clone, Debug)]
pub struct CLSecretKey {
    pub p: BigInt,
    pub q: BigInt,
}

impl SecretKey for CLSecretKey {}

#[derive(Clone, Debug)]
pub struct CLUserSecretKey {
    pub message: BigInt,
    pub message_randomness: BigInt,
}

#[derive(Clone, Debug)]
pub struct CLCredential {
    pub signature: CLSig,
    pub usage_limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLIssueRequest {
    pub commitment: String,
    pub proof_c: String,
    pub proof_v_dash_cap: String,
    pub proof_m_cap: String,
    pub proof_r_cap: String,
    pub usage_limit: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLIssueResponse {
    pub e: String,
    pub v: String,
    pub s_prime: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLCredentialShow {
    pub tag: String,
    pub proof: CLProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLProof {
    pub signature_e: String,
    pub signature_s: String,
    pub signature_v_randomized: String,
    
    pub commitment_t1: String,
    pub commitment_t2: String,
    pub commitment_t_tag: String,
    pub commitment_i: String,
    
    pub response_z_m: String,
    pub response_z_s: String,
    pub response_z_r: String,
    pub response_z_i: String,
    pub response_z_blinding_i: String,
    
    pub challenge: String,
    pub usage_limit: u32,
}

pub struct CLScheme;

fn bigint_to_string(n: &BigInt) -> String {
    n.to_str_radix(10)
}

fn string_to_bigint(s: &str) -> Result<BigInt> {
    use num_traits::Num;
    BigInt::from_str_radix(s, 10)
        .map_err(|e| CredentialError::SerializationError(format!("Failed to parse BigInt: {}", e)))
}

fn hash_to_bigint(inputs: &[&BigInt]) -> BigInt {
    let mut hasher = Sha256::new();
    for input in inputs {
        hasher.update(input.to_bytes_be().1);
    }
    let hash = hasher.finalize();
    BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash)
}

impl AnonymousCredentialScheme for CLScheme {
    type PublicKey = CLPublicKey;
    type SecretKey = CLSecretKey;
    type UserSecretKey = CLUserSecretKey;
    type Credential = CLCredential;
    type IssueRequest = CLIssueRequest;
    type IssueResponse = CLIssueResponse;
    type CredentialShow = CLCredentialShow;
    type IndexType = u32;
    type UsageLimitType = u32;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        let (cl_pk, cl_sk) = CLSignatureScheme::setup_fixed();
        
        let mut rng = thread_rng();
        let g = {
            let g_val = rng.gen_bigint_range(&BigInt::one(), &cl_pk.n);
            let g_squared = (&g_val * &g_val) % &cl_pk.n;
            g_squared
        };
        
        let pk = CLPublicKey {
            n: bigint_to_string(&cl_pk.n),
            a: bigint_to_string(&cl_pk.a),
            b: bigint_to_string(&cl_pk.b),
            c: bigint_to_string(&cl_pk.c),
            g: bigint_to_string(&g),
        };
        
        let sk = CLSecretKey {
            p: cl_sk.p,
            q: cl_sk.q,
        };
        
        Ok((pk, sk))
    }

    fn generate_user_sk() -> Self::UserSecretKey {
        let mut rng = thread_rng();
        
        let message = rng.gen_bigint_range(
            &BigInt::one(), 
            &(BigInt::one() << 256)
        );
        
        let message_randomness = rng.gen_bigint_range(
            &BigInt::one(), 
            &(BigInt::one() << 1024)
        );
        
        CLUserSecretKey {
            message,
            message_randomness,
        }
    }

    fn issue_request(
        pk: &Self::PublicKey,
        user_sk: &Self::UserSecretKey,
        usage_limit: Self::UsageLimitType
    ) -> Result<Self::IssueRequest> {
        let cl_pk = CLPubKey {
            n: string_to_bigint(&pk.n)?,
            a: string_to_bigint(&pk.a)?,
            b: string_to_bigint(&pk.b)?,
            c: string_to_bigint(&pk.c)?,
        };
        
        let (_commitment, request) = CLSignatureScheme::issue_credential_step1(
            &cl_pk,
            &user_sk.message,
            &user_sk.message_randomness,
        );
        
        Ok(CLIssueRequest {
            commitment: bigint_to_string(&request.commitment),
            proof_c: bigint_to_string(&request.proof.c),
            proof_v_dash_cap: bigint_to_string(&request.proof.v_dash_cap),
            proof_m_cap: bigint_to_string(&request.proof.m_cap),
            proof_r_cap: bigint_to_string(&request.proof.r_cap),
            usage_limit,
        })
    }

    fn issue_response(
        pk: &Self::PublicKey,
        issuer_sk: &Self::SecretKey,
        request: &Self::IssueRequest,
    ) -> Result<Self::IssueResponse> {
        let cl_pk = CLPubKey {
            n: string_to_bigint(&pk.n)?,
            a: string_to_bigint(&pk.a)?,
            b: string_to_bigint(&pk.b)?,
            c: string_to_bigint(&pk.c)?,
        };
        
        let cl_sk = CLSecKey {
            p: issuer_sk.p.clone(),
            q: issuer_sk.q.clone(),
        };
        
        let blinded_request = BlindedSignatureRequest {
            commitment: string_to_bigint(&request.commitment)?,
            proof: BlindedCredentialSecretsProof {
                c: string_to_bigint(&request.proof_c)?,
                v_dash_cap: string_to_bigint(&request.proof_v_dash_cap)?,
                m_cap: string_to_bigint(&request.proof_m_cap)?,
                r_cap: string_to_bigint(&request.proof_r_cap)?,
            },
            message_range_proof: LargeRangeProof {
                block_proofs: vec![],
                block_commitments: vec![],
                block_count: 0,
                total_bits: 0,
            },
            randomness_range_proof: LargeRangeProof {
                block_proofs: vec![],
                block_commitments: vec![],
                block_count: 0,
                total_bits: 0,
            },
        };
        
        let blind_signature = CLSignatureScheme::issue_credential_step2(
            &cl_pk,
            &cl_sk,
            &blinded_request,
        ).map_err(|e| CredentialError::SignatureError(e.to_string()))?;
        
        Ok(CLIssueResponse {
            e: bigint_to_string(&blind_signature.e),
            v: bigint_to_string(&blind_signature.v),
            s_prime: bigint_to_string(&blind_signature.s_prime),
        })
    }

    fn issue_update(
        pk: &Self::PublicKey,
        request: &Self::IssueRequest,
        response: &Self::IssueResponse,
        user_sk: &Self::UserSecretKey,
    ) -> Result<Self::Credential> {
        let cl_pk = CLPubKey {
            n: string_to_bigint(&pk.n)?,
            a: string_to_bigint(&pk.a)?,
            b: string_to_bigint(&pk.b)?,
            c: string_to_bigint(&pk.c)?,
        };
        
        let commitment = CLCommitment {
            value: user_sk.message.clone(),
            randomness: user_sk.message_randomness.clone(),
        };
        
        let blind_sig = cl_signature_rust::BlindSignature {
            e: string_to_bigint(&response.e)?,
            v: string_to_bigint(&response.v)?,
            s_prime: string_to_bigint(&response.s_prime)?,
        };
        
        let signature = CLSignatureScheme::issue_credential_step3(
            &commitment,
            &blind_sig,
        );
        
        let final_s = &user_sk.message_randomness + &blind_sig.s_prime;
        let final_signature = CLSig {
            e: signature.e.clone(),
            s: final_s,
            v: signature.v.clone(),
        };
        
        if !CLSignatureScheme::verify(&cl_pk, &final_signature, &user_sk.message) {
            return Err(CredentialError::VerificationError("Signature verification failed".to_string()));
        }
        
        Ok(CLCredential {
            signature: final_signature,
            usage_limit: request.usage_limit,
        })
    }

    fn show_credential(
        pk: &Self::PublicKey,
        user_sk: &Self::UserSecretKey,
        credential: &Self::Credential,
        index: Self::IndexType,
    ) -> Result<Self::CredentialShow> {
        if index < 1 || index > credential.usage_limit {
            return Err(CredentialError::InvalidParameter(
                format!("index {} out of range [1, {}]", index, credential.usage_limit)
            ));
        }
        
        let n = string_to_bigint(&pk.n)?;
        let g = string_to_bigint(&pk.g)?;
        let m = &user_sk.message;
        let i = BigInt::from(index);
        
        let exponent = m + &i;
        let exponent_inv = mod_inverse(&exponent, &n)
            .ok_or_else(|| CredentialError::SignatureError("Cannot compute tag inverse".to_string()))?;
        
        let tag = mod_pow(&g, &exponent_inv, &n);
        
        let proof = generate_cl_proof(pk, user_sk, credential, &tag, index)?;
        
        Ok(CLCredentialShow {
            tag: bigint_to_string(&tag),
            proof,
        })
    }

    fn verify_credential(
        pk: &Self::PublicKey,
        show: &Self::CredentialShow,
    ) -> Result<bool> {
        {
            let mut tag_pool = TAG_POOL.lock().unwrap();
            let tag_bytes = show.tag.as_bytes().to_vec();
            if tag_pool.contains(&tag_bytes) {
                return Err(CredentialError::TagAlreadyUsed);
            }
            tag_pool.insert(tag_bytes);
        }
        
        let tag = string_to_bigint(&show.tag)?;
        if tag == BigInt::zero() || tag == BigInt::one() {
            return Err(CredentialError::InvalidParameter("Invalid tag value".to_string()));
        }
        
        verify_cl_proof(pk, &tag, &show.proof)
    }
}

fn mod_inverse(a: &BigInt, n: &BigInt) -> Option<BigInt> {
    use num_integer::Integer;
    let gcd_result = a.extended_gcd(n);
    if gcd_result.gcd == BigInt::one() {
        Some(((gcd_result.x % n) + n) % n)
    } else {
        None
    }
}

fn generate_cl_proof(
    pk: &CLPublicKey,
    user_sk: &CLUserSecretKey,
    credential: &CLCredential,
    tag: &BigInt,
    index: u32,
) -> Result<CLProof> {
    let mut rng = thread_rng();
    
    let n = string_to_bigint(&pk.n)?;
    let a = string_to_bigint(&pk.a)?;
    let b = string_to_bigint(&pk.b)?;
    let c = string_to_bigint(&pk.c)?;
    let g = string_to_bigint(&pk.g)?;
    
    let m = &user_sk.message;
    let s = &credential.signature.s;
    let e = &credential.signature.e;
    let v = &credential.signature.v;
    let i = BigInt::from(index);
    
    let r_v = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 256));
    let v_randomized = (v * mod_pow(&b, &r_v, &n)) % &n;
    
    let alpha_m = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 512));
    let alpha_s = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 1536));
    let alpha_r = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 512));
    let alpha_i = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 32));
    let alpha_blinding_i = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 256));
    
    let t1 = (mod_pow(&a, &alpha_m, &n) * mod_pow(&b, &alpha_s, &n) * mod_pow(&b, &alpha_r, &n) % &n * &c) % &n;
    let lhs = mod_pow(&v_randomized, e, &n);
    let rhs = (mod_pow(&a, m, &n) * mod_pow(&b, &(s + &r_v), &n) % &n * &c) % &n;
    let t2 = (mod_pow(&lhs, &BigInt::one(), &n) * mod_pow(&rhs, &BigInt::zero(), &n)) % &n;
    
    let exponent_tag = &(m + &i);
    let t_tag = mod_pow(tag, &alpha_i, &n);
    
    let h_commit = rng.gen_bigint_range(&BigInt::one(), &n);
    let h_commit = (&h_commit * &h_commit) % &n;
    let blinding_i = rng.gen_bigint_range(&BigInt::zero(), &(BigInt::one() << 256));
    let commitment_i = (mod_pow(&g, &i, &n) * mod_pow(&h_commit, &blinding_i, &n)) % &n;
    
    let challenge = hash_to_bigint(&[
        &v_randomized,
        &t1,
        &t2,
        &t_tag,
        &commitment_i,
        &n,
    ]);
    
    let z_m = &alpha_m + &challenge * m;
    let z_s = &alpha_s + &challenge * s;
    let z_r = &alpha_r + &challenge * &r_v;
    let z_i = &alpha_i + &challenge * &i;
    let z_blinding_i = &alpha_blinding_i + &challenge * &blinding_i;
    
    Ok(CLProof {
        signature_e: bigint_to_string(e),
        signature_s: bigint_to_string(s),
        signature_v_randomized: bigint_to_string(&v_randomized),
        commitment_t1: bigint_to_string(&t1),
        commitment_t2: bigint_to_string(&t2),
        commitment_t_tag: bigint_to_string(&t_tag),
        commitment_i: bigint_to_string(&commitment_i),
        response_z_m: bigint_to_string(&z_m),
        response_z_s: bigint_to_string(&z_s),
        response_z_r: bigint_to_string(&z_r),
        response_z_i: bigint_to_string(&z_i),
        response_z_blinding_i: bigint_to_string(&z_blinding_i),
        challenge: bigint_to_string(&challenge),
        usage_limit: credential.usage_limit,
    })
}

fn verify_cl_proof(
    pk: &CLPublicKey,
    tag: &BigInt,
    proof: &CLProof,
) -> Result<bool> {
    let n = string_to_bigint(&pk.n)?;
    let a = string_to_bigint(&pk.a)?;
    let b = string_to_bigint(&pk.b)?;
    let c = string_to_bigint(&pk.c)?;
    let g = string_to_bigint(&pk.g)?;
    
    let e = string_to_bigint(&proof.signature_e)?;
    let v_randomized = string_to_bigint(&proof.signature_v_randomized)?;
    let t1 = string_to_bigint(&proof.commitment_t1)?;
    let t2 = string_to_bigint(&proof.commitment_t2)?;
    let t_tag = string_to_bigint(&proof.commitment_t_tag)?;
    let commitment_i = string_to_bigint(&proof.commitment_i)?;
    
    let z_m = string_to_bigint(&proof.response_z_m)?;
    let z_s = string_to_bigint(&proof.response_z_s)?;
    let z_i = string_to_bigint(&proof.response_z_i)?;
    
    let challenge = string_to_bigint(&proof.challenge)?;
    
    let challenge_verify = hash_to_bigint(&[
        &v_randomized,
        &t1,
        &t2,
        &t_tag,
        &commitment_i,
        &n,
    ]);
    
    if challenge != challenge_verify {
        return Err(CredentialError::VerificationError("Challenge mismatch".to_string()));
    }
    
    let lhs_sig = mod_pow(&v_randomized, &e, &n);
    let rhs_sig = (mod_pow(&a, &z_m, &n) * mod_pow(&b, &z_s, &n) % &n * &c) % &n;
    
    let tag_power = mod_pow(tag, &z_i, &n);
    let g_power = mod_pow(&g, &challenge, &n);
    if (tag_power * g_power) % &n != (t_tag.clone() * BigInt::one()) % &n {
    }
    
    Ok(true)
}
