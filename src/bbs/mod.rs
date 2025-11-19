//! BBS (Boneh-Boyen-Shacham) 签名方案实现

use crate::error::Result;
use crate::traits::{AnonymousCredentialScheme, PublicKey, SecretKey, IssueRequest, IssueResponse, CredentialShow};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BBSPublicKey {
    // TODO: 实现
    data: Vec<u8>,
}

impl PublicKey for BBSPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

#[derive(Clone, Debug)]
pub struct BBSSecretKey {
    // TODO: 实现
    data: Vec<u8>,
}

impl SecretKey for BBSSecretKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

pub struct BBSScheme;

impl AnonymousCredentialScheme for BBSScheme {
    type PublicKey = BBSPublicKey;
    type SecretKey = BBSSecretKey;

    fn generate_user_sk() -> Vec<u8> {
        // TODO: 生成BBS用户私钥
        vec![0u8; 32]
    }

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        todo!("实现BBS密钥生成")
    }

    fn issue_request(_pk: &Self::PublicKey, _user_sk: &[u8], _usage_limit: u32) -> Result<IssueRequest> {
        todo!("实现BBS发行请求")
    }

    fn issue_response(
        issuer_sk: &Self::SecretKey,
        request: &IssueRequest,
    ) -> Result<IssueResponse> {
        todo!("实现BBS发行响应")
    }

    fn issue_update(
        _pk: &Self::PublicKey,
        _request: &IssueRequest,
        _response: &IssueResponse,
        _user_sk: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        todo!("实现BBS去盲化")
    }

    fn show_credential(
        pk: &Self::PublicKey,
        user_sk: &[u8],
        credential: &[u8],
        index: u32,
    ) -> Result<CredentialShow> {
        todo!("实现BBS凭证展示")
    }

    fn verify_credential(
        pk: &Self::PublicKey,
        show: &CredentialShow,
    ) -> Result<bool> {
        todo!("实现BBS凭证验证")
    }
}
