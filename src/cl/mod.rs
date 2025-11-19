//! CL (Camenisch-Lysyanskaya) 签名方案实现
//!
//! TODO: 实现真正的CL盲签名

use crate::error::Result;
use crate::traits::{
    AnonymousCredentialScheme, PublicKey, SecretKey,
    IssueRequest, IssueResponse, CredentialShow
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLPublicKey {
    data: Vec<u8>,
}

impl PublicKey for CLPublicKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

#[derive(Clone, Debug)]
pub struct CLSecretKey {
    data: Vec<u8>,
}

impl SecretKey for CLSecretKey {
    fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { data: bytes.to_vec() })
    }
}

pub struct CLScheme;

impl AnonymousCredentialScheme for CLScheme {
    type PublicKey = CLPublicKey;
    type SecretKey = CLSecretKey;

    fn keygen() -> Result<(Self::PublicKey, Self::SecretKey)> {
        todo!("实现CL密钥生成")
    }

    fn generate_user_sk() -> Vec<u8> {
        todo!("实现CL用户私钥生成")
    }

    fn issue_request(
        _pk: &Self::PublicKey,
        _user_sk: &[u8],
        _usage_limit: u32,
    ) -> Result<IssueRequest> {
        todo!("实现CL发行请求")
    }

    fn issue_response(
        _issuer_sk: &Self::SecretKey,
        _request: &IssueRequest,
    ) -> Result<IssueResponse> {
        todo!("实现CL发行响应")
    }

    fn issue_update(
        _pk: &Self::PublicKey,
        _request: &IssueRequest,
        _response: &IssueResponse,
        _user_sk: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        todo!("实现CL去盲化")
    }

    fn show_credential(
        _pk: &Self::PublicKey,
        _user_sk: &[u8],
        _credential: &[u8],
        _index: u32,
    ) -> Result<CredentialShow> {
        todo!("实现CL凭证展示")
    }

    fn verify_credential(
        _pk: &Self::PublicKey,
        _show: &CredentialShow,
    ) -> Result<bool> {
        todo!("实现CL凭证验证")
    }
}
