//! # Anonymous Credentials Library
//!
//! 支持三种签名方案的n次匿名凭证系统：
//! - CL (Camenisch-Lysyanskaya) 签名
//! - BBS (Boneh-Boyen-Shacham) 签名
//! - RSA 盲签名
//!
//! 所有方案都支持：
//! - 盲发行（blind issuance）
//! - 使用次数限制（L次）
//! - 防重放攻击（tag池）
//! - 零知识证明（CL和BBS使用bulletproofs范围证明）

pub mod error;
pub mod traits;
pub mod tag_pool;

// 三个签名方案模块
pub mod cl;
pub mod bbs;
pub mod rsa;

// 重新导出常用类型
pub use error::{CredentialError, Result};
pub use traits::{
    AnonymousCredentialScheme,
    PublicKey,
    SecretKey,
};
pub use tag_pool::TagPool;
