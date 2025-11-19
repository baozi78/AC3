use crate::error::{CredentialError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Tag池，用于防止重放攻击
/// 只需要检查tag是否已使用，不需要credential_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagPool {
    /// 存储所有已使用的tag
    used_tags: HashSet<Vec<u8>>,
}

impl TagPool {
    /// 创建新的Tag池
    pub fn new() -> Self {
        Self {
            used_tags: HashSet::new(),
        }
    }

    /// 检查并记录tag使用
    /// 如果tag已被使用，返回错误
    pub fn check_and_record_tag(&mut self, tag: &[u8]) -> Result<()> {
        // 检查tag是否已使用
        if self.used_tags.contains(tag) {
            return Err(CredentialError::TagAlreadyUsed);
        }

        // 记录tag
        self.used_tags.insert(tag.to_vec());

        Ok(())
    }

    /// 检查tag是否已被使用（只读）
    pub fn is_tag_used(&self, tag: &[u8]) -> bool {
        self.used_tags.contains(tag)
    }

    /// 获取已使用的tag总数
    pub fn get_used_count(&self) -> usize {
        self.used_tags.len()
    }

    /// 清空tag池
    pub fn clear(&mut self) {
        self.used_tags.clear();
    }
}

impl Default for TagPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_pool_basic() {
        let mut pool = TagPool::new();
        let tag1 = b"tag1";
        let tag2 = b"tag2";

        // 第一次使用tag1
        assert!(pool.check_and_record_tag(tag1).is_ok());
        assert_eq!(pool.get_used_count(), 1);

        // 重复使用tag1应该失败
        assert!(pool.check_and_record_tag(tag1).is_err());
        assert_eq!(pool.get_used_count(), 1);

        // 使用不同的tag2
        assert!(pool.check_and_record_tag(tag2).is_ok());
        assert_eq!(pool.get_used_count(), 2);

        // 检查tag状态
        assert!(pool.is_tag_used(tag1));
        assert!(pool.is_tag_used(tag2));
        assert!(!pool.is_tag_used(b"tag3"));
    }

    #[test]
    fn test_tag_pool_clear() {
        let mut pool = TagPool::new();
        pool.check_and_record_tag(b"tag1").unwrap();
        pool.check_and_record_tag(b"tag2").unwrap();

        assert_eq!(pool.get_used_count(), 2);

        pool.clear();
        assert_eq!(pool.get_used_count(), 0);

        // 清空后可以重新使用
        assert!(pool.check_and_record_tag(b"tag1").is_ok());
    }
}
