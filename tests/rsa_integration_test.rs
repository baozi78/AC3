//! RSA签名方案集成测试
//!
//! 测试核心算法流程（tag=msg用于防重放）：
//! 1. keygen - Issuer生成RSA 3072位密钥对
//! 2. issue_request - 用户生成L个随机msg
//! 3. issue_response - Issuer对L个msg签名
//! 4. issue_update - 用户生成最后凭证
//! 5. show_credentials - 返回(msg_i, sig_i)，tag=msg_i
//! 6. verify_credentials - issuer验证签名并检查msg重复（在verify内部）
//!
//! 新特点：
//! - 使用类型安全的trait设计
//! - 在测试层面处理序列化，模拟网络传输
//! - 6个核心函数保持无序列化的原生数据类型

use anonymous_credentials::{
    rsa::{RSAScheme, RSAIssueRequest, RSAIssueResponse, RSACredentialShow},
    AnonymousCredentialScheme,
};
use serde_json;

#[test]
fn test_rsa_complete_workflow() {
    println!("\n=== RSA签名方案完整流程测试（新trait设计） ===\n");

    // ========== 1. keygen ==========
    println!("【1. keygen】Issuer生成RSA 3072位密钥对...");
    let (issuer_pk, issuer_sk) = RSAScheme::keygen()
        .expect("密钥生成失败");

    println!("✓ 密钥生成成功\n");

    // ========== 2. issue_request ==========
    println!("【2. issue_request】用户请求发行凭证...");
    let user_sk = RSAScheme::generate_user_sk();
    let usage_limit = 5; // 请求L=5次使用

    let issue_request = RSAScheme::issue_request(&issuer_pk, &user_sk, usage_limit)
        .expect("创建发行请求失败");

    println!("✓ usage_limit: {}", issue_request.usage_limit);
    println!("✓ 盲化消息数量: {}", issue_request.blind_messages.len());

    // 模拟网络传输：用户 → Issuer
    let request_bytes = serde_json::to_vec(&issue_request).unwrap();
    println!("✓ 序列化请求: {} bytes", request_bytes.len());
    let received_request: RSAIssueRequest = serde_json::from_slice(&request_bytes).unwrap();

    // ========== 3. issue_response ==========
    println!("\n【3. issue_response】Issuer签发{}个RSA签名...", usage_limit);
    let issue_response = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &received_request)
        .expect("签发凭证失败");

    println!("✓ 盲签名数量: {}", issue_response.blind_signatures.len());
    assert_eq!(issue_response.blind_signatures.len(), usage_limit as usize);

    for (i, sig) in issue_response.blind_signatures.iter().enumerate() {
        println!("  盲签名[{}]: {} bytes", i+1, sig.len());
    }

    // 模拟网络传输：Issuer → 用户
    let response_bytes = serde_json::to_vec(&issue_response).unwrap();
    println!("✓ 序列化响应: {} bytes", response_bytes.len());
    let received_response: RSAIssueResponse = serde_json::from_slice(&response_bytes).unwrap();

    // ========== 4. issue_update ==========
    println!("\n【4. issue_update】用户去盲化获取签名...");
    let credential = RSAScheme::issue_update(&issuer_pk, &issue_request, &received_response, &user_sk)
        .expect("去盲化失败");

    println!("✓ 消息数量: {}", credential.messages.len());
    println!("✓ 签名数量: {}", credential.signatures.len());
    assert_eq!(credential.messages.len(), usage_limit as usize);
    assert_eq!(credential.signatures.len(), usage_limit as usize);
    assert_eq!(credential.usage_limit, usage_limit);

    // ========== 5-6. show_credentials + verify_credentials (多次) ==========
    println!("\n【5-6. show_credentials + verify_credentials】用户多次使用凭证...\n");

    for i in 1..=usage_limit {
        println!("  --- 第 {}/{} 次使用 ---", i, usage_limit);

        // 5. show_credentials: 生成展示，tag=msg_i
        let show = RSAScheme::show_credential(
            &issuer_pk,
            &user_sk,
            &credential,
            i,
        ).expect(&format!("第{}次展示失败", i));

        println!("  show_credentials:");
        println!("    tag (msg): {} bytes", show.tag.len());
        println!("    signature: {} bytes", show.signature.len());

        // 模拟网络传输：用户 → 验证者
        let show_bytes = serde_json::to_vec(&show).unwrap();
        println!("    序列化展示: {} bytes", show_bytes.len());
        let received_show: RSACredentialShow = serde_json::from_slice(&show_bytes).unwrap();

        // 6. verify_credentials: 验证签名并检查msg重复
        let valid = RSAScheme::verify_credential(&issuer_pk, &received_show)
            .expect(&format!("第{}次验证失败", i));

        assert!(valid, "第{}次验证应该通过", i);
        println!("  verify_credentials: PASS ✓");
        println!("    ✓ 签名验证通过");
        println!("    ✓ tag未重复（已记录）\n");
    }

    // ========== 测试重放攻击防御 ==========
    println!("【测试重放攻击】重复使用第1次的tag应该失败...");
    let show_1 = RSAScheme::show_credential(&issuer_pk, &user_sk, &credential, 1).unwrap();
    let replay_result = RSAScheme::verify_credential(&issuer_pk, &show_1);

    assert!(replay_result.is_err(), "重放攻击应该被拒绝");
    println!("✓ 重放攻击被成功拒绝（tag已存在）\n");

    // ========== 测试边界条件 ==========
    println!("【边界测试】超出usage_limit的index应该失败...");
    let show_6 = RSAScheme::show_credential(&issuer_pk, &user_sk, &credential, 6);
    assert!(show_6.is_err(), "index=6 应该失败");
    println!("✓ index=6 超出范围，正确拒绝\n");

    println!("=== ✅ 所有测试通过！ ===\n");
}

#[test]
fn test_rsa_multiple_users() {
    println!("\n=== 测试多用户RSA场景 ===\n");

    // 1. keygen
    let (issuer_pk, issuer_sk) = RSAScheme::keygen().unwrap();
    println!("【keygen】Issuer密钥已生成\n");

    // 模拟3个用户
    for user_id in 1..=3 {
        println!("【用户 {}】", user_id);

        let user_sk = RSAScheme::generate_user_sk();
        let usage_limit = 3;

        // 2. issue_request
        let request = RSAScheme::issue_request(&issuer_pk, &user_sk, usage_limit).unwrap();
        println!("  2. issue_request ✓");

        // 模拟序列化传输
        let request_bytes = serde_json::to_vec(&request).unwrap();
        let received_request: RSAIssueRequest = serde_json::from_slice(&request_bytes).unwrap();

        // 3. issue_response
        let response = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &received_request).unwrap();
        println!("  3. issue_response: {} 个签名 ✓", response.blind_signatures.len());

        // 模拟序列化传输
        let response_bytes = serde_json::to_vec(&response).unwrap();
        let received_response: RSAIssueResponse = serde_json::from_slice(&response_bytes).unwrap();

        // 4. issue_update
        let credential = RSAScheme::issue_update(&issuer_pk, &request, &received_response, &user_sk).unwrap();
        println!("  4. issue_update ✓");

        // 5-6. show_credentials + verify_credentials (使用2次)
        for i in 1..=2 {
            let show = RSAScheme::show_credential(&issuer_pk, &user_sk, &credential, i).unwrap();
            
            // 模拟序列化传输
            let show_bytes = serde_json::to_vec(&show).unwrap();
            let received_show: RSACredentialShow = serde_json::from_slice(&show_bytes).unwrap();
            
            let valid = RSAScheme::verify_credential(&issuer_pk, &received_show).unwrap();
            assert!(valid);
            println!("  5-6. show+verify (index={}): PASS ✓", i);
        }

        println!();
    }

    println!("=== ✅ 多用户测试通过！ ===\n");
}

#[test]
fn test_rsa_tag_uniqueness() {
    println!("\n=== 验证不同消息生成不同的tag ===\n");

    let (issuer_pk, issuer_sk) = RSAScheme::keygen().unwrap();

    // 用户1
    let user_sk_1 = RSAScheme::generate_user_sk();
    let request1 = RSAScheme::issue_request(&issuer_pk, &user_sk_1, 3).unwrap();
    let response1 = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &request1).unwrap();
    let cred1 = RSAScheme::issue_update(&issuer_pk, &request1, &response1, &user_sk_1).unwrap();

    // 用户2
    let user_sk_2 = RSAScheme::generate_user_sk();
    let request2 = RSAScheme::issue_request(&issuer_pk, &user_sk_2, 3).unwrap();
    let response2 = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &request2).unwrap();
    let cred2 = RSAScheme::issue_update(&issuer_pk, &request2, &response2, &user_sk_2).unwrap();

    // 验证：不同用户的消息（tag）应该不同
    assert_ne!(cred1.messages[0], cred2.messages[0], "不同用户的msg应该不同");
    println!("✓ 用户1的msg[1]: {} bytes", cred1.messages[0].len());
    println!("✓ 用户2的msg[1]: {} bytes", cred2.messages[0].len());
    println!("✓ 两个msg不相同\n");

    // 验证：同一用户的不同消息应该不同
    assert_ne!(cred1.messages[0], cred1.messages[1], "同一用户的不同msg应该不同");
    println!("✓ 用户1的msg[1] ≠ msg[2]\n");

    println!("=== ✅ Tag唯一性测试通过！ ===\n");
}

#[test]
fn test_rsa_serialization_compatibility() {
    println!("\n=== 测试序列化兼容性 ===\n");

    let (issuer_pk, issuer_sk) = RSAScheme::keygen().unwrap();
    let user_sk = RSAScheme::generate_user_sk();

    // 测试各个阶段的序列化/反序列化
    let request = RSAScheme::issue_request(&issuer_pk, &user_sk, 2).unwrap();
    let request_json = serde_json::to_string_pretty(&request).unwrap();
    println!("Request JSON size: {} bytes", request_json.len());

    let response = RSAScheme::issue_response(&issuer_pk, &issuer_sk, &request).unwrap();
    let response_json = serde_json::to_string_pretty(&response).unwrap();
    println!("Response JSON size: {} bytes", response_json.len());

    let credential = RSAScheme::issue_update(&issuer_pk, &request, &response, &user_sk).unwrap();
    let credential_json = serde_json::to_string_pretty(&credential).unwrap();
    println!("Credential JSON size: {} bytes", credential_json.len());

    let show = RSAScheme::show_credential(&issuer_pk, &user_sk, &credential, 1).unwrap();
    let show_json = serde_json::to_string_pretty(&show).unwrap();
    println!("Show JSON size: {} bytes", show_json.len());

    // 验证往返序列化
    let decoded_request: RSAIssueRequest = serde_json::from_str(&request_json).unwrap();
    assert_eq!(decoded_request.usage_limit, request.usage_limit);

    let decoded_show: RSACredentialShow = serde_json::from_str(&show_json).unwrap();
    assert_eq!(decoded_show.tag, show.tag);

    println!("✓ 所有数据结构序列化/反序列化成功\n");

    println!("=== ✅ 序列化测试通过！ ===\n");
}