//! RSA签名方案集成测试
//!
//! 测试核心算法流程（tag=msg用于防重放）：
//! 1. keygen - Issuer生成RSA 3072位密钥对
//! 2. issue_request - 用户生成L个随机msg
//! 3. issue_response - Issuer对L个msg签名
//! 4. issue_update - 返回签名
//! 5. show_credentials - 返回(msg_i, sig_i)，tag=msg_i
//! 6. verify_credentials - 验证签名并检查msg重复（在verify内部）

use anonymous_credentials::{
    rsa::{RSAScheme, RSACredential},
    AnonymousCredentialScheme,
    PublicKey,
    SecretKey,
};

#[test]
fn test_rsa_complete_workflow() {
    println!("\n=== RSA签名方案完整流程测试 ===\n");

    // ========== 1. keygen ==========
    println!("【1. keygen】Issuer生成RSA 3072位密钥对...");
    let (issuer_pk, issuer_sk) = RSAScheme::keygen()
        .expect("密钥生成失败");

    println!("✓ 公钥大小: {} bytes", issuer_pk.to_bytes().unwrap().len());
    println!("✓ 私钥大小: {} bytes\n", issuer_sk.to_bytes().unwrap().len());

    // ========== 2. issue_request ==========
    println!("【2. issue_request】用户请求发行凭证...");
    let user_sk = RSAScheme::generate_user_sk();
    let usage_limit = 5; // 请求L=5次使用

    let issue_request = RSAScheme::issue_request(&issuer_pk, &user_sk, usage_limit)
        .expect("创建发行请求失败");

    println!("✓ usage_limit: {}", issue_request.usage_limit);
    println!("✓ blinded_message大小: {} bytes\n", issue_request.blinded_message.len());

    // ========== 3. issue_response ==========
    println!("【3. issue_response】Issuer签发{}个RSA签名...", usage_limit);
    let issue_response = RSAScheme::issue_response(&issuer_sk, &issue_request)
        .expect("签发凭证失败");

    println!("✓ 签名数量: {}", issue_response.blinded_signatures.len());
    assert_eq!(issue_response.blinded_signatures.len(), usage_limit as usize);

    for (i, sig) in issue_response.blinded_signatures.iter().enumerate() {
        println!("  签名[{}]: {} bytes", i+1, sig.len());
    }
    println!();

    // ========== 4. issue_update ==========
    println!("【4. issue_update】用户去盲化获取签名...");
    let signatures = RSAScheme::issue_update(&issuer_pk, &issue_request, &issue_response, &user_sk)
        .expect("去盲化失败");

    println!("✓ 签名数量: {}", signatures.len());
    assert_eq!(signatures.len(), usage_limit as usize);

    // 创建凭证结构
    let credential = RSAScheme::create_credential(&issuer_pk, &issue_request, &issue_response)
        .expect("创建凭证失败");
    let cred_bytes = serde_json::to_vec(&credential).unwrap();
    println!("✓ 凭证总大小: {} bytes\n", cred_bytes.len());

    // ========== 5-6. show_credentials + verify_credentials (多次) ==========
    println!("【5-6. show_credentials + verify_credentials】用户多次使用凭证...\n");

    for i in 1..=usage_limit {
        println!("  --- 第 {}/{} 次使用 ---", i, usage_limit);

        // 5. show_credentials: 生成展示，tag=msg_i
        let show = RSAScheme::show_credential(
            &issuer_pk,
            &user_sk,
            &cred_bytes,
            i,
        ).expect(&format!("第{}次展示失败", i));

        println!("  show_credentials:");
        println!("    tag (msg): {} bytes", show.tag.len());
        println!("    proof (sig): {} bytes", show.proof.len());

        // 6. verify_credentials: 验证签名并检查msg重复
        let valid = RSAScheme::verify_credential(&issuer_pk, &show)
            .expect(&format!("第{}次验证失败", i));

        assert!(valid, "第{}次验证应该通过", i);
        println!("  verify_credentials: PASS ✓");
        println!("    ✓ 签名验证通过");
        println!("    ✓ tag未重复（已记录）\n");
    }

    // ========== 测试重放攻击防御 ==========
    println!("【测试重放攻击】重复使用第1次的tag应该失败...");
    let show_1 = RSAScheme::show_credential(&issuer_pk, &user_sk, &cred_bytes, 1).unwrap();
    let replay_result = RSAScheme::verify_credential(&issuer_pk, &show_1);

    assert!(replay_result.is_err(), "重放攻击应该被拒绝");
    println!("✓ 重放攻击被成功拒绝（tag已存在）\n");

    // ========== 测试边界条件 ==========
    println!("【边界测试】超出usage_limit的index应该失败...");
    let show_6 = RSAScheme::show_credential(&issuer_pk, &user_sk, &cred_bytes, 6);
    assert!(show_6.is_err(), "index=6 应该失败");
    println!("✓ index=6 超出范围，正确拒绝\n");

    println!("=== ✅ 所有测试通过！ ===\n");
}

#[test]
fn test_rsa_multiple_users() {
    println!("\n=== 测试多用户场景 ===\n");

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

        // 3. issue_response
        let response = RSAScheme::issue_response(&issuer_sk, &request).unwrap();
        println!("  3. issue_response: {} 个签名 ✓", response.blinded_signatures.len());

        // 4. create_credential（去盲化）
        let credential = RSAScheme::create_credential(&issuer_pk, &request, &response).unwrap();
        let cred_bytes = serde_json::to_vec(&credential).unwrap();
        println!("  4. create_credential ✓");

        // 5-6. show_credentials + verify_credentials (使用2次)
        for i in 1..=2 {
            let show = RSAScheme::show_credential(&issuer_pk, &user_sk, &cred_bytes, i).unwrap();
            let valid = RSAScheme::verify_credential(&issuer_pk, &show).unwrap();
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
    let request1 = RSAScheme::issue_request(&issuer_pk, &[], 3).unwrap();
    let response1 = RSAScheme::issue_response(&issuer_sk, &request1).unwrap();
    let cred1 = RSAScheme::create_credential(&issuer_pk, &request1, &response1).unwrap();

    // 用户2
    let request2 = RSAScheme::issue_request(&issuer_pk, &[], 3).unwrap();
    let response2 = RSAScheme::issue_response(&issuer_sk, &request2).unwrap();
    let cred2 = RSAScheme::create_credential(&issuer_pk, &request2, &response2).unwrap();

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
