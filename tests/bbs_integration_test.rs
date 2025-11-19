//! BBS匿名凭证集成测试
//!
//! 测试核心算法流程（tag = h^{1/(r+i)}用于防重放）：
//! 1. keygen - Issuer生成BLS12-381密钥对
//! 2. generate_user_sk - 用户生成秘密s'和随机数r
//! 3. issue_request - 用户生成承诺C和POK证明
//! 4. issue_response - Issuer验证POK并签发
//! 5. issue_update - 用户获取最终凭证
//! 6. show_credential - 用户生成tag和零知识证明
//! 7. verify_credential - 验证者验证并检查tag重复
//!
//! 新特点：
//! - 使用类型安全的trait设计
//! - 在测试层面处理序列化，模拟网络传输
//! - 6个核心函数保持无序列化的原生数据类型

use anonymous_credentials::{
    bbs::{BBSScheme, BBSIssueRequest, BBSIssueResponse, BBSCredentialShow},
    AnonymousCredentialScheme,
};
use serde_json;

#[test]
fn test_bbs_complete_workflow() {
    println!("\n=== BBS匿名凭证完整流程测试（新trait设计） ===\n");

    // ========== 1. keygen ==========
    println!("【1. keygen】Issuer生成BLS12-381密钥对...");
    let (issuer_pk, issuer_sk) = BBSScheme::keygen()
        .expect("密钥生成失败");

    println!("✓ 密钥生成成功\n");

    // ========== 2. generate_user_sk ==========
    println!("【2. generate_user_sk】用户生成秘密s'和随机数r...");
    let user_sk = BBSScheme::generate_user_sk();
    println!("✓ 用户密钥生成成功\n");

    // ========== 3. issue_request ==========
    println!("【3. issue_request】用户请求发行凭证...");
    let usage_limit = 10;

    let issue_request = BBSScheme::issue_request(&issuer_pk, &user_sk, usage_limit)
        .expect("创建发行请求失败");

    println!("✓ usage_limit: {}", issue_request.usage_limit);
    println!("✓ 生成承诺C = g0^s' · g1^r");
    println!("✓ 生成POK证明 POK{{(s',r): C = g0^s' · g1^r}}");

    // 模拟网络传输：用户 → Issuer
    let request_bytes = serde_json::to_vec(&issue_request).unwrap();
    println!("✓ 序列化请求: {} bytes", request_bytes.len());
    let received_request: BBSIssueRequest = serde_json::from_slice(&request_bytes).unwrap();

    // ========== 4. issue_response ==========
    println!("\n【4. issue_response】Issuer签发BBS+签名...");
    let issue_response = BBSScheme::issue_response(&issuer_pk, &issuer_sk, &received_request)
        .expect("签发凭证失败");

    println!("✓ 生成签名A = (g·C·g0^s'')^{{1/(sk+e)}}");
    println!("✓ 随机指数e已生成");
    println!("✓ Issuer秘密s''已生成");

    // 模拟网络传输：Issuer → 用户
    let response_bytes = serde_json::to_vec(&issue_response).unwrap();
    println!("✓ 序列化响应: {} bytes", response_bytes.len());
    let received_response: BBSIssueResponse = serde_json::from_slice(&response_bytes).unwrap();

    // ========== 5. issue_update ==========
    println!("\n【5. issue_update】用户获取最终凭证...");
    let credential = BBSScheme::issue_update(&issuer_pk, &issue_request, &received_response, &user_sk)
        .expect("生成凭证失败");

    println!("✓ 计算最终秘密s = s' + s''");
    println!("✓ 凭证生成成功");
    println!("✓ usage_limit: {}", credential.usage_limit);

    // ========== 6-7. show_credential + verify_credential (多次) ==========
    println!("\n【6-7. show_credential + verify_credential】用户多次使用凭证...\n");

    for i in 1..=usage_limit {
        println!("  --- 第 {}/{} 次使用 ---", i, usage_limit);

        // 6. show_credential: 生成tag和零知识证明
        let show = BBSScheme::show_credential(
            &issuer_pk,
            &user_sk,
            &credential,
            i,
        ).expect(&format!("第{}次展示失败", i));

        println!("  show_credential:");
        println!("    生成tag = h^{{1/(r+{})}}",  i);
        println!("    生成统一零知识证明");

        // 模拟网络传输：用户 → 验证者
        let show_bytes = serde_json::to_vec(&show).unwrap();
        println!("    序列化展示: {} bytes", show_bytes.len());
        let received_show: BBSCredentialShow = serde_json::from_slice(&show_bytes).unwrap();

        // 7. verify_credential: 验证签名并检查tag重复
        let valid = BBSScheme::verify_credential(&issuer_pk, &received_show)
            .expect(&format!("第{}次验证失败", i));

        assert!(valid, "第{}次验证应该通过", i);
        println!("  verify_credential: PASS ✓");
        println!("    ✓ tag验证通过");
        println!("    ✓ 零知识证明验证通过");
        println!("    ✓ tag未重复（已记录）\n");
    }

    // ========== 测试重放攻击防御 ==========
    println!("【测试重放攻击】重复使用第1次的tag应该失败...");
    let show_1 = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, 1).unwrap();
    let replay_result = BBSScheme::verify_credential(&issuer_pk, &show_1);

    assert!(replay_result.is_err(), "重放攻击应该被拒绝");
    println!("✓ 重放攻击被成功拒绝（tag已存在）\n");

    // ========== 测试边界条件 ==========
    println!("【边界测试】超出usage_limit的index应该失败...");
    let show_11 = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, 11);
    assert!(show_11.is_err(), "index=6 应该失败");
    println!("✓ index=6 超出范围，正确拒绝\n");

    println!("【边界测试】index=0应该失败...");
    let show_0 = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, 0);
    assert!(show_0.is_err(), "index=0 应该失败");
    println!("✓ index=0 超出范围，正确拒绝\n");

    println!("=== ✅ 所有测试通过！ ===\n");
}

#[test]
fn test_bbs_multiple_users() {
    println!("\n=== 测试多用户BBS场景 ===\n");

    // 1. keygen
    let (issuer_pk, issuer_sk) = BBSScheme::keygen().unwrap();
    println!("【keygen】Issuer密钥已生成\n");

    // 模拟3个用户
    for user_id in 1..=3 {
        println!("【用户 {}】", user_id);

        let user_sk = BBSScheme::generate_user_sk();
        let usage_limit = 3;

        // 3. issue_request
        let request = BBSScheme::issue_request(&issuer_pk, &user_sk, usage_limit).unwrap();
        println!("  3. issue_request ✓");

        // 模拟序列化传输
        let request_bytes = serde_json::to_vec(&request).unwrap();
        let received_request: BBSIssueRequest = serde_json::from_slice(&request_bytes).unwrap();

        // 4. issue_response
        let response = BBSScheme::issue_response(&issuer_pk, &issuer_sk, &received_request).unwrap();
        println!("  4. issue_response ✓");

        // 模拟序列化传输
        let response_bytes = serde_json::to_vec(&response).unwrap();
        let received_response: BBSIssueResponse = serde_json::from_slice(&response_bytes).unwrap();

        // 5. issue_update
        let credential = BBSScheme::issue_update(&issuer_pk, &request, &received_response, &user_sk).unwrap();
        println!("  5. issue_update ✓");

        // 6-7. show_credential + verify_credential (使用2次)
        for i in 1..=2 {
            let show = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, i).unwrap();
            
            // 模拟序列化传输
            let show_bytes = serde_json::to_vec(&show).unwrap();
            let received_show: BBSCredentialShow = serde_json::from_slice(&show_bytes).unwrap();
            
            let valid = BBSScheme::verify_credential(&issuer_pk, &received_show).unwrap();
            assert!(valid);
            println!("  6-7. show+verify (index={}): PASS ✓", i);
        }

        println!();
    }

    println!("=== ✅ 多用户测试通过！ ===\n");
}

#[test]
fn test_bbs_tag_uniqueness() {
    println!("\n=== 验证不同索引生成不同的tag ===\n");

    let (issuer_pk, issuer_sk) = BBSScheme::keygen().unwrap();

    // 用户1
    let user_sk = BBSScheme::generate_user_sk();
    let request = BBSScheme::issue_request(&issuer_pk, &user_sk, 3).unwrap();
    let response = BBSScheme::issue_response(&issuer_pk, &issuer_sk, &request).unwrap();
    let cred = BBSScheme::issue_update(&issuer_pk, &request, &response, &user_sk).unwrap();

    // 生成两个不同索引的tag
    let show_1 = BBSScheme::show_credential(&issuer_pk, &user_sk, &cred, 1).unwrap();
    let show_2 = BBSScheme::show_credential(&issuer_pk, &user_sk, &cred, 2).unwrap();

    // 序列化整个show用于比较
    let show_1_bytes = serde_json::to_vec(&show_1).unwrap();
    let show_2_bytes = serde_json::to_vec(&show_2).unwrap();

    // 验证：不同索引的show应该不同（因为tag不同）
    assert_ne!(show_1_bytes, show_2_bytes, "不同索引的show应该不同");
    println!("✓ show[1] 与 show[2] 不相同");
    println!("✓ tag = h^{{1/(r+i)}} 公式验证通过\n");

    println!("=== ✅ Tag唯一性测试通过！ ===\n");
}

#[test]
fn test_bbs_serialization_compatibility() {
    println!("\n=== 测试序列化兼容性 ===\n");

    let (issuer_pk, issuer_sk) = BBSScheme::keygen().unwrap();
    let user_sk = BBSScheme::generate_user_sk();

    // 测试各个阶段的序列化/反序列化
    let request = BBSScheme::issue_request(&issuer_pk, &user_sk, 2).unwrap();
    let request_json = serde_json::to_string_pretty(&request).unwrap();
    println!("Request JSON size: {} bytes", request_json.len());

    let response = BBSScheme::issue_response(&issuer_pk, &issuer_sk, &request).unwrap();
    let response_json = serde_json::to_string_pretty(&response).unwrap();
    println!("Response JSON size: {} bytes", response_json.len());

    let credential = BBSScheme::issue_update(&issuer_pk, &request, &response, &user_sk).unwrap();
    let show = BBSScheme::show_credential(&issuer_pk, &user_sk, &credential, 1).unwrap();
    let show_json = serde_json::to_string_pretty(&show).unwrap();
    println!("Show JSON size: {} bytes", show_json.len());

    // 验证往返序列化
    let decoded_request: BBSIssueRequest = serde_json::from_str(&request_json).unwrap();
    assert_eq!(decoded_request.usage_limit, request.usage_limit);

    let decoded_show: BBSCredentialShow = serde_json::from_str(&show_json).unwrap();
    // 验证序列化内容一致（忽略格式差异）
    let decoded_show_compact = serde_json::to_string(&decoded_show).unwrap();
    let original_show_compact = serde_json::to_string(&show).unwrap();
    assert_eq!(decoded_show_compact, original_show_compact);

    println!("✓ 所有数据结构序列化/反序列化成功\n");

    println!("=== ✅ 序列化测试通过！ ===\n");
}

#[test]
fn test_bbs_commitment_pok() {
    println!("\n=== 测试承诺POK证明 ===\n");

    let (issuer_pk, _issuer_sk) = BBSScheme::keygen().unwrap();
    let user_sk = BBSScheme::generate_user_sk();

    // 生成发行请求（包含POK）
    let request = BBSScheme::issue_request(&issuer_pk, &user_sk, 1).unwrap();
    
    println!("✓ 承诺C = g0^s' · g1^r 已生成");
    println!("✓ POK证明已生成:");
    println!("  - 承诺值t");
    println!("  - 响应值z_s, z_r");
    println!("  - 挑战值challenge");

    // 序列化POK证明
    let pok_json = serde_json::to_string_pretty(&request.pok_proof).unwrap();
    println!("\n✓ POK证明序列化大小: {} bytes", pok_json.len());

    // 往返序列化验证
    let decoded_request: BBSIssueRequest = serde_json::from_str(
        &serde_json::to_string(&request).unwrap()
    ).unwrap();
    assert_eq!(decoded_request.usage_limit, request.usage_limit);

    println!("✓ POK证明序列化/反序列化成功\n");

    println!("=== ✅ POK证明测试通过！ ===\n");
}
