use anonymous_credentials::{
    bbs::BBSScheme,
    cl::CLScheme,
    rsa::RSAScheme,
    AnonymousCredentialScheme,
};
use std::time::Instant;

#[test]
fn test_bbs_performance() {
    println!("\n=== BBS Performance ===");
    
    let start = Instant::now();
    let (pk, sk) = BBSScheme::keygen().unwrap();
    println!("Keygen: {:?}", start.elapsed());
    
    let user_sk = BBSScheme::generate_user_sk();
    
    let start = Instant::now();
    let request = BBSScheme::issue_request(&pk, &user_sk, 10).unwrap();
    println!("Issue Request: {:?}", start.elapsed());
    
    let start = Instant::now();
    let response = BBSScheme::issue_response(&pk, &sk, &request).unwrap();
    println!("Issue Response: {:?}", start.elapsed());
    
    let start = Instant::now();
    let credential = BBSScheme::issue_update(&pk, &request, &response, &user_sk).unwrap();
    println!("Issue Update: {:?}", start.elapsed());
    
    let start = Instant::now();
    let show = BBSScheme::show_credential(&pk, &user_sk, &credential, 1).unwrap();
    println!("Show Credential: {:?}", start.elapsed());
    
    let start = Instant::now();
    BBSScheme::verify_credential(&pk, &show).unwrap();
    println!("Verify Credential: {:?}", start.elapsed());
}

#[test]
fn test_cl_performance() {
    println!("\n=== CL Performance ===");
    
    let start = Instant::now();
    let (pk, sk) = CLScheme::keygen().unwrap();
    println!("Keygen: {:?}", start.elapsed());
    
    let user_sk = CLScheme::generate_user_sk();
    
    let start = Instant::now();
    let request = CLScheme::issue_request(&pk, &user_sk, 10).unwrap();
    println!("Issue Request: {:?}", start.elapsed());
    
    let start = Instant::now();
    let response = CLScheme::issue_response(&pk, &sk, &request).unwrap();
    println!("Issue Response: {:?}", start.elapsed());
    
    let start = Instant::now();
    let credential = CLScheme::issue_update(&pk, &request, &response, &user_sk).unwrap();
    println!("Issue Update: {:?}", start.elapsed());
    
    let start = Instant::now();
    let show = CLScheme::show_credential(&pk, &user_sk, &credential, 1).unwrap();
    println!("Show Credential: {:?}", start.elapsed());
    
    let start = Instant::now();
    CLScheme::verify_credential(&pk, &show).unwrap();
    println!("Verify Credential: {:?}", start.elapsed());
}

#[test]
fn test_rsa_performance() {
    println!("\n=== RSA Performance ===");
    
    let start = Instant::now();
    let (pk, sk) = RSAScheme::keygen().unwrap();
    println!("Keygen: {:?}", start.elapsed());
    
    let user_sk = RSAScheme::generate_user_sk();
    
    let start = Instant::now();
    let request = RSAScheme::issue_request(&pk, &user_sk, 10).unwrap();
    println!("Issue Request: {:?}", start.elapsed());
    
    let start = Instant::now();
    let response = RSAScheme::issue_response(&pk, &sk, &request).unwrap();
    println!("Issue Response: {:?}", start.elapsed());
    
    let start = Instant::now();
    let credential = RSAScheme::issue_update(&pk, &request, &response, &user_sk).unwrap();
    println!("Issue Update: {:?}", start.elapsed());
    
    let start = Instant::now();
    let show = RSAScheme::show_credential(&pk, &user_sk, &credential, 1).unwrap();
    println!("Show Credential: {:?}", start.elapsed());
    
    let start = Instant::now();
    RSAScheme::verify_credential(&pk, &show).unwrap();
    println!("Verify Credential: {:?}", start.elapsed());
}
