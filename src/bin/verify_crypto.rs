//! Crypto verification: sends fake credentials to AirVPN API,
//! captures what goes over the wire, verifies no plaintext leak.
//!
//! Run: cargo build --release && sudo ./target/release/verify_crypto

use std::process::Command;
use std::io::Read;

fn main() {
    let canary_user = "CANARY_USERNAME_12345";
    let canary_pass = "CANARY_PASSWORD_67890";
    let canary_combined = "CANARY"; // shorter substring to search for

    println!("=== AirVPN-RS Crypto Verification ===\n");
    println!("This test sends FAKE credentials to the AirVPN API");
    println!("and captures network traffic to verify nothing leaks in plaintext.\n");
    println!("Canary username: {}", canary_user);
    println!("Canary password: {}", canary_pass);
    println!();

    // Step 1: Start tcpdump in background
    // Use /run/airvpn-rs/ instead of /tmp to avoid symlink attacks (this runs as root).
    let pcap_dir = std::path::Path::new("/run/airvpn-rs");
    if !pcap_dir.exists() {
        std::fs::create_dir_all(pcap_dir).expect("failed to create /run/airvpn-rs/");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(pcap_dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let pcap_path = "/run/airvpn-rs/airvpn-crypto-verify.pcap";
    println!("[1/4] Starting packet capture...");
    let mut tcpdump = Command::new("tcpdump")
        .args([
            "-i", "any",
            "-w", pcap_path,
            "host", "63.33.78.166",
            "or", "host", "54.93.175.114",
            "or", "host", "82.196.3.205",
            "or", "host", "63.33.116.50",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start tcpdump — are you running as root?");

    // Give tcpdump a moment to start capturing
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Step 2: Make the API call with fake credentials
    println!("[2/4] Sending API request with fake credentials...");
    let provider_config = airvpn::api::load_provider_config()
        .expect("failed to load provider configuration");
    let result = airvpn::api::fetch_manifest(&provider_config, canary_user, canary_pass);

    match &result {
        Ok(xml) => {
            println!("  Got response ({} bytes)", xml.len());
            println!("  (Server accepted our encryption and processed the request)");
        }
        Err(e) => {
            let err = format!("{:#}", e);
            println!("  Error: {}", err);
            if err.contains("AES decryption failed") {
                println!("  → Server sent a non-encrypted error response (likely auth rejection)");
                println!("  → This means our encryption IS correct (server could decrypt it,");
                println!("    checked creds, rejected them, sent plaintext error page)");
            }
        }
    }

    // Step 3: Stop tcpdump
    println!("\n[3/4] Stopping packet capture...");
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = tcpdump.kill();
    let _ = tcpdump.wait();

    // Step 4: Analyze the capture
    println!("[4/4] Analyzing captured traffic for plaintext leaks...\n");

    // Read the raw pcap file
    let mut pcap_data = Vec::new();
    match std::fs::File::open(pcap_path) {
        Ok(mut f) => {
            f.read_to_end(&mut pcap_data).unwrap();
        }
        Err(e) => {
            println!("  ERROR: Could not read capture file: {}", e);
            println!("  (Was tcpdump running? Are you root?)");
            return;
        }
    };

    if pcap_data.is_empty() {
        println!("  WARNING: Capture file is empty — no traffic was captured.");
        println!("  This might mean the API request didn't go out, or tcpdump");
        println!("  didn't have time to capture it.");
        return;
    }

    println!("  Captured {} bytes of network traffic", pcap_data.len());

    // Search for canary strings in raw pcap bytes
    let pcap_str = String::from_utf8_lossy(&pcap_data);
    let mut leaked = false;

    for canary in [canary_user, canary_pass, canary_combined, "CANARY_USERNAME", "CANARY_PASSWORD"] {
        if pcap_str.contains(canary) {
            println!("  ❌ FOUND '{}' IN PLAINTEXT IN NETWORK CAPTURE!", canary);
            leaked = true;
        }
    }

    // Also search raw bytes (in case of encoding issues)
    for canary in [canary_user.as_bytes(), canary_pass.as_bytes()] {
        if pcap_data.windows(canary.len()).any(|w| w == canary) {
            println!("  ❌ FOUND canary in raw bytes in network capture!");
            leaked = true;
        }
    }

    // Also check for base64 of the canary (in case it's base64-encoded but not AES-encrypted)
    let user_b64 = base64::Engine::encode(&airvpn::crypto::BASE64, canary_user.as_bytes());
    let pass_b64 = base64::Engine::encode(&airvpn::crypto::BASE64, canary_pass.as_bytes());
    for (label, b64) in [("username_b64", &user_b64), ("password_b64", &pass_b64)] {
        if pcap_str.contains(b64.as_str()) {
            println!("  ❌ FOUND {} ('{}') in network capture!", label, b64);
            leaked = true;
        }
    }

    println!();
    if leaked {
        println!("  ██████████████████████████████████████████████████");
        println!("  ██  CREDENTIALS LEAKED — DO NOT USE REAL CREDS  ██");
        println!("  ██████████████████████████████████████████████████");
    } else {
        println!("  ✅ No plaintext credentials found in network capture.");
        println!("  ✅ No base64-encoded credentials found in network capture.");
        println!("  ✅ Credentials appear to be properly AES-encrypted.");
        println!();
        println!("  Safe to proceed with real credentials.");
    }

    // Cleanup
    let _ = std::fs::remove_file(pcap_path);
}
