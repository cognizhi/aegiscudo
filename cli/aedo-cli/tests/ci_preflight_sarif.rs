use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::thread;

use tempfile::tempdir;

#[test]
fn ci_preflight_binary_emits_sarif_and_block_exit_code() {
    let workspace = tempdir().expect("temp workspace");
    let lockfile = workspace.path().join("package-lock.json");
    fs::write(
        &lockfile,
        r#"{"packages":{"node_modules/fresh-postinstall":{"version":"0.1.0","integrity":"sha512-x"}}}"#,
    )
    .expect("write lockfile");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture api");
    let address = listener.local_addr().expect("fixture api address");
    let config_path = workspace.path().join("aedo.json");
    fs::write(
        &config_path,
        format!(
            "{{\n  \"api_url\": \"http://{address}\",\n  \"token\": \"fixture-token\"\n}}"
        ),
    )
    .expect("write cli config");

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0_u8; 4096];
            let bytes_read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..bytes_read]);
            assert!(request.contains("POST /v1/cli/scans HTTP/1.1"));
            assert!(request.contains("\"name\":\"fresh-postinstall\""));
            assert!(request.contains("authorization: Bearer fixture-token"));

            let response = serde_json::json!({
                "findings": [{
                    "coordinate": {
                        "ecosystem": "npm",
                        "name": "fresh-postinstall",
                        "version": "0.1.0",
                        "namespace": null
                    },
                    "decision": "BLOCK_POLICY_VIOLATION"
                }]
            });
            let body = serde_json::to_vec(&response).expect("serialize response");
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .expect("write response headers");
            stream.write_all(&body).expect("write response body");
        }
    });

    let output = Command::new(env!("CARGO_BIN_EXE_aedo"))
        .current_dir(workspace.path())
        .env("AEDO_CONFIG_HOME", workspace.path())
        .args([
            "ci",
            "preflight",
            "--format",
            "sarif",
            "--fail-on",
            "block",
        ])
        .output()
        .expect("run aedo ci preflight");

    server.join().expect("fixture api server finished");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty(), "stderr was not empty: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("sarif json output");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("sarif results array");

    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["ruleId"], "aegiscudo-policy-decision");
    assert_eq!(
        results[0]["message"]["text"],
        "pkg:npm/fresh-postinstall@0.1.0 -> BlockPolicyViolation"
    );
}