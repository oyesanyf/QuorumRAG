//! Regression test suite for v0.6.6:
//! Forensic DNS Telemetry Harvesting, Whole-Word Intent Routing, Zero-Drift Attribution & Clean Formatting.
//!
//! Verifies:
//! 1. "WHAT PROCESS IS USING DNS TRAFFIC" and port 53 / Sysmon 22 / Dnscache queries map to `DnsTraffic`.
//! 2. Hostnames containing "dns" (`oshoosi.duckdns.org`), clock timestamps (`12:53 PM`), and years (`1853`)
//!    do NOT false-positive as `DnsTraffic` or protocol forensic queries.
//! 3. Live host DNS telemetry chunks isolate out unrelated CodeIntegrity/Defender events and static Python `.docx` code.
//! 4. Parent-expanded `artemis://` chunks with trailing pretty-printed JSON (`\n\n{...}`) are stripped cleanly
//!    so raw JSON never leaks into the Markdown response.

use std::sync::Arc;
use tempfile::tempdir;
use quorum_types::DocumentChunk;
use quorum_storage::query_framing::{detect_protocol_forensic_intent, ProtocolIntent};
use quorum_coordinator::{
    offline_engine::ForensicQueryIntent,
    CoordinatorConfig, LocalOnlyDispatcher, PeerAclManager, QueryCoordinator,
    ScatterGatherEngine, SynthesisModelFamily,
};

#[test]
fn test_forensic_dns_intent_detection_and_zero_false_positives() {
    assert_eq!(
        ForensicQueryIntent::detect("WHAT PROCESS IS USING DNS TRAFFIC"),
        Some(ForensicQueryIntent::DnsTraffic)
    );
    assert_eq!(
        ForensicQueryIntent::detect("WHAT FORENSIC PROCESS IS USING DNS TRAFFIC"),
        Some(ForensicQueryIntent::DnsTraffic)
    );
    assert_eq!(
        ForensicQueryIntent::detect("which process is listening on port 53 udp?"),
        Some(ForensicQueryIntent::DnsTraffic)
    );
    assert_eq!(
        ForensicQueryIntent::detect("show me sysmon 22 domain query logs"),
        Some(ForensicQueryIntent::DnsTraffic)
    );
    assert_eq!(
        ForensicQueryIntent::detect("which process talked to 8.8.8.8:53"),
        Some(ForensicQueryIntent::DnsTraffic)
    );
    assert_eq!(
        detect_protocol_forensic_intent("WHAT PROCESS IS USING DNS TRAFFIC"),
        ProtocolIntent::Dns
    );

    // Negative false-positive guards
    assert_eq!(
        ForensicQueryIntent::detect("check connectivity to oshoosi.duckdns.org"),
        None,
        "duckdns hostname must not false-positive as DnsTraffic"
    );
    assert_eq!(
        ForensicQueryIntent::detect("what happened in the meeting at 12:53 PM"),
        None,
        "12:53 timestamp must not false-positive as port 53"
    );
    assert_eq!(
        ForensicQueryIntent::detect("treaty signed in 1853 historical summary"),
        None,
        "year 1853 must not false-positive as port 853 DoT"
    );
    assert_eq!(
        detect_protocol_forensic_intent("connect to oshoosi.duckdns.org at 12:53 in 1853"),
        ProtocolIntent::None
    );
}

#[tokio::test]
async fn test_dns_forensic_routing_clean_formatting_and_zero_drift() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = quorum_storage::StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let dummy_embedding = vec![0.0f32; 768];

    // 1. Seed Sysmon Event 22 DNS query chunk WITH appended raw JSON (simulating parent-doc payload)
    let sysmon_dns_chunk = DocumentChunk::new(
        "artemis_live_dns_sysmon:0",
        "artemis_dns_doc",
        "artemis://windows/live/eventlog/sysmon_dns_event_22_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "DnsQuery [Image='C:\\Windows\\System32\\svchost.exe' (PID 1420), QueryName='api.github.com', Status='0', Results='140.82.113.4']\nArtemis DFIR SystemEventLog [channel='Microsoft-Windows-Sysmon/Operational', event_id=22, process='svchost.exe', pid=1420, port=53, protocol='UDP']\n\n{\n  \"EventID\": 22,\n  \"QueryName\": \"api.github.com\"\n}",
        Some(r#"{"port":53,"protocol":"UDP","event_id":"22","channel":"Microsoft-Windows-Sysmon/Operational","process_name":"svchost.exe","pid":"1420","query_name":"api.github.com","query_results":"140.82.113.4"}"#.to_string()),
    )
    .expect("chunk");

    // 2. Seed Live Socket on Port 53 UDP
    let socket_dns_chunk = DocumentChunk::new(
        "artemis_live_dns_socket:0",
        "artemis_dns_socket_doc",
        "artemis://windows/live/dns/socket_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "DnsQuery [Socket 0.0.0.0:53, Process='svchost.exe (Dnscache)', PID=1420, Protocol=UDP, State='LISTENING']\nArtemis DFIR NetworkConnection [local='0.0.0.0:53', remote='0.0.0.0:0', process='svchost.exe (Dnscache)', pid=1420, protocol='UDP', state='LISTENING']",
        Some(r#"{"port":53,"protocol":"UDP","process_name":"svchost.exe (Dnscache)","pid":"1420","dns_service":"Dnscache"}"#.to_string()),
    )
    .expect("chunk");

    // 3. Seed CodeIntegrity Event 3089 & Python static doc distractors
    let code_integrity_chunk = DocumentChunk::new(
        "artemis_live_ci:0",
        "artemis_ci_doc",
        "artemis://windows/live/eventlog/windows_codeintegrity_blocked_process_event_3089_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "SystemEventLog [channel='Microsoft-Windows-CodeIntegrity/Operational', event_id=3089, process='chrome.exe', pid=8844, date='2026-11-13']\nCodeIntegrity blocked libLiteRtWebGpuAccelerator.dll",
        Some(r#"{"event_id":"3089","channel":"Microsoft-Windows-CodeIntegrity/Operational","process_name":"chrome.exe","pid":"8844"}"#.to_string()),
    )
    .expect("chunk");

    let static_python_doc = DocumentChunk::new(
        "doc_c2_docx:0",
        "doc_c2_docx",
        "C:/Docs/C2 Traffic Detection Adequacy.docx",
        1,
        25,
        0,
        dummy_embedding,
        "def get_dns_query_sysmon(): # TODO: Process the results to flag any unusual DNS activity.",
        None,
    )
    .expect("chunk");

    storage
        .insert_chunks(&[
            sysmon_dns_chunk,
            socket_dns_chunk,
            code_integrity_chunk,
            static_python_doc,
        ])
        .await
        .expect("insert");

    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x5Bu8; 32],
        "12D3KooWDnsTestNode".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let result = coordinator
        .query_agentic_with_history_and_session(
            "WHAT PROCESS IS USING DNS TRAFFIC",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    let answer = result.synthesis_prompt;

    assert!(answer.contains("svchost.exe"), "Must identify svchost.exe: {}", answer);
    assert!(
        answer.contains("| # | Process | PID | Protocol / Port | Target Domain / Remote Socket | Query Status / Results | Telemetry Source |"),
        "Must render structured Markdown DNS summary table: {}",
        answer
    );
    assert!(
        !answer.contains("\"EventID\": 22"),
        "Must strip raw JSON payload from artemis:// chunks: {}",
        answer
    );
    assert!(
        !answer.to_ascii_lowercase().contains("codeintegrity") && !answer.contains("3089"),
        "Must not leak CodeIntegrity Event 3089: {}",
        answer
    );
    assert!(
        !answer.contains("get_dns_query_sysmon") && !answer.contains("TODO:"),
        "Must not leak static Python .docx snippets into live DNS forensic response: {}",
        answer
    );
    println!(
        "\n=== [REGRESSION TEST OUTPUT: WHAT PROCESS IS USING DNS TRAFFIC] ===\n{}\n=== [END DNS FORENSIC OUTPUT] ===",
        answer
    );
}
