//! Regression test suite for Milestone M9:
//! Forensic DNS Telemetry Harvesting, Agentic Routing & Zero-Drift Attribution.
//!
//! Verifies:
//! 1. "WHAT PROCESS IS USING DNS TRAFFIC" and "WHAT FORENSIC PROCESS IS USING DNS TRAFFIC"
//!    are recognized as `ForensicQueryIntent::DnsTraffic`.
//! 2. Live host DNS telemetry chunks (Sysmon 22, DNS-Client 3008, port 53 sockets, Dnscache service)
//!    are ranked above and isolate out unrelated CodeIntegrity/Defender block events.
//! 3. Synthesized response contains the structured Markdown summary table:
//!    `| # | Process | PID | Protocol / Port | Target Domain / Remote Socket | Query Status / Results | Telemetry Source |`
//! 4. Process attribution points accurately to the DNS process (`svchost.exe (Dnscache)` or querying executable).
//! 5. Zero CodeIntegrity drift: response does not attribute DNS traffic to CodeIntegrity blocked processes.

use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use quorum_types::{DocumentChunk, ScoredChunk};
use quorum_coordinator::{
    offline_engine::{DeterministicOfflineSynthesisEngine, ForensicQueryIntent},
    QueryCoordinator, CoordinatorConfig, ScatterGatherEngine, PeerAclManager,
    SynthesisModelFamily,
};

#[test]
fn test_forensic_dns_intent_detection() {
    let q1 = "WHAT PROCESS IS USING DNS TRAFFIC";
    let q2 = "WHAT FORENSIC PROCESS IS USING DNS TRAFFIC";
    let q3 = "which process is listening on port 53 udp?";
    let q4 = "show me sysmon 22 domain query logs";
    let q5 = "is dnscache service running?";

    assert_eq!(
        ForensicQueryIntent::detect(q1),
        Some(ForensicQueryIntent::DnsTraffic),
        "Must classify uppercase query as DnsTraffic"
    );
    assert_eq!(
        ForensicQueryIntent::detect(q2),
        Some(ForensicQueryIntent::DnsTraffic),
        "Must classify forensic query as DnsTraffic"
    );
    assert_eq!(
        ForensicQueryIntent::detect(q3),
        Some(ForensicQueryIntent::DnsTraffic),
        "Must classify port 53 query as DnsTraffic"
    );
    assert_eq!(
        ForensicQueryIntent::detect(q4),
        Some(ForensicQueryIntent::DnsTraffic),
        "Must classify Sysmon 22 query as DnsTraffic"
    );
    assert_eq!(
        ForensicQueryIntent::detect(q5),
        Some(ForensicQueryIntent::DnsTraffic),
        "Must classify dnscache query as DnsTraffic"
    );
}

#[tokio::test]
async fn test_dns_forensic_routing_and_zero_codeintegrity_drift() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = quorum_storage::StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let dummy_embedding = vec![0.0f32; 768];

    // 1. Seed Sysmon Event 22 DNS query chunk
    let sysmon_dns_chunk = DocumentChunk::new(
        "artemis_live_dns_sysmon_0",
        "artemis_dns_doc",
        "artemis://windows/live/eventlog/sysmon_dns_event_22_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "DnsQuery [Image='C:\\Windows\\System32\\svchost.exe' (PID 1420), QueryName='api.github.com', Status='0', Results='140.82.113.4']\nArtemis DFIR SystemEventLog [channel='Microsoft-Windows-Sysmon/Operational', event_id=22, process='svchost.exe', pid=1420, port=53, protocol='UDP']",
        Some(r#"{"port":53,"protocol":"UDP","event_id":"22","channel":"Microsoft-Windows-Sysmon/Operational","process_name":"svchost.exe","pid":"1420","query_name":"api.github.com","query_results":"140.82.113.4","query_status":"0"}"#.to_string()),
    ).expect("chunk");

    // 2. Seed Live Socket on Port 53 UDP
    let socket_dns_chunk = DocumentChunk::new(
        "artemis_live_dns_socket_0",
        "artemis_dns_doc",
        "artemis://windows/live/dns/socket_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "DnsQuery [Socket 0.0.0.0:53, Process='svchost.exe (Dnscache)', PID=1420, Protocol=UDP, State='LISTENING']\nArtemis DFIR NetworkConnection [local='0.0.0.0:53', remote='0.0.0.0:0', process='svchost.exe (Dnscache)', pid=1420, protocol='UDP', state='LISTENING']",
        Some(r#"{"port":53,"protocol":"UDP","process_name":"svchost.exe (Dnscache)","pid":"1420","dns_service":"Dnscache"}"#.to_string()),
    ).expect("chunk");

    // 3. Seed CodeIntegrity Event 3077 (Distractor that previously leaked into DNS answers)
    let code_integrity_chunk = DocumentChunk::new(
        "artemis_live_ci_0",
        "artemis_ci_doc",
        "artemis://windows/live/eventlog/windows_codeintegrity_blocked_process_event_3077_0",
        1,
        10,
        3,
        dummy_embedding.clone(),
        "SystemEventLog [channel='Microsoft-Windows-CodeIntegrity/Operational', event_id=3077, process='powershell.exe', pid=8844, date='2026-11-13']\nCodeIntegrity determined that a process attempted to load an unsigned driver or unauthorized binary: powershell.exe",
        Some(r#"{"event_id":"3077","channel":"Microsoft-Windows-CodeIntegrity/Operational","process_name":"powershell.exe","pid":"8844"}"#.to_string()),
    ).expect("chunk");

    storage.insert_chunks(&[sysmon_dns_chunk, socket_dns_chunk, code_integrity_chunk]).await.expect("insert");

    let node_seed = [0x5Bu8; 32];
    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        node_seed,
        "12D3KooWDnsTestNode".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let query = "WHAT PROCESS IS USING DNS TRAFFIC";
    let intent = ForensicQueryIntent::detect(query).expect("intent");
    assert_eq!(intent, ForensicQueryIntent::DnsTraffic);

    // Query coordinator
    let result = coordinator
        .query_agentic_with_history_and_session(
            query,
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    let answer = result.synthesis_prompt;

    // 1. Assert process attribution
    assert!(
        answer.contains("svchost.exe") || answer.contains("Dnscache"),
        "Answer must identify the DNS process: {}",
        answer
    );

    // 2. Assert Markdown table presence
    assert!(
        answer.contains("| # | Process | PID | Protocol / Port | Target Domain / Remote Socket | Query Status / Results | Telemetry Source |"),
        "Answer must contain the structured Markdown DNS summary table: {}",
        answer
    );

    // 3. Assert zero CodeIntegrity drift
    assert!(
        !answer.to_ascii_lowercase().contains("codeintegrity"),
        "DNS answer must NOT leak CodeIntegrity telemetry: {}",
        answer
    );
    assert!(
        !answer.contains("3077"),
        "DNS answer must NOT contain CodeIntegrity Event 3077: {}",
        answer
    );
}
