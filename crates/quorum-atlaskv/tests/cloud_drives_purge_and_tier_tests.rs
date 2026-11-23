use quorum_atlaskv::{
    l2_normalize_in_place, AtlasKvError, AtlasKvStore, AtlasKvTreeConfig, KgTripleRecord,
};
use tempfile::TempDir;

fn unit_vec(dim: usize, seed: usize) -> Vec<f32> {
    let mut v = vec![0.05f32; dim];
    v[seed % dim] = 1.0;
    l2_normalize_in_place(&mut v);
    v
}

fn make_triple(
    entity: &str,
    relation: &str,
    value: &str,
    doc_id: &str,
    chunk_id: &str,
    file_path: &str,
    tier: u8,
) -> KgTripleRecord {
    KgTripleRecord::new(
        entity,
        relation,
        value,
        doc_id,
        chunk_id,
        file_path,
        1,
        10,
        "cloud_drive_test",
        tier,
        "local",
    )
    .expect("valid triple")
}

#[test]
fn test_atlaskv_delete_by_path_prefix_boundaries_hierarchy_and_reopen() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 4,
        ..Default::default()
    };

    let q_od = unit_vec(16, 1);
    let q_sib = unit_vec(16, 2);

    {
        let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();
        let records = vec![
            make_triple(
                "OneDriveAlpha",
                "status",
                "synced_personal",
                "d1",
                "c_od_1",
                r"C:\Users\Alice\OneDrive\Docs\report.pdf",
                3,
            ),
            make_triple(
                "OneDriveBeta",
                "status",
                "synced_slash",
                "d2",
                "c_od_2",
                "C:/Users/Alice/OneDrive/Notes/todo.txt",
                3,
            ),
            make_triple(
                "OneDriveGamma",
                "status",
                "synced_verbatim",
                "d3",
                "c_od_3",
                r"\\?\c:\users\alice\onedrive\Archive\2026.md",
                3,
            ),
            make_triple(
                "OneDriveDelta",
                "status",
                "synced_deep",
                "d4",
                "c_od_4",
                r"C:\Users\Alice\OneDrive\Sub\deep.txt",
                3,
            ),
            // Siblings that MUST survive
            make_triple(
                "OneDrive2Sib",
                "status",
                "keep_onedrive2",
                "d5",
                "c_sib_1",
                r"C:\Users\Alice\OneDrive2\keep.txt",
                3,
            ),
            make_triple(
                "OneDriveBiz",
                "status",
                "keep_business",
                "d6",
                "c_sib_2",
                r"C:\Users\Alice\OneDrive - Business\biz.txt",
                3,
            ),
            make_triple(
                "UnixUpper",
                "status",
                "keep_unix_upper",
                "d7",
                "c_unix_1",
                "/home/alice/Nextcloud/item.txt",
                2,
            ),
            make_triple(
                "UnixLower",
                "status",
                "keep_unix_lower",
                "d8",
                "c_unix_2",
                "/home/alice/nextcloud/case.txt",
                2,
            ),
        ];

        let mut kvecs = Vec::new();
        let mut vvecs = Vec::new();
        for i in 0..records.len() {
            let v = if i < 4 { q_od.clone() } else { q_sib.clone() };
            kvecs.push(v.clone());
            vvecs.push(v);
        }

        let added = store.insert_triples(&records, &kvecs, &vvecs).unwrap();
        assert_eq!(added, 8);
        let stats_before = store.rebuild_hierarchy().unwrap();
        assert!(stats_before.hierarchy_built);
        assert_eq!(stats_before.active_triples, 8);

        // Fail-closed invalid prefix checks
        for bad in [
            "",
            "relative/path",
            r"C:\Users\Alice\..\OneDrive",
            "C:/Users/Alice/%2e%2e/OneDrive",
            "C:/Users/Alice/%252e%252e/OneDrive",
            r"\\server\share\OneDrive",
            r"C:\Users\Alice\OneDrive:ads",
        ] {
            let res = store.delete_by_path_prefix(bad);
            assert!(
                matches!(res, Err(AtlasKvError::Type(_))),
                "Expected fail-closed TypeError for '{bad}', got {res:?}"
            );
        }

        // Purge C:\Users\Alice\OneDrive (4 rows); siblings & Unix rows must remain
        let removed = store
            .delete_by_path_prefix("C:/Users/Alice/OneDrive/")
            .unwrap();
        assert_eq!(removed, 4);

        let stats_after = store.stats();
        assert_eq!(stats_after.active_triples, 4);
        assert!(stats_after.hierarchy_built);

        let (od_hits, _) = store.hikvp_search(&q_od, 3, 10, None).unwrap();
        assert!(
            od_hits.iter().all(|h| !h
                .triple
                .file_path
                .to_ascii_lowercase()
                .contains(r"onedrive\")),
            "Purged OneDrive triples leaked into hikvp_search: {od_hits:?}"
        );
        let (sib_hits, _) = store.hikvp_search(&q_sib, 3, 10, None).unwrap();
        assert_eq!(sib_hits.len(), 4);
    }

    // Reopen from disk: hierarchy_index.bin must preserve deleted state (active_triples == 4)
    {
        let reopened = AtlasKvStore::open(tmp.path(), cfg).unwrap();
        let stats = reopened.stats();
        assert_eq!(stats.active_triples, 4);
        assert!(stats.hierarchy_built);

        let (od_hits, _) = reopened.hikvp_search(&q_od, 3, 10, None).unwrap();
        assert!(od_hits.iter().all(|h| !h
            .triple
            .file_path
            .to_ascii_lowercase()
            .contains(r"onedrive\")));

        // Unix case preservation: purging /home/alice/Nextcloud removes only exact case
        let unix_removed = reopened
            .delete_by_path_prefix("/home/alice/Nextcloud")
            .unwrap();
        assert_eq!(unix_removed, 1);
        let stats_small = reopened.stats();
        assert_eq!(stats_small.active_triples, 3);
        assert!(
            !stats_small.hierarchy_built,
            "Hierarchy must clear when active_rows drops below 4"
        );
    }

    // Reopen again when active_rows < 4: hierarchy_index.bin must stay synchronized (3 active, 5 deleted)
    {
        let reopened2 = AtlasKvStore::open(
            tmp.path(),
            AtlasKvTreeConfig {
                embedding_dim: 16,
                min_triples_for_hierarchy: 4,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(reopened2.stats().active_triples, 3);
        let (sib_hits, _) = reopened2.hikvp_search(&q_sib, 3, 10, None).unwrap();
        assert_eq!(sib_hits.len(), 3);
        assert!(sib_hits
            .iter()
            .any(|h| h.triple.file_path == "/home/alice/nextcloud/case.txt"));
        assert!(!sib_hits
            .iter()
            .any(|h| h.triple.file_path == "/home/alice/Nextcloud/item.txt"));
    }
}

#[test]
fn test_atlaskv_update_chunk_and_prefix_access_tier_persists_across_reopen() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 4,
        ..Default::default()
    };
    let q = unit_vec(16, 5);

    {
        let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();
        let records = vec![
            make_triple(
                "DropA",
                "role",
                "alpha",
                "d1",
                "chunk_drop_1",
                r"C:\Users\Alice\Dropbox\a.txt",
                3,
            ),
            make_triple(
                "DropB",
                "role",
                "beta",
                "d2",
                "chunk_drop_2",
                r"C:\Users\Alice\Dropbox\b.txt",
                3,
            ),
            make_triple(
                "DropSib",
                "role",
                "gamma",
                "d3",
                "chunk_sib_1",
                r"C:\Users\Alice\Dropbox2\c.txt",
                3,
            ),
            make_triple(
                "LocalPub",
                "role",
                "delta",
                "d4",
                "chunk_pub_1",
                r"C:\Users\Alice\Docs\d.txt",
                0,
            ),
        ];
        let kvecs = vec![q.clone(); 4];
        let vvecs = vec![q.clone(); 4];
        store.insert_triples(&records, &kvecs, &vvecs).unwrap();
        store.rebuild_hierarchy().unwrap();

        // Fail-closed on tier > 3
        assert!(matches!(
            store.update_chunk_access_tier("chunk_drop_1", 4),
            Err(AtlasKvError::InvalidAccessTier(4))
        ));
        assert!(matches!(
            store.update_access_tier_by_path_prefix(r"C:\Users\Alice\Dropbox", 9),
            Err(AtlasKvError::InvalidAccessTier(9))
        ));

        // Tier 0 search sees only LocalPub initially
        let (t0_before, _) = store.hikvp_search(&q, 0, 10, None).unwrap();
        assert_eq!(t0_before.len(), 1);
        assert_eq!(t0_before[0].triple.chunk_id, "chunk_pub_1");

        // Update single chunk to tier 1
        let c_updated = store.update_chunk_access_tier("chunk_drop_1", 1).unwrap();
        assert_eq!(c_updated, 1);

        let (t1_mid, _) = store.hikvp_search(&q, 1, 10, None).unwrap();
        assert_eq!(t1_mid.len(), 2);

        // Prefix update Dropbox -> tier 0; Dropbox2 sibling must stay tier 3
        let p_updated = store
            .update_access_tier_by_path_prefix("C:/Users/Alice/Dropbox", 0)
            .unwrap();
        assert_eq!(p_updated, 2);

        let (t0_after, _) = store.hikvp_search(&q, 0, 10, None).unwrap();
        assert_eq!(t0_after.len(), 3);
        assert!(!t0_after.iter().any(|h| h.triple.chunk_id == "chunk_sib_1"));
    }

    // Reopen and verify updated leaf_access_tier persisted in hierarchy_index.bin
    {
        let reopened = AtlasKvStore::open(tmp.path(), cfg).unwrap();
        let (t0_reopen, _) = reopened.hikvp_search(&q, 0, 10, None).unwrap();
        assert_eq!(t0_reopen.len(), 3);
        assert!(!t0_reopen.iter().any(|h| h.triple.chunk_id == "chunk_sib_1"));
    }
}

#[test]
fn t5_atlaskv_update_chunk_access_tier_for_file_normalized_slash_case_prevents_leak() {
    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 4,
        ..Default::default()
    };
    let q = unit_vec(16, 7);

    {
        let store = AtlasKvStore::open(tmp.path(), cfg.clone()).unwrap();
        let records = vec![
            make_triple(
                "AliceSecret",
                "clearance",
                "restricted_secret",
                "d_sec",
                "c_secret",
                r"C:\Users\Alice\OneDrive\Secret.txt",
                0,
            ),
            make_triple(
                "PublicCopy",
                "clearance",
                "public_copy",
                "d_pub",
                "c_secret",
                r"C:\Users\Alice\Docs\PublicCopy.txt",
                0,
            ),
            make_triple(
                "PadOne",
                "clearance",
                "pad_one",
                "d_p1",
                "c_0",
                r"C:\Users\Alice\Docs\pad0.txt",
                0,
            ),
            make_triple(
                "PadTwo",
                "clearance",
                "pad_two",
                "d_p2",
                "c_1",
                r"C:\Users\Alice\Docs\pad1.txt",
                0,
            ),
        ];
        store
            .insert_triples(&records, &vec![q.clone(); 4], &vec![q.clone(); 4])
            .unwrap();
        store.rebuild_hierarchy().unwrap();

        // Update only OneDrive secret copy using lowercase/forward-slash Windows variant
        let updated = store
            .update_chunk_access_tier_for_file("c_secret", "c:/users/alice/onedrive/secret.txt", 3)
            .unwrap();
        assert_eq!(updated, 1);

        let (t0_hits, _) = store.hikvp_search(&q, 0, 10, None).unwrap();
        assert!(
            !t0_hits.iter().any(|h| h
                .triple
                .file_path
                .to_ascii_lowercase()
                .contains("secret.txt")),
            "Tier 0 search must NOT leak reclassified secret.txt: {t0_hits:?}"
        );
        assert!(
            t0_hits
                .iter()
                .any(|h| h.triple.file_path.contains("PublicCopy.txt")),
            "Sibling copy sharing chunk_id at another path must stay at Tier 0"
        );
        let summary = store
            .export_root_centroid_summary("local_peer", 0, 16)
            .unwrap();
        assert_eq!(summary.active_triple_count, 3);
    }

    // Reopen from disk and confirm Tier 0 isolation persists
    let reopened = AtlasKvStore::open(tmp.path(), cfg).unwrap();
    let (t0_reopen, _) = reopened.hikvp_search(&q, 0, 10, None).unwrap();
    assert_eq!(t0_reopen.len(), 3);
    assert!(!t0_reopen.iter().any(|h| h
        .triple
        .file_path
        .to_ascii_lowercase()
        .contains("secret.txt")));
}

#[test]
fn t5_atlaskv_verbatim_vs_plain_path_tier_update_and_delete_by_file_path() {
    assert_eq!(
        quorum_atlaskv::normalize_path_key(r"\\?\C:\Users\Alice\OneDrive\Verbatim_Doc.pdf"),
        quorum_atlaskv::normalize_path_key("c:/users/alice/onedrive/verbatim_doc.pdf")
    );
    assert_eq!(
        quorum_atlaskv::normalize_path_key("//?/C:/Users/Alice/OneDrive/Verbatim_Doc.pdf"),
        quorum_atlaskv::normalize_path_key(r"C:\Users\Alice\OneDrive\Verbatim_Doc.pdf")
    );
    assert_eq!(
        quorum_atlaskv::normalize_path_key(r"\\?\UNC\Fileserver\TeamShare\Doc.txt"),
        quorum_atlaskv::normalize_path_key(r"\\fileserver\teamshare\doc.txt")
    );
    assert_ne!(
        quorum_atlaskv::normalize_path_key("/home/alice/Nextcloud/Doc.txt"),
        quorum_atlaskv::normalize_path_key("/home/alice/nextcloud/doc.txt")
    );

    let tmp = TempDir::new().unwrap();
    let cfg = AtlasKvTreeConfig {
        embedding_dim: 16,
        min_triples_for_hierarchy: 4,
        ..Default::default()
    };
    let q = unit_vec(16, 9);

    let store = AtlasKvStore::open(tmp.path(), cfg).unwrap();
    let records = vec![
        make_triple(
            "VerbatimTriple",
            "clearance",
            "verb_secret",
            "d_v",
            "c_v",
            r"\\?\C:\Users\Alice\OneDrive\Verbatim_Doc.pdf",
            0,
        ),
        make_triple(
            "PlainTriple",
            "clearance",
            "plain_secret",
            "d_p",
            "c_p",
            r"C:\Users\Alice\OneDrive\Plain_Doc.pdf",
            0,
        ),
        make_triple(
            "KeepAlpha",
            "clearance",
            "keep_alpha",
            "d_ka",
            "c_ka",
            r"C:\Users\Alice\Docs\KeepA.txt",
            0,
        ),
        make_triple(
            "KeepBeta",
            "clearance",
            "keep_beta",
            "d_kb",
            "c_kb",
            r"C:\Users\Alice\Docs\KeepB.txt",
            0,
        ),
    ];
    store
        .insert_triples(&records, &vec![q.clone(); 4], &vec![q.clone(); 4])
        .unwrap();
    store.rebuild_hierarchy().unwrap();

    // Update verbatim-stored triple using plain slash/case path -> must reclassify & stop Tier 0 leak
    let u_v = store
        .update_chunk_access_tier_for_file("c_v", "c:/users/alice/onedrive/verbatim_doc.pdf", 3)
        .unwrap();
    assert_eq!(u_v, 1);

    // Update plain-stored triple using verbatim \\?\ path -> must reclassify & stop Tier 0 leak
    let u_p = store
        .update_chunk_access_tier_for_file("c_p", r"\\?\C:\Users\Alice\OneDrive\Plain_Doc.pdf", 3)
        .unwrap();
    assert_eq!(u_p, 1);

    let (t0_hits, _) = store.hikvp_search(&q, 0, 10, None).unwrap();
    assert_eq!(t0_hits.len(), 2);
    assert!(
        !t0_hits
            .iter()
            .any(|h| h.triple.chunk_id == "c_v" || h.triple.chunk_id == "c_p"),
        "Tier 0 search must NOT leak verbatim/plain reclassified triples: {t0_hits:?}"
    );

    // Delete verbatim-stored triple using plain slash/case variant and plain-stored using \\?\ variant
    let del_v = store
        .delete_by_file_path("c:/users/alice/onedrive/verbatim_doc.pdf")
        .unwrap();
    assert_eq!(del_v, 1);
    let del_p = store
        .delete_by_file_path(r"\\?\C:\Users\Alice\OneDrive\Plain_Doc.pdf")
        .unwrap();
    assert_eq!(del_p, 1);

    let (t3_after, _) = store.hikvp_search(&q, 3, 10, None).unwrap();
    assert_eq!(t3_after.len(), 2);
    assert_eq!(store.stats().active_triples, 2);
}
