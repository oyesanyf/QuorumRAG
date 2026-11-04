# Original User Request

## Initial Request — 2026-10-31T15:00:00Z

Build QuorumRAG: a production-grade local-first peer-to-peer retrieval-augmented generation daemon and simple ChatGPT-like web interface, adapting useful code from `d:\harfile` (including `d:\harfile\fusion` and IDE interface code) with Gemma Embedding contract and embedded LanceDB hybrid storage.
Mandatory User Directive: "test it run it on the ide once dont to see it it generates production code"

## Follow-up — 2026-11-01T03:52:07Z

"the code needs to have caching and re cache"

Specifically, implement first-class Caching and Re-Cache (`recache`) across the coordinator, ingestion/storage layer, daemon CLI/REST API, and ChatGPT Web UI:

1. **Multi-Layer BLAKE3 Caching Engine (`QueryCache` + `EmbeddingCache`)**:
   - **Query, Retrieval & Synthesis Cache**: Cache query embeddings, hybrid/keyword/vector search results, LangExtract grounded extractions, and synthesized responses keyed by a deterministic BLAKE3 digest of `(normalized_query, search_mode, model_family, access_tier, index_epoch)` with configurable TTL & LRU/capacity bounds.
   - **Cache Hit Telemetry**: Expose `cache_hit: bool`, `cache_hits: u64`, `cache_misses: u64`, `cached_entries: usize`, and `cache_epoch: u64` in `/api/chat`, `/api/query`, `/api/health`, and `GET /api/cache/stats` (while respecting zero-trust unpinned remote peer chunk `ZeroizeOnDrop` memory rules).

2. **Dedicated Re-Cache Process, API & Web UI Control (`recache`)**:
   - **CLI Command**: `quorumrag recache [--clear] [--warm]` to flush stale caches, increment cache epoch, synchronize with LanceDB + Tantivy index state, and pre-warm hot embeddings/queries.
   - **REST API Endpoints**:
     - `POST /api/cache/recache`: Invalidates stale cache entries, increments `cache_epoch`, rebuilds/warms active embedding & query cache from current index, returning `{ status, cache_epoch, cleared_entries, warmed_entries, duration_ms }`.
     - `GET /api/cache/stats`: Returns live cache metrics (`hits`, `misses`, `hit_rate`, `cached_queries`, `cached_embeddings`, `cache_epoch`).
   - **Automatic Cache Coherence**: Automatically invalidate/re-cache affected entries when `reindex`, `fix-drift`, or the live OS file watcher modifies indexed files.
   - **ChatGPT Web UI Integration**: Add a **"Re-Cache"** button and live Cache Hit / Cache Stats indicator in the ChatGPT Web UI sidebar/header so the user can inspect cache status and trigger a full re-cache with one click.
