//! Generic Typed Structured Extractor (`rig-core` pattern), JSON-Schema-to-GBNF Constrained
//! Decoding Compiler (`outlines-core` / `llama.cpp` pattern), `#17 Self-RAG` Structured Critique,
//! and `#20 RAGAS LLM-as-a-Judge` Typed Evaluator.
//!
//! All network calls fail closed on non-loopback endpoints to preserve QuorumRAG's 100% local,
//! air-gapped invariant.

use schemars::gen::SchemaSettings;
use schemars::schema::{InstanceType, Schema, SchemaObject};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// Verifies that an HTTP endpoint resolves strictly to a loopback IP (`127.0.0.1` / `::1` / `localhost`).
/// Fails closed on any external host or malformed URL.
pub fn is_loopback_endpoint(endpoint: &str) -> bool {
    let trimmed = endpoint.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return false;
    }
    let host_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    match host_port.to_socket_addrs() {
        Ok(mut addrs) => {
            let mut found = false;
            for addr in addrs.by_ref() {
                found = true;
                if !addr.ip().is_loopback() {
                    return false;
                }
            }
            found
        }
        Err(_) => false,
    }
}

/// Generates an inlined Draft-07 JSON Schema for any `T: JsonSchema` compatible with both
/// Ollama native `"format"` structured outputs and our pure-Rust GBNF compiler.
pub fn generate_inlined_draft07_schema<T: JsonSchema>() -> serde_json::Value {
    let settings = SchemaSettings::draft07().with(|s| {
        s.inline_subschemas = true;
    });
    let root = settings.into_generator().into_root_schema_for::<T>();
    serde_json::to_value(&root).unwrap_or_else(|_| serde_json::json!({ "type": "object" }))
}

/// Compiles a Draft-07 JSON Schema into a `llama.cpp` / `outlines-core` compatible GBNF
/// constrained-decoding grammar so direct local GGUF servers can enforce exact token-level masking.
pub fn compile_json_schema_to_gbnf(schema: &serde_json::Value) -> String {
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    let mut counter = 0usize;
    let root_expr = build_gbnf_expr(schema, "root", &mut rules, &mut counter);

    let mut out = String::with_capacity(1024);
    out.push_str(&format!("root ::= ws {root_expr} ws\n"));
    for (name, expr) in &rules {
        out.push_str(&format!("{name} ::= {expr}\n"));
    }
    out.push_str(
        r#"ws ::= [ \t\n\r]*
string ::= "\"" ( [^"\\\x7F\x00-\x1F] | "\\" (["\\/bfnrt] | "u" [0-9a-fA-F]{4}) )* "\""
integer ::= ("-"? ([0-9] | [1-9] [0-9]{0,15}))
number ::= integer ("." [0-9]+)? ([eE] [+-]? [0-9]+)?
boolean ::= "true" | "false"
null ::= "null"
json-value ::= object-any | array-any | string | number | boolean | null
object-any ::= "{" ws ( string ws ":" ws json-value ( "," ws string ws ":" ws json-value )* )? ws "}"
array-any ::= "[" ws ( json-value ( "," ws json-value )* )? ws "]"
"#,
    );
    out
}

fn sanitize_gbnf_rule_name(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let trimmed = s.trim_matches('-');
    if trimmed.is_empty() {
        "node".to_string()
    } else {
        trimmed.to_string()
    }
}

fn escape_gbnf_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn build_gbnf_expr(
    schema: &serde_json::Value,
    hint: &str,
    rules: &mut BTreeMap<String, String>,
    counter: &mut usize,
) -> String {
    // 1. Handle explicit `enum` values
    if let Some(enum_vals) = schema.get("enum").and_then(|v| v.as_array()) {
        if !enum_vals.is_empty() {
            let alts: Vec<String> = enum_vals
                .iter()
                .map(|v| format!("\"{}\"", escape_gbnf_literal(&v.to_string())))
                .collect();
            return format!("( {} )", alts.join(" | "));
        }
    }

    // 2. Handle `anyOf` / `oneOf`
    for union_key in ["anyOf", "oneOf"] {
        if let Some(variants) = schema.get(union_key).and_then(|v| v.as_array()) {
            if !variants.is_empty() {
                let mut exprs = Vec::with_capacity(variants.len());
                for (i, sub) in variants.iter().enumerate() {
                    exprs.push(build_gbnf_expr(sub, &format!("{hint}-v{i}"), rules, counter));
                }
                return format!("( {} )", exprs.join(" | "));
            }
        }
    }

    // 3. Dispatch by JSON Schema `type` (string or array of types)
    let typ = match schema.get("type") {
        Some(serde_json::Value::String(s)) => Some(s.as_str()),
        Some(serde_json::Value::Array(arr)) => {
            let mut exprs = Vec::new();
            for item in arr {
                if let Some(ts) = item.as_str() {
                    let mut single = schema.clone();
                    if let Some(obj) = single.as_object_mut() {
                        obj.insert("type".to_string(), serde_json::Value::String(ts.to_string()));
                    }
                    exprs.push(build_gbnf_expr(&single, hint, rules, counter));
                }
            }
            if !exprs.is_empty() {
                return format!("( {} )", exprs.join(" | "));
            }
            None
        }
        _ => None,
    };

    match typ {
        Some("string") => "string".to_string(),
        Some("integer") => "integer".to_string(),
        Some("number") => "number".to_string(),
        Some("boolean") => "boolean".to_string(),
        Some("null") => "null".to_string(),
        Some("array") => {
            let item_expr = if let Some(items) = schema.get("items") {
                *counter += 1;
                let rule_name = format!("{}-item-{}", sanitize_gbnf_rule_name(hint), *counter);
                let expr = build_gbnf_expr(items, &rule_name, rules, counter);
                if matches!(expr.as_str(), "string" | "integer" | "number" | "boolean" | "null") {
                    expr
                } else {
                    rules.insert(rule_name.clone(), expr);
                    rule_name
                }
            } else {
                "json-value".to_string()
            };
            format!("\"[\" ws ( {item_expr} ( \",\" ws {item_expr} )* )? ws \"]\"")
        }
        Some("object") | None if schema.get("properties").and_then(|p| p.as_object()).is_some() => {
            let props = schema["properties"].as_object().expect("checked");
            if props.is_empty() {
                return "object-any".to_string();
            }
            // Emit deterministic field order from BTreeMap (sorted keys)
            let sorted: BTreeMap<&String, &serde_json::Value> = props.iter().collect();
            let mut field_parts: Vec<String> = Vec::with_capacity(sorted.len());
            for (k, prop_schema) in sorted {
                *counter += 1;
                let prop_rule = format!(
                    "{}-{}-{}",
                    sanitize_gbnf_rule_name(hint),
                    sanitize_gbnf_rule_name(k),
                    *counter
                );
                let val_expr = build_gbnf_expr(prop_schema, &prop_rule, rules, counter);
                let val_ref = if matches!(
                    val_expr.as_str(),
                    "string" | "integer" | "number" | "boolean" | "null" | "json-value"
                ) {
                    val_expr
                } else {
                    rules.insert(prop_rule.clone(), val_expr);
                    prop_rule
                };
                let lit_key = escape_gbnf_literal(k);
                field_parts.push(format!("\"\\\"{lit_key}\\\"\" ws \":\" ws {val_ref}"));
            }
            format!("\"{{\" ws {} ws \"}}\"", field_parts.join(" ws \",\" ws "))
        }
        Some("object") => "object-any".to_string(),
        _ => "json-value".to_string(),
    }
}

/// Reusable generic typed structured extractor (`rig-core` `Extractor<T>` architecture) backed by
/// `schemars` Draft-07 JSON Schema + pure-Rust GBNF grammar compilation.
#[derive(Debug, Clone)]
pub struct TypedStructuredExtractor<T> {
    pub endpoint: String,
    pub model_tag: String,
    pub system_preamble: String,
    pub temperature: f32,
    pub num_predict: usize,
    pub num_ctx: usize,
    pub timeout: Duration,
    _marker: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned + JsonSchema> TypedStructuredExtractor<T> {
    pub fn new(
        endpoint: impl Into<String>,
        model_tag: impl Into<String>,
        system_preamble: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            model_tag: model_tag.into(),
            system_preamble: system_preamble.into(),
            temperature: 0.1,
            num_predict: 1024,
            num_ctx: 8192,
            timeout: Duration::from_secs(30),
            _marker: PhantomData,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_budget(mut self, num_predict: usize, num_ctx: usize) -> Self {
        self.num_predict = num_predict;
        self.num_ctx = num_ctx;
        self
    }

    /// Returns the inlined Draft-07 JSON Schema for `T`.
    pub fn json_schema(&self) -> serde_json::Value {
        generate_inlined_draft07_schema::<T>()
    }

    /// Returns the compiled GBNF constrained-decoding grammar for `T` (compatible with direct
    /// local `llama-server` / GGUF inference backends).
    pub fn gbnf_grammar(&self) -> String {
        compile_json_schema_to_gbnf(&self.json_schema())
    }

    /// Parses raw model JSON (stripping optional markdown code fences) into typed `T`.
    pub fn parse_raw_json(raw: &str) -> Result<T, String> {
        let trimmed = raw.trim();
        let unwrapped = if let Some(rest) = trimmed.strip_prefix("```") {
            let after_lang = rest
                .strip_prefix("json")
                .or_else(|| rest.strip_prefix("JSON"))
                .unwrap_or(rest);
            after_lang.trim().strip_suffix("```").unwrap_or(after_lang).trim()
        } else {
            trimmed
        };
        serde_json::from_str::<T>(unwrapped).map_err(|e| format!("Typed JSON parse error: {e}"))
    }

    /// Executes schema-constrained extraction via local loopback Ollama `POST /api/chat` (`format: schema`).
    pub async fn extract_ollama_async(&self, user_prompt: &str) -> Result<T, String> {
        if !is_loopback_endpoint(&self.endpoint) {
            return Err(format!(
                "Refusing non-loopback endpoint under air-gap policy: {}",
                self.endpoint
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(self.timeout)
            .build()
            .map_err(|e| format!("HTTP client init failed: {e}"))?;

        let payload = serde_json::json!({
            "model": self.model_tag,
            "messages": [
                { "role": "system", "content": self.system_preamble },
                { "role": "user", "content": user_prompt }
            ],
            "stream": false,
            "keep_alive": "24h",
            "format": self.json_schema(),
            "options": {
                "temperature": self.temperature,
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx
            }
        });

        let resp = client
            .post(format!("{}/api/chat", self.endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Ollama structured extraction request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("Ollama returned HTTP {}", resp.status()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Ollama JSON decode failed: {e}"))?;
        if let Some(err) = body.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Ollama error: {err}"));
        }
        let content = body
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| "Ollama response missing message.content".to_string())?;
        Self::parse_raw_json(content)
    }

    /// Executes GBNF-constrained extraction via a local loopback `llama-server` / GGUF
    /// OpenAI-compatible `POST /v1/chat/completions` endpoint passing `"grammar": gbnf`.
    pub async fn extract_gbnf_server_async(&self, user_prompt: &str) -> Result<T, String> {
        if !is_loopback_endpoint(&self.endpoint) {
            return Err(format!(
                "Refusing non-loopback GGUF endpoint under air-gap policy: {}",
                self.endpoint
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(self.timeout)
            .build()
            .map_err(|e| format!("HTTP client init failed: {e}"))?;

        let payload = serde_json::json!({
            "model": self.model_tag,
            "messages": [
                { "role": "system", "content": self.system_preamble },
                { "role": "user", "content": user_prompt }
            ],
            "stream": false,
            "temperature": self.temperature,
            "max_tokens": self.num_predict,
            "grammar": self.gbnf_grammar()
        });

        let resp = client
            .post(format!("{}/v1/chat/completions", self.endpoint))
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("GGUF GBNF extraction request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("GGUF server returned HTTP {}", resp.status()));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("GGUF JSON decode failed: {e}"))?;
        let content = body
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|first| first.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| "GGUF response missing choices[0].message.content".to_string())?;
        Self::parse_raw_json(content)
    }
}

/// `#17 Self-RAG` structured self-critique output verified via token-constrained decoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelfRagCritique {
    pub is_grounded: bool,
    pub answers_all_sub_questions: bool,
    #[serde(default)]
    pub unsupported_claims: Vec<String>,
    #[serde(default)]
    pub missing_document_refs: Vec<usize>,
    pub confidence: f32,
}

impl JsonSchema for SelfRagCritique {
    fn schema_name() -> String {
        "SelfRagCritique".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut obj = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let props = obj.object();
        props.properties.insert("is_grounded".to_string(), gen.subschema_for::<bool>());
        props.properties.insert(
            "answers_all_sub_questions".to_string(),
            gen.subschema_for::<bool>(),
        );
        props.properties.insert(
            "unsupported_claims".to_string(),
            gen.subschema_for::<Vec<String>>(),
        );
        props.properties.insert(
            "missing_document_refs".to_string(),
            gen.subschema_for::<Vec<usize>>(),
        );
        props.properties.insert("confidence".to_string(), gen.subschema_for::<f32>());
        for req in [
            "is_grounded",
            "answers_all_sub_questions",
            "unsupported_claims",
            "missing_document_refs",
            "confidence",
        ] {
            props.required.insert(req.to_string());
        }
        props.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(obj)
    }
}

/// `#20 RAGAS` local LLM-as-a-Judge structured evaluation scorecard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmJudgeEvaluation {
    pub faithfulness: f32,
    pub answer_relevance: f32,
    pub context_precision: f32,
    pub zero_omission_completeness: f32,
    pub rationale: String,
}

impl JsonSchema for LlmJudgeEvaluation {
    fn schema_name() -> String {
        "LlmJudgeEvaluation".to_string()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> Schema {
        let mut obj = SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            ..Default::default()
        };
        let props = obj.object();
        props.properties.insert("faithfulness".to_string(), gen.subschema_for::<f32>());
        props.properties.insert("answer_relevance".to_string(), gen.subschema_for::<f32>());
        props.properties.insert("context_precision".to_string(), gen.subschema_for::<f32>());
        props.properties.insert(
            "zero_omission_completeness".to_string(),
            gen.subschema_for::<f32>(),
        );
        props.properties.insert("rationale".to_string(), gen.subschema_for::<String>());
        for req in [
            "faithfulness",
            "answer_relevance",
            "context_precision",
            "zero_omission_completeness",
            "rationale",
        ] {
            props.required.insert(req.to_string());
        }
        props.additional_properties = Some(Box::new(Schema::Bool(false)));
        Schema::Object(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_schema_to_gbnf_compiler_and_loopback_guard() {
        assert!(is_loopback_endpoint("http://127.0.0.1:11434"));
        assert!(is_loopback_endpoint("http://localhost:8080"));
        assert!(!is_loopback_endpoint("https://api.openai.com"));
        assert!(!is_loopback_endpoint("http://192.168.1.50:11434"));

        let extractor = TypedStructuredExtractor::<SelfRagCritique>::new(
            "http://127.0.0.1:11434",
            "qwen2.5:7b",
            "Audit factual grounding.",
        );
        let schema = extractor.json_schema();
        assert!(schema["properties"]["is_grounded"].is_object());
        assert!(schema["properties"]["missing_document_refs"].is_object());

        let gbnf = extractor.gbnf_grammar();
        assert!(gbnf.starts_with("root ::= ws "), "GBNF must begin with root rule:\n{gbnf}");
        assert!(gbnf.contains("is_grounded"), "GBNF must encode is_grounded field:\n{gbnf}");
        assert!(gbnf.contains("missing_document_refs"), "GBNF must encode array field:\n{gbnf}");
        assert!(gbnf.contains("boolean ::= \"true\" | \"false\""));
    }

    #[tokio::test]
    async fn test_typed_extractor_live_loopback_ollama_and_gbnf_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 32768];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let resp_body = if req.starts_with("POST /api/chat") {
                        assert!(req.contains("\"format\""), "Ollama call must carry JSON Schema format");
                        serde_json::json!({
                            "model": "qwen2.5:7b",
                            "message": {
                                "role": "assistant",
                                "content": "{\"is_grounded\":true,\"answers_all_sub_questions\":true,\"unsupported_claims\":[],\"missing_document_refs\":[],\"confidence\":0.96}"
                            },
                            "done": true
                        })
                        .to_string()
                    } else {
                        assert!(req.starts_with("POST /v1/chat/completions"));
                        assert!(req.contains("\"grammar\""), "GGUF call must carry compiled GBNF grammar");
                        serde_json::json!({
                            "choices": [{
                                "message": {
                                    "role": "assistant",
                                    "content": "{\"faithfulness\":0.98,\"answer_relevance\":0.95,\"context_precision\":0.92,\"zero_omission_completeness\":1.0,\"rationale\":\"Every claim matches retrieved excerpts with zero omitted sources.\"}"
                                }
                            }]
                        })
                        .to_string()
                    };
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = sock.write_all(http.as_bytes()).await;
                }
            }
        });

        let endpoint = format!("http://127.0.0.1:{}", addr.port());
        let critique_ext = TypedStructuredExtractor::<SelfRagCritique>::new(
            &endpoint,
            "qwen2.5:7b",
            "Verify grounding.",
        );
        let critique = critique_ext
            .extract_ollama_async("Audit answer against sources [1]..[3].")
            .await
            .expect("Ollama typed extraction must succeed");
        assert!(critique.is_grounded);
        assert!(critique.answers_all_sub_questions);
        assert!(critique.confidence > 0.9);

        let judge_ext = TypedStructuredExtractor::<LlmJudgeEvaluation>::new(
            &endpoint,
            "qwen2.5:7b",
            "Score RAGAS dimensions.",
        );
        let judge = judge_ext
            .extract_gbnf_server_async("Evaluate answer quality.")
            .await
            .expect("GGUF GBNF typed extraction must succeed");
        assert!(judge.faithfulness >= 0.95);
        assert_eq!(judge.zero_omission_completeness, 1.0);

        let _ = server.await;
    }
}
