# QuorumRAG container image (published to ghcr.io/oyesanyf/quorumrag by
# .github/workflows/container-publish.yml from the release's prebuilt Linux binaries).
#
#   docker run -d --name quorumrag -p 3031:3031 -p 3032:3032 \
#     -v quorumrag-data:/var/lib/quorumrag \
#     ghcr.io/oyesanyf/quorumrag:latest
#
# Ollama: on Linux add --network host so the default http://127.0.0.1:11434 reaches the host's
# Ollama; otherwise set the Ollama URL in the Web UI Settings (e.g. http://host.docker.internal:11434).
#
# Build context layout expected:  bin/amd64/quorumrag  and/or  bin/arm64/quorumrag
FROM ubuntu:26.04

ARG TARGETARCH
ARG VERSION=0.6.0

LABEL org.opencontainers.image.source="https://github.com/oyesanyf/QuorumRAG" \
      org.opencontainers.image.title="QuorumRAG" \
      org.opencontainers.image.description="Local-first P2P agentic RAG daemon with an embedded ChatGPT-style Web UI" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home-dir /var/lib/quorumrag --shell /usr/sbin/nologin quorumrag \
 && mkdir -p /var/lib/quorumrag/data /var/lib/quorumrag/docs \
 && chown -R quorumrag:quorumrag /var/lib/quorumrag

COPY --chmod=0755 bin/${TARGETARCH}/quorumrag /usr/bin/quorumrag

USER quorumrag
WORKDIR /var/lib/quorumrag
VOLUME ["/var/lib/quorumrag"]
EXPOSE 3031 3032

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3031/api/health || exit 1

ENTRYPOINT ["/usr/bin/quorumrag"]
CMD ["--host", "0.0.0.0", "--port", "3031", "--p2p-port", "3032", \
     "--data-dir", "/var/lib/quorumrag/data", "--watch-dir", "/var/lib/quorumrag/docs", "--no-browser"]
