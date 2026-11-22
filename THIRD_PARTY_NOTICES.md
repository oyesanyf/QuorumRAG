# Third-Party Notices

QuorumRAG incorporates algorithms and data-format specifications inspired by and interoperable with the following MIT-licensed open-source projects:

## AtlasKV (HKUST-KnowComp)

- **Repository**: https://github.com/HKUST-KnowComp/AtlasKV
- **Paper**: *"AtlasKV: Augmenting LLMs with Billion-Scale Knowledge Graphs in 20GB VRAM"* (ICLR 2026, arXiv:2510.17934)
- **License**: MIT License
- **Components Adapted / Interoperated**: KG2KV `"the {relation} of {entity}"` key representation, 3-level hierarchical clustering scaling ($k_{\text{inter1}} = \lceil N^{2/3} \rceil$, $k_{\text{root}} = \lceil N^{1/3} \rceil$), HiKVP hierarchical key-value pruning traversal (`Root -> Inter1 -> Leaf`), and native `*_qkv.json` / `.npy` / `c2id` / `id2c` dataset interoperability implemented natively in pure Rust inside `crates/quorum-atlaskv`.

## KBLaM (Microsoft Corporation)

- **Repository**: https://github.com/microsoft/KBLaM
- **License**: MIT License
- **Attribution**: Upstream key-value knowledge base formulation referenced by AtlasKV.
