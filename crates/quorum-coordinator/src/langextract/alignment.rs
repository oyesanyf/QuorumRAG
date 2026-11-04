use super::extraction::Extraction;
use serde::{Deserialize, Serialize};

/// Few-shot example pair containing source reference text and grounded extractions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExampleData {
    pub text: String,
    pub extractions: Vec<Extraction>,
}

impl ExampleData {
    pub fn new(text: impl Into<String>, extractions: Vec<Extraction>) -> Self {
        Self {
            text: text.into(),
            extractions,
        }
    }

    /// Validates schema alignment:
    /// Checks that example extractions match class rules and have valid bounds within example text.
    pub fn validate_schema(&self) -> Result<(), String> {
        for (i, ext) in self.extractions.iter().enumerate() {
            if ext.extraction_class.trim().is_empty() {
                return Err(format!("Extraction {} has empty extraction_class", i));
            }
            if ext.extraction_text.trim().is_empty() {
                return Err(format!("Extraction {} has empty extraction_text", i));
            }
            if let Some((start, end)) = ext.char_interval {
                if start > end {
                    return Err(format!(
                        "Extraction {} interval start {} is greater than end {}",
                        i, start, end
                    ));
                }
                if end > self.text.len() {
                    return Err(format!(
                        "Extraction {} interval end {} exceeds text length {}",
                        i, end, self.text.len()
                    ));
                }
                if !self.text.is_char_boundary(start) || !self.text.is_char_boundary(end) {
                    return Err(format!(
                        "Extraction {} interval ({}, {}) does not align to UTF-8 char boundary",
                        i, start, end
                    ));
                }
                let actual_span = &self.text[start..end];
                if !actual_span.eq_ignore_ascii_case(&ext.extraction_text) {
                    return Err(format!(
                        "Extraction {} span '{}' does not match extraction_text '{}'",
                        i, actual_span, ext.extraction_text
                    ));
                }
            }
        }
        Ok(())
    }
}
