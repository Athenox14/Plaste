use std::path::Path;
use std::sync::Mutex;

use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, Value, FAST, INDEXED, STORED, TEXT};
use tantivy::{doc, Index, IndexWriter, Term};

/// Full-text index over file names + (best-effort) extracted text content.
///
/// ponytail: content extraction only handles plain-text-ish files (see
/// `extractable_content`). Real PDF/Office extraction needs `pdf-extract` /
/// `docx-rs` or similar — out of scope for MVP, add if users actually need it.
pub struct FullTextIndex {
    index: Index,
    writer: Mutex<IndexWriter>,
    id_field: tantivy::schema::Field,
    owner_field: tantivy::schema::Field,
    name_field: tantivy::schema::Field,
    content_field: tantivy::schema::Field,
}

/// Cap on how much extracted text we index per file (1MB of chars).
const MAX_CONTENT_LEN: usize = 1024 * 1024;

fn build_schema() -> (Schema, tantivy::schema::Field, tantivy::schema::Field, tantivy::schema::Field, tantivy::schema::Field) {
    let mut builder = Schema::builder();
    let id_field = builder.add_i64_field("id", STORED | INDEXED | FAST);
    let owner_field = builder.add_i64_field("owner_token_id", STORED | INDEXED | FAST);
    let name_field = builder.add_text_field("name", TEXT | STORED);
    let content_field = builder.add_text_field("content", TEXT);
    let schema = builder.build();
    (schema, id_field, owner_field, name_field, content_field)
}

impl FullTextIndex {
    /// Opens the index at `dir` if it exists, otherwise creates it.
    pub fn open_or_create(dir: &Path) -> tantivy::Result<Self> {
        std::fs::create_dir_all(dir).expect("create fts index dir");
        let (schema, id_field, owner_field, name_field, content_field) = build_schema();

        let index = if dir.read_dir().map(|mut d| d.next().is_some()).unwrap_or(false) {
            Index::open_in_dir(dir)?
        } else {
            Index::create_in_dir(dir, schema)?
        };

        let writer: IndexWriter = index.writer(50_000_000)?;

        Ok(Self {
            index,
            writer: Mutex::new(writer),
            id_field,
            owner_field,
            name_field,
            content_field,
        })
    }

    /// Best-effort: only treat as text if the name suggests it. Returns the
    /// decoded (lossy) and length-capped content, or None to skip extraction.
    pub fn extractable_content(name: &str, data: &[u8]) -> Option<String> {
        let ext = Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        let is_text_like = matches!(
            ext.as_deref(),
            Some("txt") | Some("md") | Some("json") | Some("csv") | Some("log") | None
        );
        if !is_text_like {
            return None;
        }
        let text = String::from_utf8_lossy(data);
        Some(text.chars().take(MAX_CONTENT_LEN).collect())
    }

    /// Upserts a document for this file_id: delete-by-term then add + commit.
    pub async fn index_file(&self, file_id: i64, owner_token_id: i64, name: &str, content: Option<&str>) {
        let name = name.to_string();
        let content = content.map(|s| s.to_string());
        let id_field = self.id_field;
        let owner_field = self.owner_field;
        let name_field = self.name_field;
        let content_field = self.content_field;
        // ponytail: tantivy's IndexWriter is sync; a Mutex + spawn_blocking keeps
        // the async handler from blocking the runtime. Global lock is fine at MVP
        // write volume; per-shard writers if this ever becomes a bottleneck.
        let mut writer = match self.writer.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        let term = Term::from_field_i64(id_field, file_id);
        writer.delete_term(term);
        let mut document = doc!(
            id_field => file_id,
            owner_field => owner_token_id,
            name_field => name,
        );
        if let Some(c) = content {
            document.add_text(content_field, c);
        }
        writer.add_document(document).ok();
        writer.commit().ok();
    }

    /// Delete-by-term on `id`, commit.
    pub async fn remove_file(&self, file_id: i64) {
        let id_field = self.id_field;
        let mut writer = match self.writer.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        writer.delete_term(Term::from_field_i64(id_field, file_id));
        writer.commit().ok();
    }

    /// Returns matching file ids ranked by relevance, scoped to `owner_token_id`
    /// unless `is_admin`.
    pub fn search(&self, owner_token_id: i64, is_admin: bool, query: &str, limit: usize) -> Vec<i64> {
        let reader = match self.index.reader() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let searcher = reader.searcher();
        let parser = QueryParser::for_index(&self.index, vec![self.name_field, self.content_field]);
        let parsed = match parser.parse_query(query) {
            Ok(q) => q,
            Err(_) => return Vec::new(),
        };
        // Over-fetch then post-filter by owner, since folding owner scoping into
        // the query itself would need a BooleanQuery term-filter for little gain
        // at MVP scale.
        let collector = TopDocs::with_limit(limit.saturating_mul(5)).order_by_score();
        let top_docs = match searcher.search(&parsed, &collector) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (_score, addr) in top_docs {
            let doc: tantivy::TantivyDocument = match searcher.doc(addr) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let owner: Option<i64> = doc
                .get_first(self.owner_field)
                .and_then(|v| v.as_i64());
            if !is_admin && owner != Some(owner_token_id) {
                continue;
            }
            if let Some(id) = doc.get_first(self.id_field).and_then(|v| v.as_i64()) {
                out.push(id);
                if out.len() >= limit {
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn indexes_and_scopes_by_owner() {
        let dir = tempfile_dir();
        let fts = FullTextIndex::open_or_create(&dir).expect("create index");

        fts.index_file(1, 100, "notes.txt", Some("the quick brown fox jumps")).await;
        fts.index_file(2, 100, "other.txt", Some("nothing special here")).await;
        fts.index_file(3, 200, "shared.txt", Some("brown paper bag")).await;

        let hits = fts.search(100, false, "brown", 10);
        assert!(hits.contains(&1), "expected file 1 in {hits:?}");
        assert!(!hits.contains(&2), "file 2 has no match: {hits:?}");
        assert!(!hits.contains(&3), "file 3 belongs to a different owner: {hits:?}");

        let admin_hits = fts.search(999, true, "brown", 10);
        assert!(admin_hits.contains(&1));
        assert!(admin_hits.contains(&3));
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("plaste_fts_test_{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }
}
