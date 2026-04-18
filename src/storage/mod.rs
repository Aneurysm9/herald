//! Generic `SQLite` storage for key-value pairs with timestamps.
//!
//! Provides a reusable storage layer for providers that need persistent state
//! (ACME challenges, dynamic DNS records, etc.).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;
use std::path::Path;

/// Trait for storage keys that can be serialized to/from SQL.
///
/// Keys must provide stable string representations for use as PRIMARY KEY.
pub(crate) trait StorageKey {
    /// Convert key to SQL representation.
    ///
    /// For simple keys (String, FQDN), this might just return self.
    /// For composite keys (zone, name, type), return a deterministic format.
    fn to_sql(&self) -> String;

    /// Parse key from SQL representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be parsed into a valid key.
    fn from_sql(s: &str) -> Result<Self>
    where
        Self: Sized;
}

/// String keys use themselves as SQL representation.
impl StorageKey for String {
    fn to_sql(&self) -> String {
        self.clone()
    }

    fn from_sql(s: &str) -> Result<Self> {
        Ok(s.to_string())
    }
}

/// Generic `SQLite` key-value store with automatic timestamping.
///
/// Stores entries as JSON blobs with automatic `updated_at` tracking.
/// Provides ACID guarantees for persistence.
///
/// # Type Parameters
///
/// - `K`: Key type implementing `StorageKey`
/// - `V`: Value type implementing `Serialize + DeserializeOwned`
pub(crate) struct SqliteStorage<K, V> {
    conn: Connection,
    table_name: String,
    _phantom: PhantomData<(K, V)>,
}

impl<K, V> SqliteStorage<K, V>
where
    K: StorageKey,
    V: Serialize + DeserializeOwned,
{
    /// Open or create database at the given path.
    ///
    /// Initializes the schema if the database is new. Safe to call on existing
    /// databases (uses `CREATE TABLE IF NOT EXISTS`).
    ///
    /// # Arguments
    ///
    /// - `path`: Path to the `SQLite` database file
    /// - `table_name`: Name for the table (e.g., `"acme_challenges"`, `"dynamic_records"`)
    ///
    /// # Errors
    ///
    /// Returns an error if the database file cannot be opened or the schema
    /// cannot be initialized.
    pub(crate) fn new(path: &Path, table_name: &str) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database at {}", path.display()))?;

        Self::init_schema(&conn, table_name)?;

        Ok(Self {
            conn,
            table_name: table_name.to_string(),
            _phantom: PhantomData,
        })
    }

    /// Create an in-memory database for testing.
    ///
    /// Uses `SQLite`'s `:memory:` special filename. All data is lost when the
    /// connection is closed.
    ///
    /// # Arguments
    ///
    /// - `table_name`: Name for the table
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory database cannot be created or the
    /// schema cannot be initialized.
    #[cfg(test)]
    pub(crate) fn in_memory(table_name: &str) -> Result<Self> {
        let conn = Connection::open_in_memory().context("creating in-memory database")?;

        Self::init_schema(&conn, table_name)?;

        Ok(Self {
            conn,
            table_name: table_name.to_string(),
            _phantom: PhantomData,
        })
    }

    /// Initialize database schema.
    fn init_schema(conn: &Connection, table_name: &str) -> Result<()> {
        let create_table = format!(
            "CREATE TABLE IF NOT EXISTS {table_name} (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )"
        );

        conn.execute(&create_table, [])
            .with_context(|| format!("creating {table_name} table"))?;

        let create_index = format!(
            "CREATE INDEX IF NOT EXISTS idx_{table_name}_updated_at
             ON {table_name}(updated_at)"
        );

        conn.execute(&create_index, [])
            .with_context(|| format!("creating {table_name} updated_at index"))?;

        Ok(())
    }

    /// Load all entries from database.
    ///
    /// Returns a vector of `(K, V)` tuples suitable for populating an
    /// in-memory `HashMap`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or deserialization fails.
    pub(crate) fn load_all(&self) -> Result<Vec<(K, V)>> {
        let query = format!("SELECT key, value FROM {}", self.table_name);
        let mut stmt = self.conn.prepare(&query)?;

        let entries = stmt
            .query_map([], |row| {
                let key_str: String = row.get(0)?;
                let value_json: String = row.get(1)?;
                Ok((key_str, value_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        entries
            .into_iter()
            .map(|(key_str, value_json)| {
                let key = K::from_sql(&key_str)?;
                let value: V = serde_json::from_str(&value_json)
                    .with_context(|| format!("deserializing value for key {key_str}"))?;
                Ok((key, value))
            })
            .collect()
    }

    /// Insert or update an entry.
    ///
    /// Uses `INSERT OR REPLACE` for upsert semantics. Automatically sets
    /// `updated_at` to the current Unix timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or the insert/update fails.
    pub(crate) fn upsert(&self, key: &K, value: &V) -> Result<()> {
        let key_sql = key.to_sql();
        let value_json = serde_json::to_string(value)
            .with_context(|| format!("serializing value for key {key_sql}"))?;

        #[allow(clippy::cast_possible_wrap)]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let query = format!(
            "INSERT OR REPLACE INTO {} (key, value, updated_at) VALUES (?1, ?2, ?3)",
            self.table_name
        );

        self.conn
            .execute(&query, params![key_sql, value_json, now])?;

        Ok(())
    }

    /// Delete an entry.
    ///
    /// Deleting a nonexistent entry is a no-op (idempotent).
    ///
    /// # Errors
    ///
    /// Returns an error if the delete operation fails.
    pub(crate) fn delete(&self, key: &K) -> Result<()> {
        let key_sql = key.to_sql();
        let query = format!("DELETE FROM {} WHERE key = ?1", self.table_name);

        self.conn.execute(&query, params![key_sql])?;

        Ok(())
    }

    /// Atomically delete one key and insert another in a single transaction.
    ///
    /// Used by the RFC 2136 backend to swap managed record keys when a record's
    /// value changes (the composite key includes the value). If `old_key` does
    /// not exist the delete is a no-op — the new key is still inserted.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started, or if the delete
    /// or insert fails (in which case neither operation is committed).
    pub(crate) fn swap(&self, old_key: &K, new_key: &K, new_value: &V) -> Result<()> {
        let old_key_sql = old_key.to_sql();
        let new_key_sql = new_key.to_sql();
        let new_value_json = serde_json::to_string(new_value)
            .with_context(|| format!("serializing value for key {new_key_sql}"))?;

        #[allow(clippy::cast_possible_wrap)]
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        let tx = self.conn.unchecked_transaction()?;

        let delete_query = format!("DELETE FROM {} WHERE key = ?1", self.table_name);
        tx.execute(&delete_query, params![old_key_sql])?;

        let insert_query = format!(
            "INSERT OR REPLACE INTO {} (key, value, updated_at) VALUES (?1, ?2, ?3)",
            self.table_name
        );
        tx.execute(&insert_query, params![new_key_sql, new_value_json, now])?;

        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestEntry {
        value: String,
        count: u32,
    }

    #[test]
    fn test_string_key_storage() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        // Initially empty
        let entries = storage.load_all().unwrap();
        assert!(entries.is_empty());

        // Insert entry
        let key = "test_key".to_string();
        let entry = TestEntry {
            value: "hello".to_string(),
            count: 42,
        };
        storage.upsert(&key, &entry).unwrap();

        // Load and verify
        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, key);
        assert_eq!(entries[0].1, entry);
    }

    #[test]
    fn test_upsert_updates_existing() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        let key = "key1".to_string();

        // Insert
        storage
            .upsert(
                &key,
                &TestEntry {
                    value: "v1".to_string(),
                    count: 1,
                },
            )
            .unwrap();

        // Update
        storage
            .upsert(
                &key,
                &TestEntry {
                    value: "v2".to_string(),
                    count: 2,
                },
            )
            .unwrap();

        // Verify only one entry exists with updated value
        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.value, "v2");
        assert_eq!(entries[0].1.count, 2);
    }

    #[test]
    fn test_delete() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        let key = "key1".to_string();
        storage
            .upsert(
                &key,
                &TestEntry {
                    value: "v1".to_string(),
                    count: 1,
                },
            )
            .unwrap();

        // Delete
        storage.delete(&key).unwrap();

        // Verify empty
        let entries = storage.load_all().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_delete_nonexistent_is_noop() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        // Delete nonexistent key
        storage.delete(&"nonexistent".to_string()).unwrap();

        // No error, database still empty
        let entries = storage.load_all().unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_multiple_entries() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        // Insert multiple
        for i in 0..5 {
            storage
                .upsert(
                    &format!("key{i}"),
                    &TestEntry {
                        value: format!("value{i}"),
                        count: i,
                    },
                )
                .unwrap();
        }

        // Verify count
        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 5);
    }

    #[test]
    fn test_swap_basic() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        let key1 = "key1".to_string();
        let key2 = "key2".to_string();
        let entry1 = TestEntry {
            value: "old".to_string(),
            count: 1,
        };
        let entry2 = TestEntry {
            value: "new".to_string(),
            count: 2,
        };

        storage.upsert(&key1, &entry1).unwrap();

        // Swap key1 → key2
        storage.swap(&key1, &key2, &entry2).unwrap();

        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, key2);
        assert_eq!(entries[0].1.value, "new");
        assert_eq!(entries[0].1.count, 2);
    }

    #[test]
    fn test_swap_same_key() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        let key = "key1".to_string();
        let entry = TestEntry {
            value: "original".to_string(),
            count: 1,
        };
        storage.upsert(&key, &entry).unwrap();

        // Swap with same key (e.g., TTL-only change)
        let updated = TestEntry {
            value: "updated".to_string(),
            count: 2,
        };
        storage.swap(&key, &key, &updated).unwrap();

        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.value, "updated");
    }

    #[test]
    fn test_swap_nonexistent_old_key() {
        let storage: SqliteStorage<String, TestEntry> =
            SqliteStorage::in_memory("test_table").unwrap();

        let old_key = "nonexistent".to_string();
        let new_key = "key2".to_string();
        let entry = TestEntry {
            value: "new".to_string(),
            count: 1,
        };

        // Old key doesn't exist — swap should still insert the new key
        storage.swap(&old_key, &new_key, &entry).unwrap();

        let entries = storage.load_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, new_key);
    }
}
