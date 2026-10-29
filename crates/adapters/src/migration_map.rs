//! Incremental admission for offline migration identity/proof working sets.
use devres_domain::{Error, Result};
use std::collections::BTreeMap;

const ACCOUNT: &str = "\0devres-migration-working-set-v1";
const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const ENTRY_OVERHEAD: usize = 128;

fn capacity() -> Error {
    Error::capacity("Migration identity working-set budget exhausted; history is preserved.")
}
fn account(map: &BTreeMap<String, String>) -> Result<(usize, usize)> {
    if let Some(value) = map.get(ACCOUNT) {
        let (objects, aliases) = value.split_once(':').ok_or_else(capacity)?;
        return Ok((
            objects.parse().map_err(|_| capacity())?,
            aliases.parse().map_err(|_| capacity())?,
        ));
    }
    let bytes = map.iter().try_fold(0_usize, |total, (key, value)| {
        total
            .checked_add(key.len() + value.len() + ENTRY_OVERHEAD)
            .ok_or_else(capacity)
    })?;
    Ok((bytes, 0))
}
fn store(map: &mut BTreeMap<String, String>, objects: usize, aliases: usize) {
    map.insert(ACCOUNT.into(), format!("{objects}:{aliases}"));
}
pub(crate) fn insert(map: &mut BTreeMap<String, String>, key: String, value: String) -> Result<()> {
    if key == ACCOUNT {
        return Err(Error::integrity("Reserved migration identity."));
    }
    let (objects, aliases) = account(map)?;
    let (objects, new) = if let Some(old) = map.get(&key) {
        (
            objects
                .checked_sub(old.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or_else(capacity)?,
            false,
        )
    } else {
        (
            objects
                .checked_add(key.len() + value.len() + ENTRY_OVERHEAD)
                .ok_or_else(capacity)?,
            true,
        )
    };
    if objects.checked_add(aliases).is_none_or(|n| n > MAX_BYTES) || new && map.len() >= MAX_ENTRIES
    {
        return Err(capacity());
    }
    map.insert(key, value);
    store(map, objects, aliases);
    Ok(())
}
pub(crate) fn reserve_alias(
    map: &mut BTreeMap<String, String>,
    alias: &(String, String, String),
) -> Result<()> {
    let (objects, aliases) = account(map)?;
    let aliases = aliases
        .checked_add(alias.0.len() + alias.1.len() + alias.2.len() + ENTRY_OVERHEAD)
        .ok_or_else(capacity)?;
    if objects.checked_add(aliases).is_none_or(|n| n > MAX_BYTES) {
        return Err(capacity());
    }
    store(map, objects, aliases);
    Ok(())
}
pub(crate) fn reset_aliases(map: &mut BTreeMap<String, String>) -> Result<()> {
    let (objects, _) = account(map)?;
    store(map, objects, 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admission_accounts_replacements_and_alias_lifetimes() {
        let mut map = BTreeMap::new();
        insert(&mut map, "one".into(), "value".into()).unwrap();
        let initial = account(&map).unwrap().0;
        insert(&mut map, "one".into(), "x".into()).unwrap();
        assert_eq!(account(&map).unwrap().0, initial - 4);
        reserve_alias(&mut map, &("nodes".into(), "old".into(), "new".into())).unwrap();
        assert!(account(&map).unwrap().1 > 0);
        reset_aliases(&mut map).unwrap();
        assert_eq!(account(&map).unwrap().1, 0);
        assert!(insert(&mut map, ACCOUNT.into(), "invalid".into()).is_err());
    }
}
