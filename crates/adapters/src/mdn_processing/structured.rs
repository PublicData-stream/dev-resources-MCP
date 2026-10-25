//! Bounded event readers reject aliases, duplicate keys, deep nesting and tags.
use super::{ProcessingBudget, limit, malformed};
use devres_domain::Result;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::TScalarStyle,
};

enum Container {
    Array(Vec<Value>),
    Object(Map<String, Value>, Option<String>),
}
fn insert(stack: &mut [Container], root: &mut Option<Value>, value: Value) -> Result<()> {
    match stack.last_mut() {
        Some(Container::Array(items)) => items.push(value),
        Some(Container::Object(items, key)) => {
            if let Some(key) = key.take() {
                if items.insert(key, value).is_some() {
                    return Err(malformed());
                }
            } else {
                let name = value
                    .as_str()
                    .filter(|s| s.len() <= 4096)
                    .ok_or_else(malformed)?;
                if items.contains_key(name) {
                    return Err(malformed());
                }
                *key = Some(name.into());
            }
        }
        None => {
            if root.replace(value).is_some() {
                return Err(malformed());
            }
        }
    }
    Ok(())
}
pub(super) fn yaml(source: &str, budget: &ProcessingBudget) -> Result<Value> {
    let mut parser = Parser::new_from_str(source);
    let mut stack = Vec::new();
    let mut root = None;
    let mut documents = 0;
    let mut count = 0;
    loop {
        budget.check()?;
        count += 1;
        if count > 20_000 {
            return Err(limit());
        }
        let (event, _) = parser.next_token().map_err(|_| malformed())?;
        match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(malformed());
                }
            }
            Event::MappingStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(malformed());
                }
                stack.push(Container::Object(Map::new(), None));
            }
            Event::SequenceStart(anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    return Err(malformed());
                }
                stack.push(Container::Array(Vec::new()));
            }
            Event::MappingEnd => {
                let Some(Container::Object(map, None)) = stack.pop() else {
                    return Err(malformed());
                };
                insert(&mut stack, &mut root, Value::Object(map))?;
            }
            Event::SequenceEnd => {
                let Some(Container::Array(items)) = stack.pop() else {
                    return Err(malformed());
                };
                insert(&mut stack, &mut root, Value::Array(items))?;
            }
            Event::Alias(_) => return Err(malformed()),
            Event::Scalar(s, style, anchor, tag) => {
                if anchor != 0 || tag.is_some() || s.len() > 64 * 1024 {
                    return Err(malformed());
                }
                let key = matches!(stack.last(), Some(Container::Object(_, None)));
                let value = if style == TScalarStyle::Plain && !key {
                    match yaml_rust2::Yaml::from_str(&s) {
                        yaml_rust2::Yaml::String(value) => Value::String(value),
                        yaml_rust2::Yaml::Integer(value) => Value::Number(value.into()),
                        yaml_rust2::Yaml::Boolean(value) => Value::Bool(value),
                        yaml_rust2::Yaml::Null => Value::Null,
                        yaml_rust2::Yaml::Real(value) => value.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(Value::Number).unwrap_or_else(||serde_json::json!({"unsupported_yaml_scalar":value,"kind":"real"})),
                        _ => return Err(malformed()),
                    }
                } else {
                    Value::String(s)
                };
                insert(&mut stack, &mut root, value)?;
            }
            _ => {}
        }
        if stack.len() > 64 {
            return Err(limit());
        }
    }
    if !stack.is_empty() {
        return Err(malformed());
    }
    root.ok_or_else(malformed)
}

struct Seed<'a> {
    budget: &'a ProcessingBudget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> std::result::Result<Value, D::Error> {
        self.budget
            .check()
            .map_err(|_| D::Error::custom("processing budget"))?;
        if self.depth > 64 {
            return Err(D::Error::custom("nesting limit"));
        }
        de.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON data")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if out.len() >= 100_000 {
                return Err(A::Error::custom("array limit"));
            }
            out.push(value);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 4096 || out.len() >= 100_000 || out.contains_key(&key) {
                return Err(A::Error::custom("duplicate or excessive JSON key"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}
pub(super) fn json(source: &[u8], budget: &ProcessingBudget) -> Result<Value> {
    budget.check()?;
    if source.len() > super::MAX_MEMBER {
        return Err(limit());
    }
    let mut de = serde_json::Deserializer::from_slice(source);
    let value = Seed { budget, depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| malformed())?;
    de.end().map_err(|_| malformed())?;
    budget.check()?;
    Ok(value)
}
