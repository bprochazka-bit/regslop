//! Value endpoints: set, get, delete.

use serde_json::{json, Value};

use super::{get_hive, req_path, req_str};
use crate::error::AgentError;
use crate::offreg::key::Key;
use crate::state::AppState;
use crate::valuec;

/// POST /value/set { handle, key, name, type, data } -> {}
pub fn set(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let key_path = req_path(body, "key")?;
    let name = req_str(body, "name")?;
    let type_name = req_str(body, "type")?;
    let data = body.get("data").cloned().unwrap_or(Value::Null);

    let (ty, bytes) = valuec::encode(&type_name, &data)?;
    let key = Key::open(hive.root(), &key_path)?;
    key.set_value(&name, ty, &bytes)?;
    Ok(json!({}))
}

/// GET /value/get { handle, key, name } -> { type, data }
pub fn get(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let key_path = req_path(body, "key")?;
    let name = req_str(body, "name")?;

    let key = Key::open(hive.root(), &key_path)?;
    let (ty, bytes) = key.get_value(&name)?;
    Ok(json!({
        "type": valuec::type_name(ty),
        "data": valuec::decode(ty, &bytes),
    }))
}

/// POST /value/delete { handle, key, name } -> {}
pub fn delete(state: &AppState, body: &Value) -> Result<Value, AgentError> {
    let arc = get_hive(state, body)?;
    let hive = arc.lock().unwrap();
    let key_path = req_path(body, "key")?;
    let name = req_str(body, "name")?;

    let key = Key::open(hive.root(), &key_path)?;
    key.delete_value(&name)?;
    Ok(json!({}))
}
