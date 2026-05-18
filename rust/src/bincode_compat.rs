use serde::{de::DeserializeOwned, Serialize};

pub fn serialize<T>(value: &T) -> Result<Vec<u8>, bincode::error::EncodeError>
where
    T: ?Sized + Serialize,
{
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
}

pub fn deserialize<T>(bytes: &[u8]) -> Result<T, bincode::error::DecodeError>
where
    T: DeserializeOwned,
{
    let (value, _) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())?;
    Ok(value)
}
