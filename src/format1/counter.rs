use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter(BigUint);

impl Counter {
    pub fn zero() -> Self {
        Self(BigUint::default())
    }

    pub fn from_decimal(value: &str) -> Result<Self, String> {
        if value != "0"
            && (value.is_empty()
                || value.starts_with('0')
                || !value.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err("counter must be canonical non-negative decimal".to_string());
        }
        BigUint::from_str(value)
            .map(Self)
            .map_err(|error| error.to_string())
    }

    pub fn canonical_decimal(&self) -> String {
        self.0.to_str_radix(10)
    }

    pub fn allocate(&mut self) -> Self {
        let allocated = self.clone();
        self.0 += 1_u8;
        allocated
    }
}

impl From<u64> for Counter {
    fn from(value: u64) -> Self {
        Self(value.into())
    }
}

impl From<usize> for Counter {
    fn from(value: usize) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_decimal())
    }
}

impl Serialize for Counter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.canonical_decimal())
    }
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_decimal(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Counter;

    #[test]
    fn allocates_beyond_u64_without_wrap() {
        let mut counter = Counter::from_decimal("18446744073709551615").unwrap();
        assert_eq!(counter.allocate().to_string(), "18446744073709551615");
        assert_eq!(counter.allocate().to_string(), "18446744073709551616");
        assert_eq!(counter.to_string(), "18446744073709551617");
    }

    #[test]
    fn serde_projection_is_canonical_decimal() {
        let counter = Counter::from_decimal("9007199254740993").unwrap();
        assert_eq!(
            serde_json::to_string(&counter).unwrap(),
            "\"9007199254740993\""
        );
        assert_eq!(
            serde_json::from_str::<Counter>("\"9007199254740993\"").unwrap(),
            counter
        );
    }
}
