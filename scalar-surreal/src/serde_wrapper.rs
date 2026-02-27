use std::{fmt::Display, marker::PhantomData};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use surrealdb::{
    types::{Kind, SerializationError, SurrealValue, Value},
    Error,
};

use crate::serde_wrapper::{de::WrappedValue, ser::Serializer};

mod de;
mod ser;

#[derive(Debug)]
pub struct WrappedError(Error);

impl Display for WrappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for WrappedError {}

impl WrappedError {
    pub fn serialization(message: String, details: impl Into<Option<SerializationError>>) -> Self {
        Self(Error::serialization(message, details))
    }
}

impl From<WrappedError> for Error {
    fn from(value: WrappedError) -> Self {
        value.0
    }
}

/// A wrapper struct that allows bridging between SurrealValue and types that implement Serialize
/// and Deserialize
///
/// # A note on parity with `SurrealValue`
/// Serializing and Deserializing a type does *not* behave the same as `SurrealValue` in some cases.
/// Notably:
/// - Enum variants behave differently
/// - The only primitives taken advantage of are String, Number, Object, Bool, and Array
///
/// As such, it's best to use SurrealValue directly where possible. This is intended for types where
/// an implementation of SurrealValue isn't available or practical
#[derive(Debug)]
pub struct Wrapper<'de, T: Serialize + Deserialize<'de>>(pub T, PhantomData<&'de T>);

impl<'de, T: Serialize + Deserialize<'de>> Wrapper<'de, T> {
    pub fn new(value: T) -> Self {
        Self(value, PhantomData)
    }
}

impl<'de, T: Serialize + Deserialize<'de>> SurrealValue for Wrapper<'de, T> {
    fn kind_of() -> Kind {
        Kind::Any
    }

    fn into_value(self) -> Value {
        self.0
            .serialize(Serializer)
            .expect("serialization to a value failed!")
    }

    fn from_value(value: Value) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self::new(T::deserialize(WrappedValue(value))?))
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;

    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    use crate::serde_wrapper::de::WrappedValue;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    enum Test {
        A,
        B(u8),
        C { hi: String },
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Test2 {
        is_goober: bool,
        sneaky_and_evil: (),
        also_sneaky_and_evil: Gerald,
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Gerald;

    #[rstest]
    #[case::u8(64_u8)]
    #[case::u16(64_u16)]
    #[case::u32(64_u32)]
    #[case::u64(64_u64)]
    #[case::i8(64_i8)]
    #[case::i16(64_i16)]
    #[case::i32(64_i32)]
    #[case::i64(64_i64)]
    #[case::f32(64.0_f32)]
    #[case::f64(64.0_f64)]
    #[case::bool(true)]
    #[case::zst_unit(())]
    #[case::zst_arr([(); 0])]
    #[case::zst_struct(Gerald)]
    // static strings don't work because Value isn't zero-copy
    //#[case::static_str("woag!")]
    #[case::string("woag!".to_string())]
    #[case::unit_enum(Test::A)]
    #[case::newtype_enum(Test::B(64))]
    #[case::struct_enum(Test::C{hi: "woag!".to_string()})]
    #[case::_struct(Test2 {
		is_goober: true,
		sneaky_and_evil: (),
		also_sneaky_and_evil: Gerald
	})]
    fn wrapper_roundtrip<'a>(#[case] value: impl Serialize + Deserialize<'a> + PartialEq + Debug) {
        use crate::serde_wrapper::ser::Serializer;

        let serialized_value = value.serialize(Serializer).expect("this should work!");
        let deserialized_value = <_ as Deserialize>::deserialize(WrappedValue(serialized_value))
            .expect("this should work!");
        assert_eq!(value, deserialized_value);
    }
}
