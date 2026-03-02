use std::{fmt::Display, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::{
    db::{ContentActions, ValidationContext},
    DatabaseConnection, Document,
};

/// A wrapper type to indicate that the inner type is valid.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct Valid<T: Document>(T);

impl<T: Document + Sync> Valid<T> {
    /// Validates the input, then returns a Valid<T>.
    ///
    /// # Errors
    ///
    /// This function will return an error if validation fails.
    pub async fn new<DB: DatabaseConnection + ContentActions<T> + Sync>(
        val: T,
        ctx: ValidationContext<'_, DB, T>,
    ) -> Result<Self, ValidationError> {
        val.validate(ctx).await?;
        Ok(Self(val))
    }

    pub fn inner(self) -> T {
        self.0
    }
}

macro_rules! wrapped_string {
    ($ty:ident) => {
        #[derive(Serialize, Debug)]
        pub struct $ty(pub Arc<str>);

        impl Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<T: Into<Arc<str>>> From<T> for $ty {
            fn from(val: T) -> Self {
                Self(val.into())
            }
        }
    };
}

wrapped_string!(Reason);
wrapped_string!(Field);

/// validatoin error
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ValidationError {
    /// a single type is invalid (e.g [`NonZeroI32`] is 0, email is invalid, etc.)
    Single(Reason),
    /// a struct/document of validated types is invalid for one or more reasons
    Composite(Vec<ErroredField>),
}

#[derive(Debug, Serialize)]
pub struct ErroredField {
    pub field: Field,
    pub error: ValidationError,
}

#[diagnostic::on_unimplemented(
    note = "all document fields are validated by default",
    note = "if validation isn't necesarry, use #[validate(skip)]"
)]
#[trait_variant::make(Send + Sized)]
pub trait Validate {
    /// Validates the thing.
    ///
    /// # Errors
    ///
    /// This function will return an error if validation fails.
    async fn validate<DB: DatabaseConnection + ContentActions<D> + Sync, D: Document + Sync>(
        &self,
        ctx: ValidationContext<'_, DB, D>,
    ) -> Result<(), ValidationError>;
}

impl<T: Validate + Sync> Validate for Option<T> {
    async fn validate<DB: DatabaseConnection + ContentActions<D> + Sync, D: Document + Sync>(
        &self,
        ctx: ValidationContext<'_, DB, D>,
    ) -> Result<(), ValidationError> {
        match self.as_ref() {
            Some(inner) => inner.validate(ctx).await,
            None => Ok(()),
        }
    }
}

macro_rules! validator {
    ($ty:ty, $inner:ty, $expr:block, $v:ident) => {
        impl crate::editor_field::ToEditorField for $ty {
            fn to_editor_field(
                default: Option<impl Into<$ty>>,
                name: &'static str,
                title: &'static str,
                placeholder: Option<&'static str>,
                validator: Option<&'static str>,
                component_key: Option<&'static str>,
            ) -> crate::EditorField
            where
                Self: std::marker::Sized,
            {
                <$inner>::to_editor_field(
                    default.map(|v| v.into().0),
                    name,
                    title,
                    placeholder,
                    validator,
                    component_key,
                )
            }
        }

        impl From<$ty> for $inner {
            fn from(val: $ty) -> Self {
                val.0
            }
        }

        impl Validate for $ty {
            async fn validate<DB: DatabaseConnection + ContentActions<D> + Sync, D: Document>(
                &self,
                _ctx: ValidationContext<'_, DB, D>,
            ) -> Result<(), ValidationError> {
                let $v = self;
                $expr
            }
        }
    };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NonZeroI32(pub i32);

validator! {NonZeroI32, i32, {
    match v.0 {
        0 => Err(ValidationError::Single("value must not be zero".into())),
        _ => Ok(()),
    }
}, v}
