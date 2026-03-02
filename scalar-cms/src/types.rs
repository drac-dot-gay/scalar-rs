use std::ops::{Deref, DerefMut};

use scalar_expr::expression;
use serde::{Deserialize, Serialize};

use crate::{
    db::{ContentActions, ValidationContext},
    editor_field::ToEditorField,
    validations::{Validate, ValidationError},
    DatabaseConnection, Document,
};

macro_rules! deref {
    ($ty:ty > $target:ty) => {
        impl Deref for $ty {
            type Target = $target;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl DerefMut for $ty {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

    (generic $ty:ident > $target:ty) => {
        impl<T: ToEditorField> Deref for $ty<T> {
            type Target = $target;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl<T: ToEditorField> DerefMut for $ty<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MultiLine(pub String);

deref!(MultiLine > str);

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct Markdown(pub String);

deref!(Markdown > str);

#[derive(Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct Slug(pub String);

deref!(Slug > str);

impl Validate for Slug {
    async fn validate<
        DB: DatabaseConnection + ContentActions<D> + Send + Sync,
        D: Document + Send + Sync,
    >(
        &self,
        ctx: ValidationContext<'_, DB, D>,
    ) -> Result<(), crate::validations::ValidationError> {
        self.0
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            .then_some(())
            .ok_or_else(|| {
                ValidationError::Single(
                    "slugs can only contain alphanumeic characters, -, and _.".into(),
                )
            })?;
        ctx.none(expression!($current == self.0))
            .await
            .unwrap()
            .then_some(())
            .ok_or_else(|| ValidationError::Single("slugs must be unique!".into()))
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(from = "Option<T>")]
pub struct Toggle<T: ToEditorField>(pub Option<T>);

impl<T: ToEditorField> From<Option<T>> for Toggle<T> {
    fn from(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<T: ToEditorField> Default for Toggle<T> {
    fn default() -> Self {
        Self(Option::default())
    }
}

deref!(generic Toggle > Option<T>);
