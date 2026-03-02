use std::fmt::Debug;

pub use scalar_derive::{doc_enum, Document, EditorField, Enum};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub use chrono::{DateTime, NaiveDate, Utc};
pub use nanoid::nanoid;
#[cfg(feature = "rgb")]
pub use rgb::RGBA8;
#[cfg(feature = "url")]
pub use url::Url;

pub use db::DatabaseConnection;

pub mod db;
pub mod editor_field;
pub mod editor_type;
pub mod types;
pub mod validations;

pub use serde_json;

pub use editor_field::EditorField;
pub use editor_type::EditorType;
use validations::Validate;

pub use scalar_expr as expr;

use crate::db::{ContentActions, ValidationContext};

#[derive(Serialize, TS)]
#[ts(export)]
pub struct Schema {
    identifier: &'static str,
    title: &'static str,
    singleton: bool,
    label: Option<&'static str>,
    sub_label: Option<&'static str>,
    fields: &'static [EditorField],
}

#[derive(Serialize, TS)]
#[ts(export)]
pub struct DocInfo {
    pub identifier: &'static str,
    pub title: &'static str,
}

pub trait Document: Validate + Debug {
    const IDENTIFIER: &'static str;
    const TITLE: &'static str;
    const LABEL: Option<&'static str>;
    const SUB_LABEL: Option<&'static str>;
    const SINGLETON: bool;

    fn fields() -> &'static [EditorField];
    #[must_use]
    fn schema() -> Schema {
        Schema {
            identifier: Self::IDENTIFIER,
            title: Self::TITLE,
            label: Self::LABEL,
            sub_label: Self::SUB_LABEL,
            singleton: Self::SINGLETON,
            fields: Self::fields(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, TS)]
#[ts(export, concrete(D = String))]
pub struct Item<D> {
    #[serde(rename = "__sc_id")]
    pub id: String,
    #[serde(rename = "__sc_created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "__sc_modified_at")]
    pub modified_at: DateTime<Utc>,
    #[serde(rename = "__sc_published_at")]
    pub published_at: Option<DateTime<Utc>>,
    #[serde(rename = "content")]
    #[ts(type = "any")]
    pub inner: D,
}

impl<D: Document + Send + Sync> Validate for Item<D> {
    async fn validate<DB: DatabaseConnection + ContentActions<DD> + Sync, DD: Document + Sync>(
        &self,
        ctx: ValidationContext<'_, DB, DD>,
    ) -> Result<(), validations::ValidationError> {
        self.inner.validate(ctx).await
    }
}
