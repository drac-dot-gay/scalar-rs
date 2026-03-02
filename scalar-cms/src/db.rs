use std::fmt::Debug;
use std::marker::PhantomData;
use std::{error::Error, sync::Arc};

use chrono::{DateTime, Utc};
use scalar_expr::Expression;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{validations::Valid, Document, Item};

#[derive(Error, Debug)]
pub enum AuthenticationError<DE: Error> {
    #[error("Invalid token provided")]
    BadToken,
    #[error("Invalid credentials provided")]
    BadCredentials,
    #[error("Database error: {0}")]
    DatabaseError(#[from] DE),
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    email: String,
    password: String,
}

impl Credentials {
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("email", &self.email)
            .field("password", &"<REDACTED>")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    email: Arc<str>,
    name: Arc<str>,
    profile_picture_url: Arc<str>,
    admin: bool,
}

impl User {
    pub fn new(
        email: impl Into<String>,
        name: impl Into<String>,
        profile_picture_url: impl Into<String>,
        admin: bool,
    ) -> Self {
        Self {
            email: email.into().into(),
            name: name.into().into(),
            profile_picture_url: profile_picture_url.into().into(),
            admin,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn profile_picture_url(&self) -> &str {
        &self.profile_picture_url
    }

    #[must_use]
    pub fn admin(&self) -> bool {
        self.admin
    }
}

#[trait_variant::make(Send + Sized)]
pub trait DatabaseFactory {
    type Error: Error;
    type Connection: DatabaseConnection + Sync;

    async fn init(&self) -> Result<Self::Connection, Self::Error>;
    async fn init_system(&self) -> Result<Self::Connection, Self::Error>;
}

pub struct ValidationContext<'a, DB: DatabaseConnection, D: Document> {
    conn: &'a DB,
    excluded_id: &'a str,
    field_name: &'a str,
    phantom: PhantomData<D>,
}

impl<DB: DatabaseConnection, D: Document> Clone for ValidationContext<'_, DB, D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<DB: DatabaseConnection, D: Document> Copy for ValidationContext<'_, DB, D> {}

impl<'a, 'b, DB: DatabaseConnection + ContentActions<D>, D: Document> ValidationContext<'a, DB, D>
where
    'b: 'a,
    'a: 'b,
{
    pub fn new(conn: &'a DB, excluded_id: &'a str) -> Self {
        ValidationContext {
            conn,
            excluded_id,
            field_name: "",
            phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn for_field(&self, field_name: &'b str) -> ValidationContext<'b, DB, D> {
        Self {
            conn: self.conn,
            excluded_id: self.excluded_id,
            field_name,
            phantom: PhantomData,
        }
    }

    pub async fn all(&self, expr: Expression) -> Result<bool, DB::Error> {
        self.conn
            .vctx_all(self.excluded_id, self.field_name, expr)
            .await
    }
    pub async fn none(&self, expr: Expression) -> Result<bool, DB::Error> {
        self.conn
            .vctx_none(self.excluded_id, self.field_name, expr)
            .await
    }
    pub async fn any(&self, expr: Expression) -> Result<bool, DB::Error> {
        self.conn
            .vctx_any(self.excluded_id, self.field_name, expr)
            .await
    }
}

#[derive(Debug)]
pub struct Authenticated<DB: DatabaseConnection> {
    conn: DB,
    user: User,
}

impl<DB: DatabaseConnection> Authenticated<DB> {
    /// Creates an authenticated DB connection.
    ///
    /// # Errors
    ///
    /// This function will return an error if authentication fails.
    pub async fn authenticate(
        conn: DB,
        token: &str,
    ) -> Result<Self, AuthenticationError<DB::Error>> {
        Ok(Self {
            user: conn.authenticate(token).await?,
            conn,
        })
    }

    pub fn me(&self) -> User {
        self.user.clone()
    }

    pub fn inner(&self) -> &DB {
        &self.conn
    }
}

#[trait_variant::make(Send + Sized)]
pub trait DatabaseConnection {
    type Error: Error;

    async fn authenticate(&self, jwt: &str) -> Result<User, AuthenticationError<Self::Error>>;
    async fn signin(
        &self,
        credentials: Credentials,
    ) -> Result<String, AuthenticationError<Self::Error>>;
    #[cfg(feature = "oidc")]
    async fn signin_oidc<
        AC: openidconnect::AdditionalClaims + Send + Sync,
        GC: openidconnect::GenderClaim + Send + Sync,
    >(
        &self,
        user_info: &openidconnect::IdTokenClaims<AC, GC>,
    ) -> Result<String, AuthenticationError<Self::Error>>;
}

#[trait_variant::make(Send + Sized)]
pub trait ContentActions<D: Document>: DatabaseConnection {
    async fn draft(
        conn: &Authenticated<Self>,
        id: &str,
        data: serde_json::Value,
    ) -> Result<Item<serde_json::Value>, Self::Error>;
    async fn delete_draft(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Item<serde_json::Value>, Self::Error>;

    async fn publish(
        conn: &Authenticated<Self>,
        id: &str,
        publish_at: Option<DateTime<Utc>>,
        data: Valid<D>,
    ) -> Result<Item<D>, Self::Error>;
    async fn unpublish(conn: &Authenticated<Self>, id: &str) -> Result<Option<D>, Self::Error>;

    async fn put(conn: &Authenticated<Self>, item: Item<D>) -> Result<Item<D>, Self::Error>;
    async fn delete(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Option<Item<serde_json::Value>>, Self::Error>;
    async fn get_all(&self) -> Result<Vec<Item<serde_json::Value>>, Self::Error>;
    async fn get_by_id(&self, id: &str) -> Result<Option<Item<serde_json::Value>>, Self::Error>;

    async fn vctx_all(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error>;
    async fn vctx_none(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error>;
    async fn vctx_any(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error>;
}
