use std::{convert::Infallible, fmt::Debug};

use argon2::{Argon2, PasswordHash, PasswordVerifier, password_hash};
use openidconnect::{AdditionalClaims, GenderClaim, IdTokenClaims};
use rusty_paseto::{
    core::{Key, Local, PasetoSymmetricKey, V4},
    prelude::*,
};
use scalar_cms::{
    DatabaseConnection, DateTime, Document, Item, Utc,
    db::{Authenticated, AuthenticationError, Credentials, DatabaseFactory, User},
    expr::Expression,
    validations::Valid,
};
use sqlx::{Database, Pool};
use thiserror::Error;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub(crate) trait DatabaseInner {
    fn get_password_hash(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<Option<String>, sqlx::Error>> + Send;

    fn get_user(&self, email: &str) -> impl Future<Output = Result<User, sqlx::Error>> + Send;

    fn draft<D: Document>(
        &self,
        id: &str,
        data: serde_json::Value,
    ) -> impl Future<Output = Result<Item<serde_json::Value>, sqlx::Error>> + Send;

    fn get_all<D: Document>(
        &self,
    ) -> impl Future<Output = Result<Vec<Item<serde_json::Value>>, sqlx::Error>> + Send;

    fn get_by_id<D: Document>(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<Option<Item<serde_json::Value>>, sqlx::Error>> + Send;
}

#[derive(Debug)]
pub struct ConnectionFactory<DB: Database> {
    pool: Pool<DB>,
    paseto_key: Key<32>,
}

impl<DB: Database> Clone for ConnectionFactory<DB> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            paseto_key: self.paseto_key.clone(),
        }
    }
}

impl<DB: Database> ConnectionFactory<DB> {
    /// Creates a new `ConnectionFactory` with a random key for Paseto tokens.
    ///
    /// # Errors
    ///
    /// This function will return an error if ring's RNG fails for whatever reason.
    pub fn try_new_random(db: Pool<DB>) -> Result<Self, PasetoError> {
        Ok(Self {
            paseto_key: Key::try_new_random()?,
            pool: db,
        })
    }
}

impl<DB: Database> DatabaseFactory for ConnectionFactory<DB>
where
    Pool<DB>: DatabaseInner,
{
    type Error = Infallible;

    type Connection = Connection<DB>;

    async fn init(&self) -> Result<Self::Connection, Self::Error> {
        Ok(Connection {
            paseto_key: PasetoSymmetricKey::from(self.paseto_key.clone()),
            inner: self.pool.clone(),
        })
    }

    async fn init_system(&self) -> Result<Self::Connection, Self::Error> {
        Ok(Connection {
            paseto_key: PasetoSymmetricKey::from(self.paseto_key.clone()),
            inner: self.pool.clone(),
        })
    }
}

pub struct Connection<DB: Database> {
    paseto_key: PasetoSymmetricKey<V4, Local>,
    inner: Pool<DB>,
}

impl<DB: Database + Debug> Debug for Connection<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("paseto_key", &"<redacted>")
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("password error: {0}")]
    Password(#[from] password_hash::Error),
}

impl<DB: Database> DatabaseConnection for Connection<DB>
where
    Pool<DB>: DatabaseInner,
{
    type Error = Error;

    #[tracing::instrument(level = "debug", err)]
    async fn authenticate(&self, jwt: &str) -> Result<User, AuthenticationError<Self::Error>> {
        let claims = PasetoParser::<V4, Local>::default()
            .parse(jwt, &self.paseto_key)
            .map_err(|_| AuthenticationError::BadToken)?;

        serde_json::from_value(
            claims
                .get("user")
                .ok_or(AuthenticationError::BadToken)?
                .to_owned(),
        )
        .map_err(|_| AuthenticationError::BadToken)
    }

    #[tracing::instrument(level = "debug", err)]
    async fn signin(
        &self,
        credentials: Credentials,
    ) -> Result<String, AuthenticationError<Self::Error>> {
        let password_hash = self
            .inner
            .get_password_hash(credentials.email())
            .await
            .map_err(Error::from)?
            .ok_or(AuthenticationError::BadCredentials)?;

        let parsed_hash = PasswordHash::new(&password_hash).unwrap();
        Argon2::default()
            .verify_password(credentials.password().as_bytes(), &parsed_hash)
            .map_err(|e| match e {
                password_hash::Error::Password => AuthenticationError::BadCredentials,
                e => Error::from(e).into(),
            })?;

        let user = self
            .inner
            .get_user(credentials.email())
            .await
            .map_err(Error::from)?;

        let token = PasetoBuilder::<_, Local>::default()
            .set_claim(CustomClaim::try_from(("user", user)).unwrap())
            .build(&self.paseto_key)
            .unwrap();

        Ok(token)
    }

    #[tracing::instrument(level = "debug", err)]
    #[cfg(feature = "oidc")]
    async fn signin_oidc<AC: AdditionalClaims + Send + Sync, GC: GenderClaim + Send + Sync>(
        &self,
        claims: &IdTokenClaims<AC, GC>,
    ) -> Result<String, AuthenticationError<Self::Error>> {
        let user = User::new(
            claims.email().unwrap().to_string(),
            claims.given_name().unwrap().get(None).unwrap().to_string(),
            claims
                .picture()
                .and_then(|l| l.get(None).map(|u| u.as_str()))
                .unwrap_or_default(),
            true,
        );

        let token = PasetoBuilder::<_, Local>::default()
            .set_claim(CustomClaim::try_from(("user", user)).unwrap())
            .build(&self.paseto_key)
            .unwrap();

        Ok(token)
    }

    #[tracing::instrument(level = "debug", err)]
    async fn draft<D: Document + Send>(
        conn: &Authenticated<Self>,
        id: &str,
        data: serde_json::Value,
    ) -> Result<Item<serde_json::Value>, Self::Error> {
        Ok(conn.inner().inner.draft::<D>(id, data).await?)
    }

    #[tracing::instrument(level = "debug", err)]
    async fn delete_draft<D: Document + Send>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Item<serde_json::Value>, Self::Error> {
        todo!();
        // #[derive(Serialize)]
        // struct Bindings<'a> {
        //     doc: Cow<'a, str>,
        //     id: Cow<'a, str>,
        // }

        // //TODO: VERY BAD!!!!
        // let pre_delete = self.get_by_id::<D>(id).await?.unwrap();

        // let _ = self
        //     .query("LET $draft_id = type::thing(string::concat($doc, '_draft'), $id)")
        //     .query("LET $meta_id = type::thing(string::concat($doc, '_meta'), $id)")
        //     .query("DELETE $draft_id")
        //     .query("DELETE $meta_id WHERE published IS NONE")
        //     .bind(Bindings {
        //         doc: D::identifier().into(),
        //         id: id.to_owned().into(),
        //     })
        //     .await?;

        // Ok(pre_delete)
    }

    async fn publish<D: Document + Send + 'static>(
        conn: &Authenticated<Self>,
        id: &str,
        publish_at: Option<DateTime<Utc>>,
        data: Valid<D>,
    ) -> Result<Item<D>, Self::Error> {
        todo!()
        // #[derive(Serialize)]
        // struct Bindings<'a, D> {
        //     doc: Cow<'a, str>,
        //     id: Cow<'a, str>,
        //     publish_at: Option<DateTime<Utc>>,
        //     inner: D,
        // }

        // let mut result = self
        //     .query("LET $published_id = type::thing($doc, $id)")
        //     .query("LET $draft_id = type::thing(string::concat($doc, '_draft'), $id)")
        //     .query("LET $meta_id = type::thing(string::concat($doc, '_meta'), $id)")
        //     .query("UPSERT $published_id SET inner = $inner, published_at = $published_at")
        //     .query("UPSERT $meta_id SET published = $published_id, modified_at = time::now(), draft = NONE")
        //     .query("DELETE $draft_id")
        //     .query(
        //         "SELECT
        //         id,
        //         created_at,
        //         modified_at,
        //         IF draft IS NOT NONE THEN draft.inner ELSE published.inner END AS inner,
        //         published.published_at AS published_at
        //     FROM $meta_id
        //     FETCH draft, published",
        //     ).bind(Bindings::<D> {
        //         doc: D::identifier().into(),
        //         id: id.to_owned().into(),
        //         publish_at,
        //         inner: data.inner()
        //     }).await?;

        // let thingy: Option<SurrealItem<D>> = result.take(6).expect("this should always succeed");

        // Ok(thingy
        //     .expect("this option should always return something")
        //     .into())
    }

    async fn unpublish<D: Document + Send + 'static>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Option<D>, Self::Error> {
        todo!()
    }

    #[tracing::instrument(level = "debug", err)]
    async fn put<D: Document + Send + Debug + 'static>(
        conn: &Authenticated<Self>,
        item: Item<D>,
    ) -> Result<Item<D>, Self::Error> {
        todo!()
        // let updated_thingy: Option<SurrealItem<D>> = self
        //     .upsert((D::identifier(), item.id.to_owned()))
        //     .content(SurrealItem::<D>::from(item))
        //     .await?;

        // Ok(updated_thingy
        //     .expect("surreal should return data regardless")
        //     .into())
    }

    #[tracing::instrument(level = "debug", err)]
    async fn delete<D: Document + Send + Debug>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Option<Item<serde_json::Value>>, Self::Error> {
        todo!()
    }

    #[tracing::instrument(level = "debug", err)]
    async fn get_all<D: Document + Send>(
        &self,
    ) -> Result<Vec<Item<serde_json::Value>>, Self::Error> {
        Ok(self.inner.get_all::<D>().await?)
    }

    #[tracing::instrument(level = "debug", err)]
    async fn get_by_id<D: Document + Send>(
        &self,
        id: &str,
    ) -> Result<Option<Item<serde_json::Value>>, Self::Error> {
        Ok(self.inner.get_by_id::<D>(id).await?)
    }

    async fn vctx_all<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
    async fn vctx_none<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
    async fn vctx_any<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}
