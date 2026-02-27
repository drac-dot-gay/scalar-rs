use std::{borrow::Cow, fmt::Debug, ops::Deref, sync::Arc};

#[cfg(feature = "oidc")]
use openidconnect::{
    AdditionalClaims, EndUserEmail, EndUserPictureUrl, EndUserUsername, GenderClaim, IdTokenClaims,
    SubjectIdentifier,
};
use scalar_cms::{
    db::{Authenticated, AuthenticationError, Credentials, DatabaseFactory, User},
    expr::Expression,
    validations::Valid,
    DateTime, Document, Item, Utc,
};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use surrealdb::{
    opt::{
        auth::{Record, Root},
        IntoEndpoint,
    },
    types::{AuthError, ErrorDetails, NotAllowedError, RecordId, RecordIdKey, SurrealValue, Table},
    Connection, Error, Surreal,
};

use crate::serde_wrapper::Wrapper;

mod serde_wrapper;

#[derive(SurrealValue)]
#[surreal(crate = "surrealdb::types")]
struct SurrealUser {
    email: String,
    name: String,
    profile_picture_url: String,
    admin: bool,
}

impl From<SurrealUser> for User {
    fn from(value: SurrealUser) -> Self {
        Self::new(
            value.email,
            value.name,
            value.profile_picture_url,
            value.admin,
        )
    }
}

#[derive(SurrealValue)]
#[surreal(crate = "surrealdb::types")]
pub struct MetaTable {
    pub id: RecordId,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub draft: Option<RecordId>,
    pub published: Option<RecordId>,
}

#[derive(SurrealValue)]
#[surreal(crate = "surrealdb::types")]
pub struct DraftTable {
    pub id: RecordId,
    pub inner: serde_json::Value,
}

#[derive(SurrealValue)]
#[surreal(crate = "surrealdb::types")]
pub struct PublishedTable {
    pub id: RecordId,
    pub inner: serde_json::Value,
    pub published_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SurrealConnection<C: Connection + Debug> {
    namespace: String,
    db: String,
    inner: Surreal<C>,
}

impl<C: Connection + Debug> SurrealConnection<C> {
    #[must_use]
    pub fn new(namespace: String, db: String, inner: Surreal<C>) -> Self {
        Self {
            namespace,
            db,
            inner,
        }
    }
}

impl<C: Connection + Debug> Deref for SurrealConnection<C> {
    type Target = Surreal<C>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(SurrealValue, Debug)]
#[surreal(crate = "surrealdb::types")]
pub struct SurrealItem<'a, D: Serialize + DeserializeOwned> {
    pub id: RecordId,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub inner: Wrapper<'a, D>,
}

impl<D: Serialize + DeserializeOwned> From<SurrealItem<'_, D>> for Item<D> {
    fn from(item: SurrealItem<D>) -> Self {
        let RecordIdKey::String(id) = item.id.key else {
            panic!("key types MUST be strings")
        };
        Self {
            id,
            created_at: item.created_at,
            modified_at: item.modified_at,
            published_at: item.published_at,
            inner: item.inner.0,
        }
    }
}

impl<D: Debug + Document + Serialize + DeserializeOwned> From<Item<D>> for SurrealItem<'_, D> {
    fn from(item: Item<D>) -> Self {
        Self {
            id: RecordId {
                table: Table::new(D::IDENTIFIER),
                key: item.id.into(),
            },
            created_at: item.created_at,
            modified_at: item.modified_at,
            published_at: item.published_at,
            inner: Wrapper::new(item.inner),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SurrealStore<C: Connection> {
    namespace: String,
    db: String,
    inner_instance: Surreal<C>,
}

impl<C: Connection> SurrealStore<C> {
    pub async fn new<P>(
        address: impl IntoEndpoint<P, Client = C>,
        namespace: String,
        db: String,
    ) -> Result<Self, surrealdb::Error> {
        Ok(Self {
            namespace,
            db,
            inner_instance: Surreal::new(address).await?,
        })
    }
}

impl<C: Connection + Clone + Debug> DatabaseFactory for SurrealStore<C> {
    type Error = surrealdb::Error;

    type Connection = SurrealConnection<C>;

    #[tracing::instrument(level = "debug", err)]
    async fn init(&self) -> Result<Self::Connection, Self::Error> {
        let inner = self.inner_instance.clone();

        inner.use_ns(&self.namespace).await?;
        inner.use_db(&self.db).await?;

        Ok(SurrealConnection {
            namespace: self.namespace.clone(),
            db: self.namespace.clone(),
            inner,
        })
    }

    #[tracing::instrument(level = "debug", err)]
    async fn init_system(&self) -> Result<Self::Connection, Self::Error> {
        let inner = self.inner_instance.clone();

        inner.use_ns(&self.namespace).await?;
        inner.use_db(&self.db).await?;

        inner
            .signin(Root {
                username: "root".into(),
                password: "root".into(),
            })
            .await?;

        Ok(SurrealConnection {
            namespace: self.namespace.clone(),
            db: self.namespace.clone(),
            inner,
        })
    }
}

impl<C: Connection + Debug> scalar_cms::DatabaseConnection for SurrealConnection<C> {
    type Error = surrealdb::Error;

    #[tracing::instrument(level = "debug", skip(jwt))]
    async fn authenticate(&self, jwt: &str) -> Result<User, AuthenticationError<Self::Error>> {
        self.inner
            .authenticate(jwt)
            .await
            .map_err(|e| match e.details() {
                ErrorDetails::Validation(_) => {
                    let e: Box<dyn std::error::Error> = Box::new(e);
                    tracing::error!(e, "query error");
                    AuthenticationError::BadToken
                }
                ErrorDetails::NotAllowed(Some(NotAllowedError::Auth(
                    AuthError::InvalidAuth | AuthError::TokenExpired | AuthError::SessionExpired,
                ))) => AuthenticationError::BadToken,
                ErrorDetails::Internal if e.message() == "InvalidToken" => {
                    AuthenticationError::BadToken
                }
                _ => e.into(),
            })?;

        let user: Option<SurrealUser> = self
            .query("SELECT *, IF pfp_url = NONE {string::concat(\"https://gravatar.com/avatar/\", crypto::sha256(email))} ELSE {pfp_url} as profile_picture_url OMIT id, password FROM $auth")
            .await?
            .take(0)?;

        Ok(user
            .expect("user should be authenticated when this is called")
            .into())
    }

    #[tracing::instrument(level = "debug")]
    async fn signin(
        &self,
        credentials: Credentials,
    ) -> Result<String, AuthenticationError<Self::Error>> {
        let result = self
            .inner
            .signin(Record {
                namespace: self.namespace.clone(),
                database: self.db.clone(),
                access: "sc__editor".into(),
                params: Wrapper::new(credentials),
            })
            .await
            .map_err(|e| match e.details() {
                ErrorDetails::Validation(_) => {
                    let e: Box<dyn std::error::Error> = Box::new(e);
                    tracing::error!(e, "query error");
                    AuthenticationError::BadCredentials
                }
                ErrorDetails::NotAllowed(Some(NotAllowedError::Auth(AuthError::InvalidAuth))) => {
                    AuthenticationError::BadCredentials
                }
                _ => e.into(),
            })?;

        Ok(result.access.into_insecure_token())
    }

    #[tracing::instrument(level = "debug")]
    #[cfg(feature = "oidc")]
    async fn signin_oidc<AC: AdditionalClaims + Send + Sync, GC: GenderClaim + Send + Sync>(
        &self,
        user_info: &IdTokenClaims<AC, GC>,
    ) -> Result<String, AuthenticationError<Self::Error>> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct OidcClaim<'a> {
            subject: Wrapper<'a, SubjectIdentifier>,
            username: Wrapper<'a, EndUserUsername>,
            email: Wrapper<'a, EndUserEmail>,
            pfp_url: Option<Wrapper<'a, EndUserPictureUrl>>,
        }

        let result = self
            .inner
            .signin(Record {
                namespace: self.namespace.clone(),
                database: self.db.clone(),
                access: "sc__editor".into(),
                params: OidcClaim {
                    subject: Wrapper::new(user_info.subject().clone()),
                    username: Wrapper::new(user_info.preferred_username().unwrap().clone()),
                    email: Wrapper::new(user_info.email().unwrap().clone()),
                    pfp_url: user_info
                        .picture()
                        .and_then(|v| v.get(None).cloned())
                        .map(Wrapper::new),
                },
            })
            .await
            .map_err(|e| match e.details() {
                ErrorDetails::Validation(_) => {
                    let e: Box<dyn std::error::Error> = Box::new(e);
                    tracing::error!(e, "query error");
                    AuthenticationError::BadCredentials
                }
                ErrorDetails::NotAllowed(Some(NotAllowedError::Auth(AuthError::InvalidAuth))) => {
                    AuthenticationError::BadCredentials
                }
                _ => e.into(),
            })?;

        Ok(result.access.into_insecure_token())
    }

    #[tracing::instrument(level = "debug", err, skip(conn))]
    async fn draft<D: Document + Send>(
        conn: &Authenticated<Self>,
        id: &str,
        data: serde_json::Value,
    ) -> Result<Item<serde_json::Value>, Self::Error> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct Bindings {
            doc: &'static str,
            id: String,
            inner: serde_json::Value,
        }

        let transaction = Surreal::clone(conn.inner()).begin().await?;
        let mut result = transaction
            .query(
                "
            LET $draft_id = type::thing(string::concat($doc, '_draft'), $id);
            LET $meta_id = type::thing(string::concat($doc, '_meta'), $id);
            UPSERT $draft_id SET inner = $inner;
            UPSERT $meta_id SET draft = $draft_id, modified_at = time::now();
            SELECT
                id,
                created_at,
                modified_at,
                IF draft IS NOT NONE THEN draft.inner ELSE published.inner END AS inner,
                published.published_at AS published_at
            FROM $meta_id
            FETCH draft, published;
            ",
            )
            .bind(Bindings {
                doc: D::IDENTIFIER.into(),
                id: id.into(),
                inner: data,
            })
            .await?
            .check()?;

        transaction.commit().await?;

        let thingy: Option<SurrealItem<serde_json::Value>> =
            result.take(4).expect("this should always succeed");

        Ok(thingy
            .expect("this option should always return something")
            .into())
    }

    #[tracing::instrument(level = "debug", err, skip(conn))]
    async fn delete_draft<D: Document + Send + DeserializeOwned>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Item<serde_json::Value>, Self::Error> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct Bindings {
            doc: &'static str,
            id: String,
        }

        //TODO: VERY BAD!!!!
        let pre_delete = conn.inner().get_by_id::<D>(id).await?.unwrap();

        let transaction = Surreal::clone(conn.inner()).begin().await?;

        transaction
            .query(
                "LET $draft_id = type::thing(string::concat($doc, '_draft'), $id);
            LET $meta_id = type::thing(string::concat($doc, '_meta'), $id);
            DELETE $draft_id;
            DELETE $meta_id WHERE published IS NONE;",
            )
            .bind(Bindings {
                doc: D::IDENTIFIER,
                id: id.to_owned().into(),
            })
            .await?;

        Ok(pre_delete)
    }

    #[tracing::instrument(level = "debug", skip(conn))]
    async fn publish<D: Document + Send + Sync + Serialize + DeserializeOwned + 'static>(
        conn: &Authenticated<Self>,
        id: &str,
        publish_at: Option<DateTime<Utc>>,
        data: Valid<D>,
    ) -> Result<Item<D>, Self::Error> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct Bindings {
            doc: &'static str,
            id: String,
            publish_at: Option<DateTime<Utc>>,
            inner: serde_json::Value,
        }

        let data = data.inner();

        let transaction = Surreal::clone(conn.inner()).begin().await?;
        let mut result = transaction
            .query("LET $published_id = type::thing($doc, $id);
            LET $draft_id = type::thing(string::concat($doc, '_draft'), $id);
            LET $meta_id = type::thing(string::concat($doc, '_meta'), $id);
            UPSERT $published_id SET inner = $inner, published_at = IF $publish_at IS NOT NONE { <datetime>$publish_at } ELSE { NONE };
            UPSERT $meta_id SET published = $published_id, modified_at = time::now(), draft = NONE;
            DELETE $draft_id;
            SELECT
                id,
                created_at,
                modified_at,
                IF draft IS NOT NONE THEN draft.inner ELSE published.inner END AS inner,
                published.published_at AS published_at
            FROM $meta_id
            FETCH draft, published;",
            )
            .bind(Bindings {
                doc: D::IDENTIFIER.into(),
                id: id.into(),
                publish_at,
                inner: serde_json::to_value(&data).expect("whuh")
            }).await?.check()?;

        let thingy: Option<SurrealItem<D>> = result.take(6).expect("this should always succeed");

        Ok(thingy
            .expect("this option should always return something")
            .into())
    }

    #[tracing::instrument(level = "debug", skip(conn))]
    async fn unpublish<D: Document + Send + Serialize + DeserializeOwned + 'static>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Option<D>, Self::Error> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct Bindings {
            doc: &'static str,
            id: String,
        }
        let transaction = Surreal::clone(conn.inner()).begin().await?;
        let mut result = transaction
            .query(
                "LET $meta_id = type::thing(string::concat($doc, '_meta'), $id);
            LET $draft_id = type::thing(string::concat($doc, '_draft'), $id);
            LET $published_id = type::thing($doc, $id);
            UPSERT $draft_id SET inner = (SELECT VALUE inner FROM ONLY $published_id);
            UPDATE $meta_id SET draft = $draft_id, published = NONE, modified_at = time::now();
            DELETE $published_id RETURN BEFORE;",
            )
            .bind(Bindings {
                doc: D::IDENTIFIER,
                id: id.into(),
            })
            .await?
            .check()?;

        transaction.commit().await?;
        result
            .take::<Option<Wrapper<'_, D>>>(6)
            .map(|v| v.map(|v| v.0))
    }

    #[tracing::instrument(level = "debug", err)]
    async fn put<D: Document + Serialize + DeserializeOwned + Send + Debug + 'static>(
        conn: &Authenticated<Self>,
        item: Item<D>,
    ) -> Result<Item<D>, Self::Error> {
        let updated_thingy: Option<SurrealItem<D>> = conn
            .inner()
            .upsert((D::IDENTIFIER, item.id.as_str()))
            .content(SurrealItem::<D>::from(item))
            .await?;

        Ok(updated_thingy
            .expect("surreal should return data regardless")
            .into())
    }

    #[tracing::instrument(level = "debug", err)]
    async fn delete<D: Document + Send + Debug>(
        conn: &Authenticated<Self>,
        id: &str,
    ) -> Result<Option<Item<serde_json::Value>>, Self::Error> {
        let transaction = Surreal::clone(conn.inner()).begin().await?;
        let mut result = transaction
            .query(
                "LET $published_id = type::thing($doc, $id);
                    LET $draft_id = type::thing(string::concat($doc, '_draft'), $id);
                    LET $meta_id = type::thing(string::concat($doc, '_meta'), $id);
                    DELETE $meta_id RETURN BEFORE;
                    DELETE $published_id RETURN BEFORE;
                    DELETE $draft_id RETURN BEFORE;",
            )
            .bind(("doc", D::IDENTIFIER))
            .bind(("id", id.to_owned()))
            .await?
            .check()?;
        transaction.commit().await?;

        let meta: Option<MetaTable> = result.take(3)?;
        let published: Option<PublishedTable> = result.take(4)?;
        let draft: Option<DraftTable> = result.take(5)?;

        Ok(meta.map(
            |MetaTable {
                 id,
                 created_at,
                 modified_at,
                 ..
             }| {
                let RecordIdKey::String(id) = id.key else {
                    panic!("record ids MUST be a string")
                };
                Item {
                    id,
                    created_at,
                    modified_at,
                    published_at: published.as_ref().map(|p| p.published_at),
                    inner: draft.map_or(published.map_or(Value::Null, |p| p.inner), |d| d.inner),
                }
            },
        ))
    }

    #[tracing::instrument(level = "debug", err)]
    async fn get_all<D: Document + DeserializeOwned + Send>(
        &self,
    ) -> Result<Vec<Item<serde_json::Value>>, Self::Error> {
        let result = self
            .query(
                "SELECT
                id,
                created_at,
                modified_at,
                IF draft IS NOT NONE THEN draft.inner ELSE published.inner END AS inner,
                published.published_at AS published_at
            FROM type::table(string::concat($doc, '_meta'))
            FETCH draft, published",
            )
            .bind(("doc", D::IDENTIFIER))
            .await?
            .check()?
            .take::<Vec<SurrealItem<serde_json::Value>>>(0)?;

        Ok(result.into_iter().map(Into::into).collect())
    }

    #[tracing::instrument(level = "debug", err)]
    async fn get_by_id<D: Document + DeserializeOwned + Send>(
        &self,
        id: &str,
    ) -> Result<Option<Item<serde_json::Value>>, Self::Error> {
        #[derive(SurrealValue)]
        #[surreal(crate = "surrealdb::types")]
        struct Bindings {
            doc: &'static str,
            id: String,
        }

        Ok(self
            .query(
                "LET $meta_id = type::thing(string::concat($doc, '_meta'), $id)
            SELECT
                id,
                created_at,
                modified_at,
                IF draft IS NOT NONE THEN draft.inner ELSE published.inner END AS inner,
                published.published_at AS published_at
            FROM $meta_id
            FETCH draft, published",
            )
            .bind(Bindings {
                doc: D::IDENTIFIER.into(),
                id: id.into(),
            })
            .await?
            .check()?
            .take::<Option<SurrealItem<serde_json::Value>>>(1)?
            .map(Into::into))
    }

    async fn vctx_all<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        let (bindings, where_clause) = compile_expression(field_name, expression);
        let mut resp = bindings
            .into_iter()
            .fold(
                self.query(format!(
                   "count(SELECT * FROM {0} WHERE record::id(id) != $excl_id AND ({where_clause}));
                    count(SELECT * FROM {0} WHERE record::id(id) != $excl_id)",
                    D::IDENTIFIER
                ))
                .bind(("excl_id", excl_id.to_string())),
                surrealdb::method::Query::bind,
            )
            .await?
            .check()?;
        let cond_count = resp.take::<Option<usize>>(0)?.expect("a number");
        let total = resp.take::<Option<usize>>(1)?.expect("a number");

        Ok(cond_count == total)
    }
    async fn vctx_none<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        let (bindings, where_clause) = compile_expression(field_name, expression);
        let mut resp = bindings
            .into_iter()
            .fold(
                self.query(format!(
                    "count(SELECT * FROM {} WHERE record::id(id) != $excl_id AND ({}))",
                    D::IDENTIFIER,
                    where_clause
                ))
                .bind(("excl_id", excl_id.to_string())),
                surrealdb::method::Query::bind,
            )
            .await?
            .check()?;
        let cond_count = resp.take::<Option<usize>>(0)?.expect("a number");

        Ok(cond_count == 0)
    }
    async fn vctx_any<D: Document>(
        &self,
        excl_id: &str,
        field_name: &str,
        expression: Expression,
    ) -> Result<bool, Self::Error> {
        let (bindings, where_clause) = compile_expression(field_name, expression);
        let mut resp = bindings
            .into_iter()
            .fold(
                self.query(format!(
                    "count(SELECT * FROM {} WHERE record::id(id) != $excl_id AND ({}))",
                    D::IDENTIFIER,
                    where_clause
                ))
                .bind(("excl_id", excl_id.to_string())),
                surrealdb::method::Query::bind,
            )
            .await?
            .check()?;
        let cond_count = resp.take::<Option<usize>>(0)?.expect("a number");

        Ok(cond_count > 0)
    }
}

fn compile_expression(
    field_name: &str,
    expression: Expression,
) -> (Vec<(String, serde_json::Value)>, String) {
    let mut bindings = Vec::new();
    let where_clause = match expression {
        Expression::Equals { lhs, rhs } => format!(
            "{} = {}",
            resolve_value(&mut bindings, field_name, lhs),
            resolve_value(&mut bindings, field_name, rhs)
        ),
        Expression::NotEquals { lhs, rhs } => format!(
            "{} != {}",
            resolve_value(&mut bindings, field_name, lhs),
            resolve_value(&mut bindings, field_name, rhs)
        ),
        Expression::And { lhs, rhs } => {
            let (left_bindings, left_inner) = compile_expression(field_name, *lhs);
            bindings.extend(left_bindings);
            let (right_bindings, right_inner) = compile_expression(field_name, *rhs);
            bindings.extend(right_bindings);
            format!("({left_inner} AND {right_inner})")
        }
        Expression::Or { lhs, rhs } => {
            let (left_bindings, left_inner) = compile_expression(field_name, *lhs);
            bindings.extend(left_bindings);
            let (right_bindings, right_inner) = compile_expression(field_name, *rhs);
            bindings.extend(right_bindings);
            format!("({left_inner} OR {right_inner})")
        }
        _ => panic!("missed expr"),
    };
    (bindings, where_clause)
}

fn resolve_value(
    bindings: &mut Vec<(String, serde_json::Value)>,
    field_name: &str,
    value: scalar_cms::expr::Value,
) -> String {
    match value {
        scalar_cms::expr::Value::CurrentField => format!("inner.{field_name}"),
        // all fields are on the inner object, so we gotta adapt
        scalar_cms::expr::Value::Ident(ident) => format!("inner.{ident}"),
        scalar_cms::expr::Value::Value(value) => {
            let binding_name = format!("b{}", bindings.len());
            bindings.push((binding_name.clone(), value));
            format!("${binding_name}")
        }
    }
}

impl<C: Connection + Debug> SurrealConnection<C> {
    /// Initializes data for a given doc. Most of the time,
    /// this should be a completely safe operation.
    ///
    /// # Panics
    ///
    /// Panics if initialization fails.
    #[tracing::instrument(level = "info", fields(doc = D::IDENTIFIER))]
    pub async fn init_doc<D: Document>(&self) {
        tracing::info!("initializing database table");
        let published_table = D::IDENTIFIER;
        let draft_table = format!("{published_table}_draft");
        let meta_table = format!("{published_table}_meta");
        let transaction = self
            .inner
            .clone()
            .begin()
            .await
            .expect("couldn't begin transaction");
        transaction
            .query(format!("DEFINE TABLE OVERWRITE {published_table} SCHEMAFULL PERMISSIONS FOR select WHERE true FOR create, update, delete WHERE $auth.id IS NOT NONE;
            DEFINE FIELD OVERWRITE published_at ON {published_table} TYPE datetime DEFAULT time::now();
            DEFINE FIELD IF NOT EXISTS inner ON {published_table} TYPE object FLEXIBLE;
            UPDATE {published_table} SET published_at = time::now() WHERE published_at = NONE;
            DEFINE TABLE OVERWRITE {draft_table} SCHEMAFULL PERMISSIONS FOR select, create, update, delete WHERE $auth.id IS NOT NONE;
            DEFINE FIELD IF NOT EXISTS inner ON {draft_table} TYPE object FLEXIBLE;
            DEFINE TABLE OVERWRITE {meta_table} SCHEMAFULL PERMISSIONS FOR select, create, update, delete WHERE $auth.id IS NOT NONE;
            DEFINE FIELD IF NOT EXISTS created_at ON {meta_table} TYPE datetime DEFAULT time::now();
            DEFINE FIELD IF NOT EXISTS modified_at ON {meta_table} TYPE datetime;
            DEFINE FIELD IF NOT EXISTS draft ON {meta_table} TYPE option<record<{draft_table}>>;
            DEFINE FIELD IF NOT EXISTS published ON {meta_table} TYPE option<record<{published_table}>>;
            DEFINE FUNCTION OVERWRITE fn::{published_table}_public() {{ RETURN (array::map(SELECT inner FROM {published_table} WHERE published_at < time::now(), |$v| $v.inner)) }};"))
            .await
            .unwrap_or_else(|e| panic!("setting up tables for {published_table} failed: {e}"))
            .check()
            .unwrap_or_else(|e| panic!("setting up tables for {published_table} failed: {e}"));
        transaction
            .commit()
            .await
            .unwrap_or_else(|e| panic!("setting up tables for {published_table} failed: {e}"));
        tracing::info!("done");
    }

    /// Initializies auth for this database. This is usually an operation that's safe to autoamtically
    /// run at startup.
    ///
    /// # Panics
    ///
    /// Panics if initialization fails.
    pub async fn init_auth(&self) {
        tracing::info!("setting up auth..");
        let transaction = self
            .inner
            .clone()
            .begin()
            .await
            .expect("couldn't begin transaction");
        transaction
            .query("DEFINE TABLE OVERWRITE sc__editor SCHEMAFULL PERMISSIONS FOR select, update, delete WHERE id = $auth.id OR $auth.admin = true FOR create WHERE $auth.admin = true;
            DEFINE FIELD IF NOT EXISTS name ON sc__editor TYPE string;
            DEFINE FIELD IF NOT EXISTS email ON sc__editor TYPE string ASSERT string::is_email($value);
            DEFINE FIELD IF NOT EXISTS password ON sc__editor TYPE option<string>;
            DEFINE FIELD IF NOT EXISTS admin ON sc__editor TYPE bool;
            DEFINE FIELD IF NOT EXISTS oidc_subject ON sc__editor TYPE option<string>;
            DEFINE FIELD IF NOT EXISTS pfp_url ON sc__editor TYPE option<string>;
            DEFINE INDEX IF NOT EXISTS email ON sc__editor FIELDS email UNIQUE;
            DEFINE INDEX IF NOT EXISTS oidc_subject ON sc__editor FIELDS oidc_subject UNIQUE;
            DEFINE ACCESS OVERWRITE sc__editor ON DATABASE TYPE RECORD SIGNIN (RETURN IF $subject != NONE
	{

		LET $intermediate_query = (SELECT * FROM sc__editor WHERE oidc_subject = $subject);

		IF $intermediate_query = []
			{
				RETURN (INSERT INTO sc__editor {
					admin: true,
					email: $email,
					name: $username,
					oidc_subject: $subject,
					pfp_url: $pfp_url
				});
			}
		ELSE
			{
				RETURN $intermediate_query;
			}
		;

            }
            ELSE
	{
		RETURN (SELECT * FROM sc__editor WHERE email = $email AND crypto::argon2::compare(password, $password));
	}
            )").await.expect("auth setup failed").check().expect("auth setup failed");
        transaction.commit().await.expect("auth setup failed");
        tracing::info!("done");
    }
}

// TODO: unit tests

#[macro_export]
macro_rules! doc_init {
    ($db:ident, $doc:ty) => {
        $db.init_doc::<$doc>().await;
    };
    ($db:ident, $doc:ty, $($docs:ty),+) => {
        ::scalar_surreal::doc_init!($db, $doc);
        ::scalar_surreal::doc_init!($db, $($docs),+);
    }
}

#[macro_export]
macro_rules! init {
    ($db:ident, $($docs:ty),+) => {
        $db.init_auth().await;
        ::scalar_surreal::doc_init!($db, $($docs),+);
    };
}
