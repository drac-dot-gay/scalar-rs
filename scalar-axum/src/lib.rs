use std::error::Error;

use axum::{
    extract::{FromRef, FromRequestParts, Path, Query, State},
    http::{self, StatusCode},
    response::IntoResponse,
    Json, Router,
};
use scalar_cms::{
    db::{Authenticated, Credentials, DatabaseFactory, User, ValidationContext},
    validations::{Valid, ValidationError},
    DatabaseConnection, DateTime, Document, Item, Schema, Utc,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub mod expire_map;
#[cfg(feature = "img")]
pub mod img;
#[cfg(feature = "oidc")]
pub mod oidc;

pub struct ValidationFailiure(pub ValidationError);

impl IntoResponse for ValidationFailiure {
    fn into_response(self) -> axum::response::Response {
        let mut response = Json(self.0).into_response();
        *response.status_mut() = StatusCode::NOT_ACCEPTABLE;
        response
    }
}

#[cfg(feature = "img")]
#[doc(hidden)]
pub fn add_image_routes__<
    S: Clone + Send + Sync + 'static,
    F: DatabaseFactory + FromRef<S> + 'static,
>(
    router: Router<S>,
) -> Router<S>
where
    scalar_img::WrappedBucket: FromRef<S>,
{
    use axum::extract::DefaultBodyLimit;
    use img::{list_files, list_images, upload_file, upload_image};

    router
        .route(
            "/images/upload",
            axum::routing::put(upload_image::<F>).layer(DefaultBodyLimit::max(25_000_000)),
        )
        .route(
            "/files/upload",
            axum::routing::put(upload_file::<F>).layer(DefaultBodyLimit::disable()),
        )
        .route("/images/list", axum::routing::get(list_images::<F>))
        .route("/files/list", axum::routing::get(list_files::<F>))
}

#[cfg(not(feature = "img"))]
#[doc(hidden)]
pub fn add_image_routes__<
    S: Clone + Send + Sync + 'static,
    F: DatabaseFactory + FromRef<S> + 'static,
>(
    router: Router<S>,
) -> Router<S> {
    router
}

#[macro_export]
#[doc(hidden)]
macro_rules! crud_routes__ {
    ($router:ident, $db:ty, $doc:ty) => {
        let path = format!("/docs/{}", <$doc>::IDENTIFIER);
        let id_path = format!("{path}/{{id}}");
        let drafts_path = format!("{id_path}/drafts");
        $router = $router
            .route(&path, ::axum::routing::get(::scalar_axum::get_all_docs::<$doc, $db>))
            .route(&id_path, ::axum::routing::get(::scalar_axum::get_doc_by_id::<$doc, $db>))
            .route(&drafts_path, ::axum::routing::put(::scalar_axum::update_draft::<$doc, $db>))
            .route(&drafts_path, ::axum::routing::delete(::scalar_axum::delete_draft::<$doc, $db>))
            .route(&id_path, ::axum::routing::delete(::scalar_axum::delete_doc::<$doc, $db>))
            .route(&format!("{path}/schema"), ::axum::routing::get(::scalar_axum::get_schema::<$doc>));
    };

    ($router:ident, $db:ty, $($doc:ty),+) => {
        $(::scalar_axum::crud_routes__!($router, $db, $doc);)*
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! publish_routes__ {
    ($router:ident, $db:ty, $doc:ty) => {
        let path = format!("/docs/{}/{{id}}/publish", <$doc>::IDENTIFIER);
        $router = $router
            .route(&path, ::axum::routing::post(::scalar_axum::publish_doc::<$doc, $db>))
            .route(&path, ::axum::routing::delete(::scalar_axum::unpublish_doc::<$doc, $db>));
    };

    ($router:ident, $db:ty, $($doc:ty),+) => {
        $(::scalar_axum::publish_routes__!($router, $db, $doc);)*
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! validate_routes__ {
    ($db:ty, $router:ident, $doc:ty) => {
        $router = $router
            .route(&format!("/docs/{}/validate", <$doc>::IDENTIFIER), ::axum::routing::post(::scalar_axum::validate::<$db, $doc>));
    };

    ($db:ty, $router:ident, $($doc:ty),+) => {
        $(::scalar_axum::validate_routes__!($db, $router, $doc);)*
    };
}

#[macro_export]
#[cfg(feature = "oidc")]
macro_rules! generate_routes {
    ({ db: $db:ty }, [$($doc:ty),+]) => {
        {
            let mut router = ::axum::Router::new();
            ::scalar_axum::crud_routes__!(router, $db, $($doc),+);
            ::scalar_axum::publish_routes__!(router, $db, $($doc),+);
            async fn get_docs() -> ::axum::Json<Vec<::scalar_cms::DocInfo>> {
                ::axum::Json(vec![
                    $(::scalar_cms::DocInfo {
                        identifier: <$doc>::IDENTIFIER,
                        title: <$doc>::TITLE
                    }),+
                ])
            }
            router = router.route("/docs", ::axum::routing::get(get_docs));

            router = router.route("/me", ::axum::routing::get(::scalar_axum::me::<$db>));
            router = ::scalar_axum::add_image_routes__::<_, $db>(router);
            router = router.route("/signin", ::axum::routing::post(::scalar_axum::signin::<$db>));

            ::scalar_axum::validate_routes__!($db, router, $($doc),+);

            router
        }
    };

    ({ db: $db:ty, oidc: { state: $oidc:ty, response_type: $response_type:ty, oidc_only: $only:expr } }, [$($doc:ty),+]) => {
        {
            let mut router = ::scalar_axum::generate_routes!({db: $db}, [$($doc),+]);

            async fn is_auto() -> String {
                bool::to_string(&$only)
            }

            router = router.route("/signin/oidc", ::axum::routing::get(::scalar_axum::oidc::begin_oidc_auth::<_, _, _, _, _, _, _, _, _, _, _, _, _, _, $oidc, $response_type>));
            router = router.route("/signin/oidc/is_auto", ::axum::routing::get(is_auto));
            router = router.route("/signin/oidc/complete", ::axum::routing::get(::scalar_axum::oidc::complete_oidc_auth::<_, _, _, _, _, _, _, _, _, _, _, _, _, _, $oidc, $response_type, $db>));
            router
        }
    };
}

#[macro_export]
#[cfg(not(feature = "oidc"))]
macro_rules! generate_routes {
    ({ db: $db:ty }, [$($doc:ty),+]) => {
        {
            let mut router = ::axum::Router::new();
            ::scalar_axum::crud_routes__!(router, $db, $($doc),+);
            ::scalar_axum::publish_routes__!(router, $db, $($doc),+);
            async fn get_docs() -> ::axum::Json<Vec<::scalar_cms::DocInfo>> {
                ::axum::Json(vec![
                    $(::scalar_cms::DocInfo {
                        identifier: <$doc>::IDENTIFIER,
                        title: <$doc>::TITLE
                    }),+
                ])
            }
            router = router.route("/docs", ::axum::routing::get(get_docs));

            router = router.route("/me", ::axum::routing::get(::scalar_axum::me::<$db>));
            router = ::scalar_axum::add_image_routes__::<_, $db>(router);
            router = router.route("/signin", ::axum::routing::post(::scalar_axum::signin::<$db>));

            ::scalar_axum::validate_routes__!(router, $($doc),+);

            router
        }
    };
}

pub struct AuthenticatedConnection<F: DatabaseFactory>(Authenticated<F::Connection>);

impl<F: DatabaseFactory, S> FromRequestParts<S> for AuthenticatedConnection<F>
where
    F: FromRef<S>,
    S: Send + Sync,
    <F as scalar_cms::db::DatabaseFactory>::Error: 'static,
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let db_factory = F::from_ref(state);
        let auth_header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .map(|header| {
                header
                    .to_str()
                    .map(str::trim)
                    .map_err(|_| StatusCode::BAD_REQUEST)
            })
            .ok_or(StatusCode::UNAUTHORIZED)??;

        let connection = db_factory.init().await.map_err(|e| {
            tracing::error!(
                cause = &e as &dyn Error,
                "failed to init a database connection"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let connection = Authenticated::authenticate(connection, token)
            .await
            .map_err(|e| match e {
                scalar_cms::db::AuthenticationError::BadToken
                | scalar_cms::db::AuthenticationError::BadCredentials => StatusCode::UNAUTHORIZED,
                scalar_cms::db::AuthenticationError::DatabaseError(e) => {
                    tracing::error!(cause = ?e, "failed to authenticate connection");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            })?;

        Ok(Self(connection))
    }
}

/// Endpoint that signs a user in with a username and password.
///
/// # Errors
///
/// This function will return an error if authentication fails.
pub async fn signin<F: DatabaseFactory + Clone>(
    State(factory): State<F>,
    Json(credentials): Json<Credentials>,
) -> Result<String, StatusCode>
where
    <F as scalar_cms::db::DatabaseFactory>::Error: 'static,
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    let connection = factory.init().await.map_err(|e| {
        tracing::error!(
            cause = &e as &dyn Error,
            "failed to init a database connection"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!("connection succesfully established");

    let token = connection.signin(credentials).await.map_err(|e| match e {
        scalar_cms::db::AuthenticationError::BadToken
        | scalar_cms::db::AuthenticationError::BadCredentials => StatusCode::UNAUTHORIZED,
        scalar_cms::db::AuthenticationError::DatabaseError(e) => {
            tracing::error!(cause = &e as &dyn Error, "failed to signin");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    })?;

    Ok(token)
}

#[allow(clippy::unused_async)]
// this has to be async for axum
pub async fn get_schema<D: Document>() -> Json<Schema> {
    Json(D::schema())
}

#[derive(Deserialize)]
pub struct ValidateQueryParams {
    id: String,
}

/// Endpoint to validate a document.
///
/// # Errors
///
/// This function will return an error if [`Document::validate`] returns an error.
#[allow(clippy::unused_async)]
// this has to be async for axum
pub async fn validate<F: DatabaseFactory, D: Document + Send + Sync>(
    AuthenticatedConnection(conn): AuthenticatedConnection<F>,
    Query(ValidateQueryParams { id }): Query<ValidateQueryParams>,
    Json(doc): Json<D>,
) -> Result<(), (StatusCode, Json<ValidationError>)> {
    let ctx = ValidationContext::<'_, _, D>::new(conn.inner(), &id);
    doc.validate(ctx)
        .await
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, Json(e)))
}

#[allow(clippy::unused_async)]
// this has to be async for axum
pub async fn me<F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
) -> Json<User> {
    Json(state.me())
}

/// Endpoint that updates a draft.
///
/// # Errors
///
/// This function will return an error if updating the draft fails, usually by database errors.
pub async fn update_draft<D: Document + Serialize + DeserializeOwned + Send, F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
    Path(id): Path<String>,
    Json(data): Json<serde_json::Value>,
) -> Result<Json<Item<serde_json::Value>>, StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    Ok(Json(
        DatabaseConnection::draft::<D>(&state, &id, data)
            .await
            .map_err(|e| {
                tracing::error!(cause = &e as &dyn Error, "couldn't update draft");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
    ))
}

/// Endpoint that deletes a draft.
///
/// # Errors
///
/// This function will return an error if updating the draft fails, usually by database errors.
pub async fn delete_draft<D: Document + Serialize + DeserializeOwned + Send, F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
    Path(id): Path<String>,
) -> Result<Json<Item<serde_json::Value>>, StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    Ok(Json(
        DatabaseConnection::delete_draft::<D>(&state, &id)
            .await
            .map_err(|e| {
                tracing::error!(cause = &e as &dyn Error, "couldn't delete draft");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
    ))
}

/// Endpoint that deletes a docs.
///
/// # Errors
///
/// This function will return an error if updating the draft fails, usually by database errors.
pub async fn delete_doc<D: Document + Serialize + DeserializeOwned + Send, F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
    Path(id): Path<String>,
) -> Result<Json<Option<Item<serde_json::Value>>>, StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    Ok(Json(
        DatabaseConnection::delete::<D>(&state, &id)
            .await
            .map_err(|e| {
                tracing::error!(cause = &e as &dyn Error, "couldn't delete draft");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
    ))
}

#[derive(Deserialize)]
pub struct PublishParams<D> {
    publish_at: Option<DateTime<Utc>>,
    doc: D,
}

/// Endpoint that publishes the document, if it's valid.
///
/// # Errors
///
/// This function will return an error if the document is invalid (determined by [`Document::validate`]), or if the database fails to commit the publish.
pub async fn publish_doc<
    D: Document + Serialize + DeserializeOwned + Send + Sync + 'static,
    F: DatabaseFactory,
>(
    Path(id): Path<String>,
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
    Json(PublishParams { publish_at, doc }): Json<PublishParams<D>>,
) -> Result<(), StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    let ctx = ValidationContext::new(state.inner(), &id);
    DatabaseConnection::publish(
        &state,
        &id,
        publish_at,
        Valid::new(doc, ctx)
            .await
            .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?,
    )
    .await
    .map_err(|e| {
        tracing::error!(cause = &e as &dyn Error, "couldn't publish document");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(())
}

/// Endpoint that unpublishes the document, and puts the current version as a draft.
///
/// # Errors
///
/// This function will return an error if the database fails to commit the publish.
pub async fn unpublish_doc<
    D: Document + Serialize + DeserializeOwned + Send + 'static,
    F: DatabaseFactory,
>(
    Path(id): Path<String>,
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
) -> Result<(), StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    DatabaseConnection::unpublish::<D>(&state, &id)
        .await
        .map_err(|e| {
            tracing::error!(cause = &e as &dyn Error, "couldn't unpublish document");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(())
}

/// Endpoint that gets all documents of a certain type.
///
/// # Errors
///
/// This function will return an error if the database fails to get a document for whatever reason.
pub async fn get_all_docs<D: Document + Serialize + DeserializeOwned + Send, F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
) -> Result<Json<Vec<Item<serde_json::Value>>>, StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    let items = state.inner().get_all::<D>().await.map_err(|e| {
        tracing::error!(cause = &e as &dyn Error, "couldn't get documents");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(items))
}

/// Endpoint that gets a document by id.
///
/// # Errors
///
/// This function will return an error if the document isn't found, or some other database error occurs.
pub async fn get_doc_by_id<D: Document + Serialize + DeserializeOwned + Send, F: DatabaseFactory>(
    AuthenticatedConnection(state): AuthenticatedConnection<F>,
    id: Path<String>,
) -> Result<Json<Item<serde_json::Value>>, StatusCode>
where
    <<F as scalar_cms::db::DatabaseFactory>::Connection as scalar_cms::DatabaseConnection>::Error:
        'static,
{
    state
        .inner()
        .get_by_id::<D>(id.as_str())
        .await
        .map_err(|e| {
            tracing::error!(cause = &e as &dyn Error, "couldn't get document");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
