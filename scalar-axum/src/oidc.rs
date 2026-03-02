use std::{
    error::Error,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    extract::{Query, State},
    response::Redirect,
};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
        CoreJweContentEncryptionAlgorithm, CoreRevocableToken, CoreRevocationErrorResponse,
        CoreTokenIntrospectionResponse, CoreTokenResponse,
    },
    AccessTokenHash, AuthorizationCode, Client, CsrfToken, EmptyAdditionalClaims, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, Nonce, PkceCodeChallenge, PkceCodeVerifier, ResponseType, Scope,
    StandardErrorResponse,
};
use scalar_cms::{db::DatabaseFactory, DatabaseConnection};
use serde::Deserialize;

use crate::expire_map::ExpiringHashMap;

pub trait ToStatusCode {
    fn to_status_code(&self) -> axum::http::StatusCode;
}

impl ToStatusCode for StandardErrorResponse<CoreErrorResponseType> {
    fn to_status_code(&self) -> axum::http::StatusCode {
        match self.error() {
            CoreErrorResponseType::InvalidClient
            | CoreErrorResponseType::InvalidGrant
            | CoreErrorResponseType::InvalidRequest
            | CoreErrorResponseType::InvalidScope => axum::http::StatusCode::BAD_REQUEST,
            CoreErrorResponseType::UnauthorizedClient
            | CoreErrorResponseType::UnsupportedGrantType
            | CoreErrorResponseType::Extension(_) => axum::http::StatusCode::UNAUTHORIZED,
        }
    }
}

pub struct AuthState(PkceCodeVerifier, Nonce);

pub type CoreOidcState = OidcState<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
>;

trait Sealed {}

impl<
        AC: openidconnect::AdditionalClaims,
        AD: openidconnect::AuthDisplay,
        GC: openidconnect::GenderClaim,
        JE: openidconnect::JweContentEncryptionAlgorithm<
            KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
        >,
        K: openidconnect::JsonWebKey,
        P: openidconnect::AuthPrompt,
        TE: openidconnect::ErrorResponse,
        TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
        TIR: openidconnect::TokenIntrospectionResponse,
        RT: openidconnect::RevocableToken,
        TRE: openidconnect::ErrorResponse,
        HasDeviceAuthUrl: openidconnect::EndpointState,
        HasIntrospectionUrl: openidconnect::EndpointState,
        HasRevocationUrl: openidconnect::EndpointState,
    > Sealed
    for OidcState<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
}

#[allow(private_bounds, clippy::type_complexity)]
pub trait OidcStateGetter<
    AC: openidconnect::AdditionalClaims,
    AD: openidconnect::AuthDisplay,
    GC: openidconnect::GenderClaim,
    JE: openidconnect::JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
    >,
    K: openidconnect::JsonWebKey,
    P: openidconnect::AuthPrompt,
    TE: openidconnect::ErrorResponse,
    TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: openidconnect::TokenIntrospectionResponse,
    RT: openidconnect::RevocableToken,
    TRE: openidconnect::ErrorResponse,
    HasDeviceAuthUrl: openidconnect::EndpointState,
    HasIntrospectionUrl: openidconnect::EndpointState,
    HasRevocationUrl: openidconnect::EndpointState,
>: Sealed
{
    fn oidc_client(
        &self,
    ) -> &Client<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointSet,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >;

    fn reqwest_client(&self) -> &reqwest::Client;

    fn auth_states(&self) -> &Arc<Mutex<ExpiringHashMap<String, AuthState>>>;
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct OidcState<
    AC: openidconnect::AdditionalClaims,
    AD: openidconnect::AuthDisplay,
    GC: openidconnect::GenderClaim,
    JE: openidconnect::JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
    >,
    K: openidconnect::JsonWebKey,
    P: openidconnect::AuthPrompt,
    TE: openidconnect::ErrorResponse,
    TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: openidconnect::TokenIntrospectionResponse,
    RT: openidconnect::RevocableToken,
    TRE: openidconnect::ErrorResponse,
    HasDeviceAuthUrl: openidconnect::EndpointState,
    HasIntrospectionUrl: openidconnect::EndpointState,
    HasRevocationUrl: openidconnect::EndpointState,
> {
    oidc_client: Client<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointSet,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    reqwest_client: reqwest::Client,
    auth_states: Arc<Mutex<ExpiringHashMap<String, AuthState>>>,
}

impl<
        AC: openidconnect::AdditionalClaims,
        AD: openidconnect::AuthDisplay,
        GC: openidconnect::GenderClaim,
        JE: openidconnect::JweContentEncryptionAlgorithm<
            KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
        >,
        K: openidconnect::JsonWebKey,
        P: openidconnect::AuthPrompt,
        TE: openidconnect::ErrorResponse,
        TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
        TIR: openidconnect::TokenIntrospectionResponse,
        RT: openidconnect::RevocableToken,
        TRE: openidconnect::ErrorResponse,
        HasDeviceAuthUrl: openidconnect::EndpointState,
        HasIntrospectionUrl: openidconnect::EndpointState,
        HasRevocationUrl: openidconnect::EndpointState,
    >
    OidcState<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn new(
        oidc_client: Client<
            AC,
            AD,
            GC,
            JE,
            K,
            P,
            TE,
            TR,
            TIR,
            RT,
            TRE,
            EndpointSet,
            HasDeviceAuthUrl,
            HasIntrospectionUrl,
            HasRevocationUrl,
            EndpointMaybeSet,
            EndpointMaybeSet,
        >,
        reqwest_client: reqwest::Client,
    ) -> Self {
        Self {
            oidc_client,
            reqwest_client,
            auth_states: Arc::new(Mutex::new(ExpiringHashMap::new(Duration::from_mins(10)))),
        }
    }
}

impl<
        AC: openidconnect::AdditionalClaims,
        AD: openidconnect::AuthDisplay,
        GC: openidconnect::GenderClaim,
        JE: openidconnect::JweContentEncryptionAlgorithm<
            KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
        >,
        K: openidconnect::JsonWebKey,
        P: openidconnect::AuthPrompt,
        TE: openidconnect::ErrorResponse,
        TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
        TIR: openidconnect::TokenIntrospectionResponse,
        RT: openidconnect::RevocableToken,
        TRE: openidconnect::ErrorResponse,
        HasDeviceAuthUrl: openidconnect::EndpointState,
        HasIntrospectionUrl: openidconnect::EndpointState,
        HasRevocationUrl: openidconnect::EndpointState,
    >
    OidcStateGetter<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
    for OidcState<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >
{
    fn oidc_client(
        &self,
    ) -> &Client<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointSet,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
        EndpointMaybeSet,
        EndpointMaybeSet,
    > {
        &self.oidc_client
    }

    fn reqwest_client(&self) -> &reqwest::Client {
        &self.reqwest_client
    }

    fn auth_states(&self) -> &Arc<Mutex<ExpiringHashMap<String, AuthState>>> {
        &self.auth_states
    }
}

/// Begins the OIDC auth process, returning a redirect response to send to the client.
///
/// # Panics
///
/// Panics if the CSRF state mutex was somehow poisoned.
#[allow(clippy::unused_async)]
// axum only allows async functions in endpoints
pub async fn begin_oidc_auth<
    AC: openidconnect::AdditionalClaims,
    AD: openidconnect::AuthDisplay,
    GC: openidconnect::GenderClaim,
    JE: openidconnect::JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
    >,
    K: openidconnect::JsonWebKey,
    P: openidconnect::AuthPrompt,
    TE: openidconnect::ErrorResponse + 'static,
    TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: openidconnect::TokenIntrospectionResponse,
    RT: openidconnect::RevocableToken,
    TRE: openidconnect::ErrorResponse + 'static,
    HasDeviceAuthUrl: openidconnect::EndpointState,
    HasIntrospectionUrl: openidconnect::EndpointState,
    HasRevocationUrl: openidconnect::EndpointState,
    OS: OidcStateGetter<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >,
    RS: ResponseType,
>(
    State(oidc_state): State<OS>,
) -> Redirect {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_state, nonce) = oidc_state
        .oidc_client()
        .authorize_url(
            openidconnect::AuthenticationFlow::<RS>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes([
            Scope::new("openid".into()),
            Scope::new("profile".into()),
            Scope::new("email".into()),
        ])
        .set_pkce_challenge(challenge)
        .url();

    oidc_state
        .auth_states()
        .lock()
        .expect("poisoned mutex. this should never happen!")
        .insert(csrf_state.into_secret(), AuthState(verifier, nonce));

    Redirect::to(authorize_url.as_str())
}

#[derive(Deserialize)]
pub struct RedirectParams {
    code: String,
    state: String,
}

/// Complete OIDC auth.
///
/// # Panics
///
/// Panics if provider metadata hasn't been configured on [`OidcState::oidc_client`],
/// or if the csrf state mutex was somehow poisoned.
///
/// # Errors
///
/// This function will return an error if authentication failed for any reason.
pub async fn complete_oidc_auth<
    AC: openidconnect::AdditionalClaims + Send + Sync,
    AD: openidconnect::AuthDisplay,
    GC: openidconnect::GenderClaim + Send + Sync,
    JE: openidconnect::JweContentEncryptionAlgorithm<
        KeyType = <K::SigningAlgorithm as openidconnect::JwsSigningAlgorithm>::KeyType,
    >,
    K: openidconnect::JsonWebKey,
    P: openidconnect::AuthPrompt,
    TE: openidconnect::ErrorResponse + ToStatusCode + 'static,
    TR: openidconnect::TokenResponse<AC, GC, JE, K::SigningAlgorithm>,
    TIR: openidconnect::TokenIntrospectionResponse,
    RT: openidconnect::RevocableToken,
    TRE: openidconnect::ErrorResponse + 'static,
    HasDeviceAuthUrl: openidconnect::EndpointState,
    HasIntrospectionUrl: openidconnect::EndpointState,
    HasRevocationUrl: openidconnect::EndpointState,
    OS: OidcStateGetter<
        AC,
        AD,
        GC,
        JE,
        K,
        P,
        TE,
        TR,
        TIR,
        RT,
        TRE,
        HasDeviceAuthUrl,
        HasIntrospectionUrl,
        HasRevocationUrl,
    >,
    RS: ResponseType,
    F: DatabaseFactory,
>(
    State(oidc_state): State<OS>,
    State(connection): State<F>,
    Query(params): Query<RedirectParams>,
) -> Result<String, axum::http::StatusCode> {
    let AuthState(verifier, nonce) = oidc_state
        .auth_states()
        .lock()
        .expect("poisoned mutex. this should never happen!")
        .remove(&params.state)
        .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;

    let exchange = oidc_state
        .oidc_client()
        .exchange_code(AuthorizationCode::new(params.code))
        .expect("proper config")
        .set_pkce_verifier(verifier)
        .request_async(oidc_state.reqwest_client())
        .await
        .map_err(|e| match e {
            openidconnect::RequestTokenError::ServerResponse(e) => e.to_status_code(),
            openidconnect::RequestTokenError::Request(cause) => {
                tracing::error!(cause = &cause as &dyn Error, "couldn't request token");
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            openidconnect::RequestTokenError::Other(cause) => {
                tracing::error!(
                    cause = Box::<dyn Error>::from(cause),
                    "couldn't request token"
                );
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            }
            openidconnect::RequestTokenError::Parse(error, items) => {
                tracing::error!(
                    cause = &error as &dyn Error,
                    ?items,
                    "couldn't parse response"
                );
                axum::http::StatusCode::BAD_REQUEST
            }
        })?;

    let id_token = exchange
        .id_token()
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let id_token_verifier = oidc_state.oidc_client().id_token_verifier();
    let claims = id_token
        .claims(&id_token_verifier, &nonce)
        .map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash = AccessTokenHash::from_token(
            exchange.access_token(),
            id_token.signing_alg().unwrap(),
            id_token.signing_key(&id_token_verifier).unwrap(),
        )
        .unwrap();
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        }
    }

    Ok(connection
        .init()
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .signin_oidc(claims)
        .await
        .unwrap())
}
