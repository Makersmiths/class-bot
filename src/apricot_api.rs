pub mod events;

use std::{env, time};

use base64::prelude::*;
use log::{debug, info, trace};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error making request")]
    NetError(#[from] reqwest::Error),

    #[error("Error parsing request response")]
    ParseError(#[from] serde_json::Error),

    #[error("Environment variable file error")]
    DotEnvError(#[from] dotenv::Error),

    #[error("Environment variable load error")]
    EnvVarError(#[from] std::env::VarError),

    #[error("Type conversion parse error")]
    ConvertError(#[from] std::num::TryFromIntError),
}

/// Generalized Wild Apricots API struct, new endpoints should be added here
/// This struct should remain agnostic to what endpoints it is targeting
#[derive(Debug)]
pub struct ApricotApi {
    auth_uri: String,
    api_uri: String,
    api_key: String,
    oauth_token: String,
    account_id: i64,
    token_expire: time::Instant,
}

impl ApricotApi {
    /// Form a Wild Apricot API interface, does not make any requests by itself
    /// # Errors
    /// Failure to request initial oauth token
    async fn new() -> Result<Self, Error> {
        info!("Apricot API initilzing");
        if env::var("APRICOT_API_KEY").is_err()
            || env::var("APRICOT_CLIENT_ID").is_err()
            || env::var("APRICOT_CLIENT_SECRET").is_err()
            || env::var("APRICOT_API_URI").is_err()
            || env::var("APRICOT_AUTH_URI").is_err()
        {
            dotenv::dotenv()?;
        }

        let auth_uri: String =
            env::var("APRICOT_AUTH_URI").unwrap_or("https://oauth.wildapricot.org".to_string());
        let api_uri: String =
            env::var("APRICOT_API_URI").unwrap_or("https://api.wildapricot.org".to_string());
        let api_key: String = env::var("APRICOT_API_KEY")?;

        let auth_header = BASE64_STANDARD.encode(format!("APIKEY:{api_key}"));
        let auth_header: String = format!("Basic {auth_header}");

        // Initial oauth request, further requests should just be renewals
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{auth_uri}/auth/token"))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .body("grant_type=client_credentials&scope=auto")
            .send()
            .await?
            .text()
            .await?;
        trace!("Raw auth response: {resp}");
        let oauth_response: OAuthResponse = serde_json::from_str(&resp)?;
        debug!("Auth response: {oauth_response:?}");

        // Extract the pieces we care about
        let oauth_token = oauth_response.access_token;
        let account_id = oauth_response.permissions[0].account_id;
        let token_expire =
            time::Instant::now() + time::Duration::from_secs(oauth_response.expires_in.try_into()?);

        Ok(Self {
            auth_uri,
            api_uri,
            api_key,
            oauth_token,
            account_id,
            token_expire,
        })
    }

    /// Request a new token from oauth, replace the old one, update expiry time
    /// # Errors
    /// Errors on API request or parsing issues
    async fn renew_token(&mut self) -> Result<(), Error> {
        info!("Requesting token renewal");

        let auth_header = BASE64_STANDARD.encode(format!("APIKEY:{}", self.api_key));
        let auth_header: String = format!("Basic {auth_header}");

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/auth/token", self.auth_uri))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .body("grant_type=client_credentials&scope=auto&obtain_refresh_token=true")
            .send()
            .await?
            .text()
            .await?;
        trace!("Raw renewal response: {resp}");
        let oauth_response: OAuthResponse = serde_json::from_str(&resp)?;
        debug!("Renewal response: {oauth_response:?}");

        // Extract the pieces we care about
        let oauth_token = oauth_response.access_token;
        let account_id = oauth_response.permissions[0].account_id;
        let token_expire =
            time::Instant::now() + time::Duration::from_secs(oauth_response.expires_in.try_into()?);

        self.oauth_token = oauth_token;
        self.account_id = account_id;
        self.token_expire = token_expire;

        Ok(())
    }

    /// Get list of events on the calendar
    /// # Errors
    /// Errors on API request or parsing issues
    async fn events(&mut self) -> Result<EventsResponse, Error> {
        info!("Events requested");
        if self.token_expire < time::Instant::now() {
            info!("oauth token has expired since last request, getting a renewal");
            self.renew_token().await?;
        }

        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "{}/v2/accounts/{}/events",
                self.api_uri, self.account_id
            ))
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.oauth_token),
            )
            .body("") // TODO: I have not been able to get filtering to work at all
            .send()
            .await?
            .text()
            .await?;
        trace!("Raw course list response: {resp}");
        // TODO: Create event response struct
        let events_response: EventsResponse = serde_json::from_str(&resp)?;
        Ok(events_response)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(dead_code)] // Some fields we don't need now but could be handy later
struct OAuthResponse {
    access_token: String,
    token_type: String,
    expires_in: i32,
    refresh_token: String,
    #[serde(rename = "Permissions")]
    permissions: Vec<Permission>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Permission {
    account_id: i64,
    security_profile_id: i64,
    available_scopes: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EventsResponse {
    events: Vec<Event>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::struct_excessive_bools)] // We can't avoid this because its a Serde struct
pub struct Event {
    pub id: i64,
    pub url: String,
    pub event_type: String,
    pub start_date: String,
    pub end_date: String,
    pub location: String,
    pub registration_enabled: bool,
    pub registrations_limit: Option<i64>,
    pub pending_registrations_count: i64,
    pub confirmed_registrations_count: i64,
    pub wait_list_registration_count: i64,
    pub checked_in_attendees_number: i64,
    pub tags: Vec<String>,
    pub access_level: String,
    pub start_time_specified: bool,
    pub end_time_specified: bool,
    pub has_enabled_registration_types: bool,
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[test_log::test]
    fn api_env_vars() {
        // This is not always a fail state, sometimes env vars could come from somewhere else
        match dotenv::dotenv() {
            Ok(_) => debug!("Loaded .env file"),
            Err(e) => debug!("Failed to load .env: {e}"),
        }

        let test_var = |var: &str| {
            if env::var(var)
                .unwrap_or_else(|e| panic!("{var} load failed with {e}"))
                .is_empty()
            {
                panic!("{var} is empty");
            }
        };

        test_var("APRICOT_API_KEY");
        test_var("APRICOT_API_URI");
        test_var("APRICOT_AUTH_URI");
    }

    #[tokio::test]
    #[test_log::test]
    async fn new_apricot() {
        let apricot = ApricotApi::new().await.unwrap();
        assert!(!apricot.oauth_token.is_empty());
    }

    #[tokio::test]
    #[test_log::test]
    async fn refresh_token() {
        let mut apricot = ApricotApi::new().await.unwrap();
        let oauth_key = apricot.oauth_token.clone();
        apricot
            .renew_token()
            .await
            .expect("Failed to refresh token");
        let new_oauth_key = apricot.oauth_token;
        assert_ne!(oauth_key, new_oauth_key, "Key was not updated");
    }

    #[tokio::test]
    #[test_log::test]
    async fn event_list() {
        let mut apricot = ApricotApi::new().await.unwrap();
        let response = apricot.events().await.unwrap();
        assert!(!response.events.is_empty());
    }
}
