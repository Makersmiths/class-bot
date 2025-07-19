use log::{debug, info, trace};
use std::{env, time};
use thiserror::Error;

use base64::prelude::*;
use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Error)]
pub enum ApricotError {
    #[error("Error making request")]
    NetError(#[from] reqwest::Error),
    #[error("Error parsing request response")]
    ParseError(#[from] serde_json::Error),
}

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
    /// Form a Open AI interface, does not make any requests by itself
    /// # Panics
    /// Failure to load env vars
    /// # Errors
    /// Failure to request initial oauth token
    pub async fn new() -> Result<Self, ApricotError> {
        info!("Apricot API initilzing");
        if env::var("APRICOT_API_KEY").is_err()
            || env::var("APRICOT_CLIENT_ID").is_err()
            || env::var("APRICOT_CLIENT_SECRET").is_err()
            || env::var("APRICOT_API_URI").is_err()
            || env::var("APRICOT_AUTH_URI").is_err()
        {
            dotenv::dotenv().expect("Failed to load env vars for API.");
        }

        let auth_uri: String = env::var("APRICOT_AUTH_URI").expect("Auth URI not defined");
        let api_uri: String = env::var("APRICOT_API_URI").expect("API URI not defined");
        let api_key: String = env::var("APRICOT_API_KEY").expect("API Key not defined");
        let api_key = BASE64_STANDARD.encode(format!("APIKEY:{api_key}"));

        let auth_header: String = format!("Basic {api_key}");

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
        let token_expire = time::Instant::now()
            + time::Duration::from_secs(
                oauth_response
                    .expires_in
                    .try_into()
                    .expect("Could not calculate oauth token expiry"),
            );

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
    pub fn renew_token(&mut self) -> Result<(), ApricotError> {
        self.oauth_token = "wip".to_string();
        let _ = self.auth_uri;
        let _ = self.api_key;
        todo!("Add logic for token renewal");
    }

    /// Get list of events on the calendar
    /// # Errors
    /// Errors on API request or parsing issues
    pub async fn events(&mut self) -> Result<String, ApricotError> {
        info!("Events requested");
        if self.token_expire < time::Instant::now() {
            info!("oauth token has expired since last request, getting a renewal");
            self.renew_token()?;
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
            .body("$top=10$filter=substringof(TextIndex,'house')")
            .send()
            .await?
            .text()
            .await?;
        trace!("Raw course list response: {resp}");
        // TODO: Create event response struct
        // let events_response: EventsResponse = serde_json::from_str(&resp)?;
        Ok(resp)
    }
}

#[allow(dead_code)] // Some fields we don't need now but could be handy later
#[derive(Debug, Deserialize)]
pub struct OAuthResponse {
    access_token: String,
    token_type: String,
    expires_in: i32,
    refresh_token: String,
    #[serde(rename = "Permissions")]
    permissions: Vec<Permission>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    #[serde(rename = "AccountId")]
    pub account_id: i64,
    #[serde(rename = "SecurityProfileId")]
    pub security_profile_id: i64,
    #[serde(rename = "AvailableScopes")]
    pub available_scopes: Vec<String>,
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
    async fn event_list() {
        let mut apricot = ApricotApi::new().await.unwrap();
        let response = apricot.events().await.unwrap();
        assert!(response.contains("StartTimeSpecified"));
    }
}
