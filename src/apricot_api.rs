use log::{debug, info, trace};
use std::env;
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
}

impl ApricotApi {
    /// Form a Open AI interface, does not make any requests by itself
    /// # Panics
    /// Failure to load dotenv
    #[must_use]
    pub async fn new() -> Result<Self, ApricotError> {
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
        let api_key = BASE64_STANDARD.encode(&format!("APIKEY:{api_key}"));

        let auth_header: String = format!("Basic {api_key}");

        // Initial oauth request, further requests should just be renewals
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/auth/token", auth_uri))
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

        // Extract the peices we care about
        let oauth_token = oauth_response.access_token;
        let account_id = oauth_response.permissions[0].account_id;

        Ok(Self {
            auth_uri,
            api_uri,
            api_key,
            oauth_token,
            account_id,
        })
    }

    pub async fn events(&self) -> Result<String, ApricotError> {
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
        // let oauth_response: OAuthResponse = serde_json::from_str(&resp)?;
        Ok(resp)
    }
}

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

    // #[test]
    // fn test_api_env_vars() {
    //     // This is not always a fail state, sometimes env vars could come from somewhere else
    //     match dotenv::dotenv() {
    //         Ok(_) => debug!("Loaded .env file"),
    //         Err(e) => debug!("Failed to load .env: {e}"),
    //     }; // from .env file
    //
    //     if env::var("OPEN_AI_TOKEN")
    //         .expect("OPEN_AI_TOKEN load failed")
    //         .is_empty()
    //     {
    //         panic!("OPEN_AI_TOKEN is empty");
    //     }
    //
    //     if env::var("OPEN_AI_URI")
    //         .expect("OPEN_AI_URI load failed")
    //         .is_empty()
    //     {
    //         panic!("OPEN_AI_URI is empty");
    //     }
    // }
    //
    // #[test]
    // fn test_new_openaiapi() {
    //     let openai_api = OpenAiApi::new();
    //     assert!(!openai_api.uri.is_empty() && !openai_api.auth_header.is_empty());
    // }
    //
    // #[tokio::test]
    // async fn test_test_connection() {
    //     let openai_api = OpenAiApi::new();
    //     let response = openai_api.test_connection().await.unwrap();
    //     assert!(response.starts_with("Connection opened with"));
    // }
    //
    // #[tokio::test]
    // async fn test_chat_prompt_not_empty() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::from("Hello!");
    //     let chat_id = String::from("test_chat_id");
    //     let response = openai_api
    //         .chat(prompt.clone(), chat_id.clone())
    //         .await
    //         .unwrap();
    //     assert!(!response.is_empty());
    // }
    //
    // #[tokio::test]
    // async fn test_chat_prompt_empty() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::new();
    //     let chat_id = String::from("test_chat_id");
    //     let response = openai_api
    //         .chat(prompt.clone(), chat_id.clone())
    //         .await
    //         .unwrap();
    //     assert_eq!(response, "Prompt is empty, usage: '/chat [PROMPT HERE]'");
    // }
    //
    // #[tokio::test]
    // async fn test_chat_purge_with_prompt() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::from("test prompt");
    //     let chat_id = String::from("test_purge_with_prompt");
    //     let response = openai_api.chat_purge(&chat_id, &prompt).unwrap();
    //     assert_eq!(response, "Chat history purged with prompt 'test prompt'.");
    //     let history = ChatHistory::new(&chat_id).unwrap();
    //     assert_eq!(history.messages[0].role, "system");
    //     assert_eq!(history.messages[0].content, "test prompt");
    // }
    //
    // #[tokio::test]
    // async fn test_chat_purge_without_prompt() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::new();
    //     let chat_id = String::from("test_purge_without_prompt");
    //     let response = openai_api.chat_purge(&chat_id, &prompt).unwrap();
    //     assert_eq!(response, "Chat history purged without a custom prompt.");
    // }
    //
    // #[tokio::test]
    // async fn test_image_prompt_not_empty() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::from("test prompt");
    //     let response = openai_api.image(prompt.clone()).await.unwrap();
    //     assert!(!response.is_empty());
    // }
    //
    // #[tokio::test]
    // async fn test_image_prompt_empty() {
    //     let openai_api = OpenAiApi::new();
    //     let prompt = String::new();
    //     let response = openai_api.image(prompt.clone()).await;
    //     assert!(response.is_ok(), "Error: {:?}", response.err());
    //     assert_eq!(
    //         response.unwrap(),
    //         "Prompt is empty, usage: '/image [PROMPT HERE]'"
    //     );
    // }
}
