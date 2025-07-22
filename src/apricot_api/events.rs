use std::{
    fmt::Display,
    sync::{Arc, OnceLock},
    time,
};

use chrono::DateTime;
use log::{debug, info};
use tokio::sync::Mutex;

use super::{ApricotApi, Error, Event, EventsResponse};

static EVENTS_STORE: OnceLock<Arc<Mutex<EventsCache>>> = OnceLock::new();
const EVENTS_RENEW_SECS: u64 = 1800; // How often to renew events from the API when requested

/// Stores the information necessary to request events and cache the results
struct EventsCache {
    apricot_api: ApricotApi,
    last_update: time::Instant,
    events_response: EventsResponse,
}

impl EventsCache {
    async fn new() -> Result<Self, Error> {
        info!("Events requested, Wild Apricots API being initialized");
        let mut apricot_api = ApricotApi::new().await?;
        let events_response = apricot_api.events().await?;
        let last_update = time::Instant::now();
        Ok(Self {
            apricot_api,
            last_update,
            events_response,
        })
    }
}

/// Get a list of events from the API, only refreshes when the data is expired
/// # Errors
/// On Apricot API errors
pub async fn get_events() -> Result<Vec<Event>, Error> {
    if EVENTS_STORE.get().is_none() {
        EVENTS_STORE
            .set(Arc::new(Mutex::new(EventsCache::new().await?)))
            .unwrap_or_else(|_| unreachable!("Just checked this is empty"));
    }

    let mut events_store = EVENTS_STORE
        .get()
        .unwrap_or_else(|| unreachable!("Just filled this if it was empty"))
        .lock()
        .await;

    if events_store.last_update.elapsed() > time::Duration::from_secs(EVENTS_RENEW_SECS) {
        info!("Events out of date, requesting update");
        events_store.events_response = events_store.apricot_api.events().await?;
        debug!("Events update complete");
    }

    Ok(events_store.events_response.events.clone())
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format dates - https://docs.rs/chrono/latest/chrono/format/strftime
        let (start_date, start_time) = if self.end_time_specified {
            let end_datetime = DateTime::parse_from_rfc3339(&self.start_date).unwrap_or_default();
            let start_date = end_datetime.format("- Start date: %v \n").to_string();
            let start_time = end_datetime
                .format("- Start time: %-l:%M %P \n")
                .to_string();
            (start_date, start_time)
        } else {
            (String::new(), String::new())
        };
        let (mut end_date, end_time) = if self.end_time_specified {
            let end_datetime = DateTime::parse_from_rfc3339(&self.end_date).unwrap_or_default();
            let end_date = end_datetime.format("- End date: %v \n").to_string();
            let end_time = end_datetime.format("- End time: %-l:%M %P \n").to_string();
            (end_date, end_time)
        } else {
            (String::new(), String::new())
        };
        // Single day classes should not display end date
        // Slice is to cut out the "- Start date: " and compare just the dates
        if start_date[14..] == end_date[12..] {
            end_date = String::new();
        }

        // Registartion limits
        let registration_str = match self.registrations_limit {
            Some(registration_limit) => {
                format!(
                    "- Registration: {} out of {registration_limit} slots registered\n",
                    self.confirmed_registrations_count
                )
            }
            None if self.registration_enabled => {
                format!(
                    "- Registration: {} signed up, no limit\n",
                    self.confirmed_registrations_count
                )
            }
            None => "- Registration: online registration disabled\n".to_string(),
        };

        // Tags
        let mut tags_str = self
            .tags
            .iter()
            .fold(String::new(), |acc, tag| format!("{acc} {tag}"));
        if !tags_str.is_empty() {
            tags_str = format!("- Tags:{tags_str}\n");
        }

        write!(
            f,
            "## Event: {} \n\
            - Link: https://makersmiths.org/event-{} \n\
            - Location: {} \n\
            {start_date}\
            {end_date}\
            {start_time}\
            {end_time}\
            {registration_str}\
            {tags_str}\
            ",
            self.name, self.id, self.location
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[test_log::test]
    async fn get_cached_events() {
        // This should fully initialize the api and grab events, it may take a couple seconds
        let events_first = get_events().await.unwrap();
        assert!(!events_first.is_empty());

        // Check the underlying statics for the cache
        // Make sure we drop the mutex
        {
            let events_store = EVENTS_STORE
                .get()
                .expect("Should be initialized")
                .lock()
                .await;
            assert!(!events_store.events_response.events.is_empty());
        }

        // The second time should be very fast as it is grabbing from cache
        let cache_grab_start = time::Instant::now();
        let events_second = get_events().await.unwrap();
        assert!(!events_second.is_empty());
        assert!(cache_grab_start.elapsed().as_millis() < 500);
    }
}
