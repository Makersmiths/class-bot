use std::{
    sync::{Arc, OnceLock},
    time,
};

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
