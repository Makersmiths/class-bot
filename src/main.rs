use log::info;

use class_bot::apricot_api;

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("Failed to load env vars");
    pretty_env_logger::init();

    info!("Starting class-bot...");

    let events = apricot_api::events::get_events().await.unwrap();
    info!("Events: {events:#?}");
}
