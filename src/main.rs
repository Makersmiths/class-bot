use class_bot::apricot_api;
use log::info;

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("Failed to load env vars");

    pretty_env_logger::init();

    info!("Starting class-bot...");

    let mut apricot = apricot_api::ApricotApi::new()
        .await
        .expect("Failed to authorize with Wild Apricots");
    info!("Apricot API: {apricot:#?}");
    let events = apricot.events().await;
    info!("Events: {events:#?}");
}
