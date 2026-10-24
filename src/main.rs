mod probe;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("probe-server") if args.next().is_none() => probe::serve().await?,
        _ => {
            eprintln!("usage: creds probe-server");
            eprintln!("Runs the local WebTransport compatibility probe server.");
            std::process::exit(2);
        }
    }

    Ok(())
}
