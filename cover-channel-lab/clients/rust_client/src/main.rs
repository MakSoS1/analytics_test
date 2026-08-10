use base64::Engine;
use reqwest::blocking::Client;
use reqwest::Method;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 { return Err("URL METHOD BODY_B64 [Header=Value ...]".into()); }
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let method = Method::from_bytes(args[2].as_bytes())?;
    let body = base64::engine::general_purpose::STANDARD.decode(&args[3])?;
    let mut req = client.request(method, &args[1]);
    for h in args.iter().skip(4) {
        if let Some((k,v)) = h.split_once('=') { req = req.header(k, v); }
    }
    if !body.is_empty() { req = req.body(body); }
    let resp = req.send()?;
    println!("{}", resp.status().as_u16());
    Ok(())
}
