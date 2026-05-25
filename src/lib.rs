// SNI Spoof for Android - Complete working version
use android_activity::AndroidApp;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use byteorder::{BigEndian, WriteBytesExt};
use rand::Rng;

const FAKE_SNI: &str = "security.vercel.com";

#[no_mangle]
fn android_main(app: AndroidApp) {
    // Initialize logging
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(log::Level::Info)
            .with_tag("snispoof")
    );
    
    log::info!("SNI Spoof Proxy starting...");
    log::info!("Listening on 127.0.0.1:40443");
    log::info!("Fake SNI: {}", FAKE_SNI);
    
    // Start proxy in background
    std::thread::spawn(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            run_proxy().await;
        });
    });
    
    // Keep app alive
    loop {
        app.poll_events(Some(std::time::Duration::from_millis(100)));
    }
}

async fn run_proxy() {
    let listener = TcpListener::bind("127.0.0.1:40443").await.unwrap();
    log::info!("Proxy is ready!");
    
    while let Ok((client, addr)) = listener.accept().await {
        log::info!("Connection from {}", addr);
        tokio::spawn(handle_connection(client));
    }
}

async fn handle_connection(mut client: TcpStream) {
    // Connect to upstream Cloudflare
    let mut server = match TcpStream::connect("104.18.4.130:443").await {
        Ok(s) => s,
        Err(e) => {
            log::error!("Cannot connect: {}", e);
            return;
        }
    };
    
    log::info!("Connected to upstream");
    
    // Create fake ClientHello
    let fake_hello = build_fake_client_hello();
    log::info!("Sending fake ClientHello ({} bytes)", fake_hello.len());
    
    // Send fake packet first
    if let Err(e) = server.write_all(&fake_hello).await {
        log::error!("Failed to send fake: {}", e);
        return;
    }
    
    log::info!("Fake sent, starting relay");
    
    // Bidirectional copy
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();
    
    tokio::select! {
        _ = tokio::io::copy(&mut cr, &mut sw) => {}
        _ = tokio::io::copy(&mut sr, &mut cw) => {}
    }
    
    log::info!("Connection closed");
}

fn build_fake_client_hello() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut result = Vec::new();
    
    // TLS Record Layer
    result.push(0x16); // Handshake
    result.push(0x03); // TLS 1.2
    result.push(0x03);
    result.push(0x00); // Length placeholder
    result.push(0x00);
    
    // Handshake header
    result.push(0x01); // ClientHello
    result.push(0x00); // Length (3 bytes)
    result.push(0x00);
    result.push(0x00);
    
    // Version
    result.push(0x03);
    result.push(0x03);
    
    // Random (32 bytes)
    for _ in 0..32 {
        result.push(rng.gen());
    }
    
    // Session ID (empty)
    result.push(0x00);
    
    // Cipher suites
    result.push(0x00);
    result.push(0x0a); // 10 bytes
    result.extend_from_slice(&[
        0x13, 0x02, 0x13, 0x01, 0x13, 0x03, 0xc0, 0x2c, 0xc0, 0x30
    ]);
    
    // Compression
    result.push(0x01);
    result.push(0x00);
    
    // SNI Extension
    let sni_bytes = FAKE_SNI.as_bytes();
    let sni_len = sni_bytes.len();
    
    result.push(0x00); // Extension type: server_name
    result.push(0x00);
    result.push(0x00);
    result.push((sni_len + 5) as u8);
    
    result.push(0x00);
    result.push((sni_len + 3) as u8);
    result.push(0x00);
    result.push((sni_len as u8));
    result.extend_from_slice(sni_bytes);
    
    // Update lengths
    let total_len = result.len() - 5;
    result[3] = ((total_len >> 8) & 0xff) as u8;
    result[4] = (total_len & 0xff) as u8;
    
    let handshake_len = total_len - 4;
    result[6] = ((handshake_len >> 16) & 0xff) as u8;
    result[7] = ((handshake_len >> 8) & 0xff) as u8;
    result[8] = (handshake_len & 0xff) as u8;
    
    result
}
