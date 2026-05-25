use android_activity::AndroidApp;
use android_activity::input::InputEvent;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use std::io::Cursor;

// TLS Record Types
const TLS_HANDSHAKE: u8 = 0x16;
const TLS_APPLICATION_DATA: u8 = 0x17;

// Handshake Types
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

const FAKE_SNI: &str = "www.hcaptcha.com";

// Structure to track each connection
struct ConnectionContext {
    // Whether we've intercepted and modified the ClientHello
    intercepted: bool,
    // Buffer for data we're holding while waiting for ClientHello
    buffer: Vec<u8>,
}

struct SniInterceptor {
    connections: Arc<Mutex<HashMap<String, ConnectionContext>>>,
}

impl SniInterceptor {
    fn new() -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Process a data chunk from client, intercept and modify ClientHello if found
    async fn process_client_data(&self, client_id: &str, data: &[u8]) -> Vec<u8> {
        let mut conns = self.connections.lock().unwrap();
        let ctx = conns.entry(client_id.to_string()).or_insert(ConnectionContext {
            intercepted: false,
            buffer: Vec::new(),
        });

        // Append to buffer
        ctx.buffer.extend_from_slice(data);

        if !ctx.intercepted {
            // Try to find and modify ClientHello
            if let Some(modified) = self.try_extract_and_modify_client_hello(&ctx.buffer) {
                ctx.intercepted = true;
                ctx.buffer.clear();
                return modified;
            }
            
            // If buffer is getting too large without finding ClientHello,
            if ctx.buffer.len() > 65535 {
                ctx.intercepted = true;
                let result = ctx.buffer.clone();
                ctx.buffer.clear();
                return result;
            }
            
            // Haven't found ClientHello yet, return empty (hold data)
            Vec::new()
        } else {
            // Already intercepted, just forward
            let result = ctx.buffer.clone();
            ctx.buffer.clear();
            result
        }
    }

    // Extract TLS ClientHello, modify SNI, return modified packet
    fn try_extract_and_modify_client_hello(&self, data: &[u8]) -> Option<Vec<u8>> {
        let mut cursor = Cursor::new(data);
        
        // Need at least TLS record header (5 bytes)
        if data.len() < 5 {
            return None;
        }
        
        // Check if it's a TLS handshake record
        let content_type = data[0];
        if content_type != TLS_HANDSHAKE {
            return None;
        }
        
        // Check version (should be 0x0301, 0x0302, 0x0303)
        let version_major = data[1];
        let version_minor = data[2];
        if version_major != 0x03 || (version_minor < 0x01 || version_minor > 0x04) {
            return None;
        }
        
        // Get record length
        let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
        if data.len() < 5 + record_len {
            return None; // Incomplete record
        }
        
        let record_data = &data[5..5 + record_len];
        
        // Check if first handshake message is ClientHello
        if record_data.is_empty() || record_data[0] != HANDSHAKE_CLIENT_HELLO {
            return None;
        }
        
        // Parse handshake header
        if record_data.len() < 4 {
            return None;
        }
        
        let handshake_len = ((record_data[1] as usize) << 16) |
                           ((record_data[2] as usize) << 8) |
                           (record_data[3] as usize);
        
        if record_data.len() < 4 + handshake_len {
            return None;
        }
        
        let handshake_data = &record_data[4..4 + handshake_len];
        
        // Parse ClientHello
        // Skip client_version (2 bytes) and random (32 bytes)
        if handshake_data.len() < 34 {
            return None;
        }
        
        let mut pos = 34; // After version (2) + random (32)
        
        // Skip session_id
        let session_id_len = handshake_data[pos] as usize;
        pos += 1 + session_id_len;
        
        if handshake_data.len() <= pos {
            return None;
        }
        
        // Skip cipher_suites
        let cipher_suites_len = ((handshake_data[pos] as usize) << 8) | (handshake_data[pos + 1] as usize);
        pos += 2 + cipher_suites_len;
        
        if handshake_data.len() <= pos {
            return None;
        }
        
        // Skip compression_methods
        let compression_len = handshake_data[pos] as usize;
        pos += 1 + compression_len;
        
        if handshake_data.len() <= pos {
            return None;
        }
        
        // Now parse extensions
        let extensions_len = ((handshake_data[pos] as usize) << 8) | (handshake_data[pos + 1] as usize);
        pos += 2;
        
        let extensions_end = pos + extensions_len;
        if handshake_data.len() < extensions_end {
            return None;
        }
        
        // Build modified ClientHello
        let mut modified = Vec::new();
        
        // Copy everything before extensions
        modified.extend_from_slice(&handshake_data[0..pos]);
        
        // Track if we found and replaced SNI
        let mut sni_replaced = false;
        let mut ext_pos = pos;
        
        while ext_pos + 4 <= extensions_end {
            let ext_type = ((handshake_data[ext_pos] as usize) << 8) | (handshake_data[ext_pos + 1] as usize);
            let ext_len = ((handshake_data[ext_pos + 2] as usize) << 8) | (handshake_data[ext_pos + 3] as usize);
            let ext_end = ext_pos + 4 + ext_len;
            
            if ext_type == 0x0000 {
                // SNI extension found! Replace it
                sni_replaced = true;
                
                // Write extension header
                modified.write_u16::<BigEndian>(0x0000).unwrap();
                
                // Build new SNI extension with fake SNI
                let sni_bytes = FAKE_SNI.as_bytes();
                // Extension length = SNI list length (2 bytes) + SNI entry (1 type + 2 length + sni_len)
                let new_ext_len = 2 + 1 + 2 + sni_bytes.len();
                modified.write_u16::<BigEndian>(new_ext_len as u16).unwrap();
                
                // SNI list length
                modified.write_u16::<BigEndian>((1 + 2 + sni_bytes.len()) as u16).unwrap();
                
                // Name type: host_name (0)
                modified.push(0x00);
                
                // SNI length
                modified.write_u16::<BigEndian>(sni_bytes.len() as u16).unwrap();
                
                // SNI value
                modified.extend_from_slice(sni_bytes);
                
                // Skip to next extension
                ext_pos = ext_end;
            } else {
                // Copy extension as-is
                modified.extend_from_slice(&handshake_data[ext_pos..ext_end]);
                ext_pos = ext_end;
            }
        }
        
        if !sni_replaced {
            // SNI not found, add it as a new extension
            let sni_bytes = FAKE_SNI.as_bytes();
            modified.write_u16::<BigEndian>(0x0000).unwrap();
            let new_ext_len = 2 + 1 + 2 + sni_bytes.len();
            modified.write_u16::<BigEndian>(new_ext_len as u16).unwrap();
            modified.write_u16::<BigEndian>((1 + 2 + sni_bytes.len()) as u16).unwrap();
            modified.push(0x00);
            modified.write_u16::<BigEndian>(sni_bytes.len() as u16).unwrap();
            modified.extend_from_slice(sni_bytes);
        }
        
        // Update extensions length in the handshake
        let new_extensions_len = modified.len() - pos;
        let ext_len_pos = pos - 2;
        modified[ext_len_pos] = ((new_extensions_len >> 8) & 0xff) as u8;
        modified[ext_len_pos + 1] = (new_extensions_len & 0xff) as u8;
        
        // Update handshake length
        let new_handshake_len = modified.len() - 4;
        modified[1] = ((new_handshake_len >> 16) & 0xff) as u8;
        modified[2] = ((new_handshake_len >> 8) & 0xff) as u8;
        modified[3] = (new_handshake_len & 0xff) as u8;
        
        // Wrap back into TLS record
        let mut tls_record = Vec::new();
        tls_record.push(TLS_HANDSHAKE);
        tls_record.push(0x03); // TLS 1.2
        tls_record.push(0x03);
        let final_record_len = modified.len();
        tls_record.write_u16::<BigEndian>(final_record_len as u16).unwrap();
        tls_record.extend_from_slice(&modified);
        
        log::info!("✓ Intercepted and modified ClientHello: SNI replaced with {}", FAKE_SNI);
        
        Some(tls_record)
    }
}

// The main proxy server
async fn run_proxy(listen_addr: &str, upstream_host: &str, upstream_port: u16) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    log::info!("SNI Spoof Proxy listening on {}", listen_addr);
    log::info!("Forwarding to {}:{}", upstream_host, upstream_port);
    log::info!("Fake SNI being injected: {}", FAKE_SNI);
    
    let interceptor = Arc::new(SniInterceptor::new());
    
    while let Ok((client, client_addr)) = listener.accept().await {
        log::info!("New client connection from {}", client_addr);
        
        let interceptor_clone = interceptor.clone();
        let upstream_addr = format!("{}:{}", upstream_host, upstream_port);
        
        tokio::spawn(async move {
            let mut client = client;
            let mut upstream = match TcpStream::connect(&upstream_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("Failed to connect to upstream: {}", e);
                    return;
                }
            };
            
            let client_id = format!("{}:{}", client_addr.ip(), client_addr.port());
            
            // Create buffers for bidirectional copy with interception
            let (mut client_read, mut client_write) = client.split();
            let (mut upstream_read, mut upstream_write) = upstream.split();
            
            // Client -> Upstream (with SNI interception)
            let interceptor_clone2 = interceptor_clone.clone();
            let client_id_clone = client_id.clone();
            let client_to_upstream = async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    match client_read.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = &buffer[0..n];
                            let processed = interceptor_clone2.process_client_data(&client_id_clone, data).await;
                            if !processed.is_empty() && upstream_write.write_all(&processed).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("Client read error: {}", e);
                            break;
                        }
                    }
                }
            };
            
            // Upstream -> Client (no interception needed, just forward)
            let upstream_to_client = async move {
                let mut buffer = vec![0u8; 16384];
                loop {
                    match upstream_read.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if client_write.write_all(&buffer[0..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("Upstream read error: {}", e);
                            break;
                        }
                    }
                }
            };
            
            tokio::select! {
                _ = client_to_upstream => {}
                _ = upstream_to_client => {}
            }
            
            log::info!("Connection closed for {}", client_id);
        });
    }
    
    Ok(())
}

// Android entry point
#[no_mangle]
fn android_main(app: AndroidApp) {
    // Initialize logging to logcat
    android_logger::init_once(
        android_logger::Config::default()
            .with_min_level(log::Level::Info)
            .with_tag("snispoof")
    );
    
    log::info!("═══════════════════════════════════════════");
    log::info!("  SNI Spoof Proxy for Android v1.0");
    log::info!("═══════════════════════════════════════════");
    
    let listen_addr = "127.0.0.1:40443";
    let upstream_host = "104.19.229.21";
    let upstream_port = 443;
    
    log::info!("📡 Listening on: {}", listen_addr);
    log::info!("🎯 Upstream: {}:{}", upstream_host, upstream_port);
    log::info!("🔧 Fake SNI: {}", FAKE_SNI);
    log::info!("═══════════════════════════════════════════");
    
    // Start the proxy in a Tokio runtime
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            if let Err(e) = run_proxy(listen_addr, upstream_host, upstream_port).await {
                log::error!("Proxy error: {}", e);
            }
        });
    });
    
    // Keep app alive and handle events
    loop {
        app.poll_events(Some(std::time::Duration::from_millis(100)));
        while let Some(event) = app.next_event() {
            match event {
                android_activity::AndroidEvent::InputEvent(InputEvent::KeyEvent(key_event)) => {
                    if key_event.key_code() == android_activity::keycodes::KEYCODE_BACK {
                        log::info!("Back button pressed, exiting...");
                        return;
                    }
                }
                android_activity::AndroidEvent::Destroy => {
                    log::info!("App destroying, exiting...");
                    return;
                }
                _ => {}
            }
        }
    }
}

// JNI exports for potential future use
#[no_mangle]
pub extern "C" fn Java_com_snispoof_android_MainActivity_startProxy(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) {
    log::info!("JNI startProxy called");
}

#[no_mangle]
pub extern "C" fn Java_com_snispoof_android_MainActivity_stopProxy(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
) {
    log::info!("JNI stopProxy called");
}
