#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

use std::str::FromStr;
use notify::Watcher;
use std::future::Future;
use lettre::AsyncTransport;
use mailparse::MailHeaderMap;

#[derive(Debug, Deserialize)]
struct Settings {
    listen_addr: String,
    client_id: String,
    tls_conf: Option<TLSConfig>,
    onward_delivery: OnwardDeliveryConfig,
    smime_cert_dir: String,
    smime_pass: String,
}

#[derive(Debug, Deserialize)]
struct TLSConfig {
    cert_file: String,
    key_file: String,
}

#[derive(Debug, Deserialize)]
struct OnwardDeliveryConfig {
    server: String,
    port: u16,
    use_tls: bool,
}

#[async_std::main]
async fn main() {
    pretty_env_logger::init();

    let mut settings = config::Config::default();
    settings
        .merge(config::File::with_name("settings").required(false)).unwrap()
        .merge(config::Environment::with_prefix("SMIME")).unwrap();
    let settings = settings.try_into::<Settings>().unwrap();

    let onward_transport = lettre::transport::smtp::AsyncSmtpTransport::<lettre::AsyncStd1Executor>::builder_dangerous(
        &settings.onward_delivery.server
    )
        .port(settings.onward_delivery.port)
        .hello_name(lettre::transport::smtp::extension::ClientId::Domain(settings.client_id.clone()))
        .tls(if settings.onward_delivery.use_tls {
            lettre::transport::smtp::client::Tls::Opportunistic(lettre::transport::smtp::client::TlsParameters::new(settings.onward_delivery.server).unwrap())
        } else {
            lettre::transport::smtp::client::Tls::Required(lettre::transport::smtp::client::TlsParameters::new(settings.onward_delivery.server).unwrap())
        })
        .pool_config(lettre::transport::smtp::PoolConfig::new())
        .build();

    let mut mail = samotop::mail::Builder
        + IPAcl
        + Extensions
        + samotop::mail::DebugService::new(settings.client_id.clone())
        + samotop::mail::Name::new(settings.client_id.clone())
        + samotop::smtp::Esmtp.with(samotop::smtp::SmtpParser)
        + SMIMESigner {
        p12_dir: async_std::path::Path::new(&settings.smime_cert_dir).to_path_buf(),
        p12_pass: settings.smime_pass,
        transport: onward_transport,
        client_id: settings.client_id.clone()
    };

    if let Some(tls_conf) = settings.tls_conf {
        let tls_provider = TLSProvider::new(&tls_conf.cert_file, &tls_conf.key_file).await.expect("Unable to setup TLS");
        mail += samotop::smtp::EsmtpStartTls.with(samotop::smtp::SmtpParser, tls_provider)
    }

    let srv = samotop::server::TcpServer::on(settings.listen_addr).serve(mail.build());

    srv.await.unwrap()
}

#[derive(Debug)]
struct TLSProvider {
    pkey: std::sync::Arc<async_std::sync::RwLock<openssl::pkey::PKey<openssl::pkey::Private>>>,
    cert_stack: std::sync::Arc<async_std::sync::RwLock<Vec<openssl::x509::X509>>>,
}

impl TLSProvider {
    async fn new(cert_file: &str, key_file: &str) -> Result<Self, std::io::Error> {
        let tls_cert = async_std::fs::read(cert_file).await?;
        let tls_key = async_std::fs::read(key_file).await?;

        let cert_stack = openssl::x509::X509::stack_from_pem(&tls_cert)?;
        let pkey = openssl::pkey::PKey::private_key_from_pem(&tls_key)?;

        if cert_stack.len() < 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "No certs given"));
        }

        let cert_stack = std::sync::Arc::new(async_std::sync::RwLock::new(cert_stack));
        let pkey = std::sync::Arc::new(async_std::sync::RwLock::new(pkey));

        info!("TLS configured");

        info!("Setting up TLS watcher");
        let cert_file_string = cert_file.to_string();
        let key_file_string = key_file.to_string();
        let watcher_cert_stack = cert_stack.clone();
        let watcher_pkey = pkey.clone();
        std::thread::spawn(move || {
            loop {
                let (cert_tx, cert_rx) = std::sync::mpsc::channel();
                let mut cert_watcher = match notify::watcher(cert_tx, std::time::Duration::from_secs(10)) {
                    Ok(w) => w,
                    Err(err) => {
                        warn!("Unable to create certificate watcher: {}", err);
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        continue;
                    }
                };

                match cert_watcher.watch(&cert_file_string, notify::RecursiveMode::NonRecursive) {
                    Ok(()) => {}
                    Err(err) => {
                        warn!("Unable to watch certificate file: {}", err);
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        continue;
                    }
                };

                loop {
                    match cert_rx.recv() {
                        Ok(notify::DebouncedEvent::Write(_)) => {
                            info!("TLS Certificate file updated; reloading");

                            let tls_cert = match std::fs::read(&cert_file_string) {
                                Ok(k) => k,
                                Err(err) => {
                                    error!("Unable to read new TLS certificate: {}", err);
                                    continue;
                                }
                            };
                            let cert_stack = match openssl::x509::X509::stack_from_pem(&tls_cert) {
                                Ok(k) => k,
                                Err(err) => {
                                    error!("Unable to read new TLS certificate: {}", err);
                                    continue;
                                }
                            };

                            if cert_stack.len() < 1 {
                                error!("Unable to read new TLS certificate: no certs in file")
                            }

                            async_std::task::block_on(async {
                                *watcher_cert_stack.write().await = cert_stack;
                            });
                        }
                        Err(e) => error!("Watch error: {:?}", e),
                        _ => {}
                    }
                }
            }
        });
        std::thread::spawn(move || {
            loop {
                let (key_tx, key_rx) = std::sync::mpsc::channel();
                let mut cert_watcher = match notify::watcher(key_tx, std::time::Duration::from_secs(10)) {
                    Ok(w) => w,
                    Err(err) => {
                        warn!("Unable to create key watcher: {}", err);
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        continue;
                    }
                };

                match cert_watcher.watch(&key_file_string, notify::RecursiveMode::NonRecursive) {
                    Ok(()) => {}
                    Err(err) => {
                        warn!("Unable to watch key file: {}", err);
                        std::thread::sleep(std::time::Duration::from_secs(10));
                        continue;
                    }
                };

                loop {
                    match key_rx.recv() {
                        Ok(notify::DebouncedEvent::Write(_)) => {
                            info!("TLS Key file updated; reloading");

                            let tls_key = match std::fs::read(&key_file_string) {
                                Ok(k) => k,
                                Err(err) => {
                                    error!("Unable to read new TLS key: {}", err);
                                    continue;
                                }
                            };
                            let pkey = match openssl::pkey::PKey::private_key_from_pem(&tls_key) {
                                Ok(k) => k,
                                Err(err) => {
                                    error!("Unable to read new TLS key: {}", err);
                                    continue;
                                }
                            };

                            async_std::task::block_on(async {
                                *watcher_pkey.write().await = pkey;
                            });
                        }
                        Err(e) => error!("Watch error: {:?}", e),
                        _ => {}
                    }
                }
            }
        });

        Ok(Self {
            cert_stack,
            pkey,
        })
    }
}

impl samotop::mail::net::tls::TlsProvider for TLSProvider {
    fn get_tls_upgrade(&self) -> Option<Box<dyn samotop::mail::net::tls::TlsUpgrade>> {
        Some(Box::new(TLSUpgrade {
            pkey: self.pkey.clone(),
            cert_stack: self.cert_stack.clone(),
        }))
    }
}

#[derive(Debug)]
struct TLSUpgrade {
    pkey: std::sync::Arc<async_std::sync::RwLock<openssl::pkey::PKey<openssl::pkey::Private>>>,
    cert_stack: std::sync::Arc<async_std::sync::RwLock<Vec<openssl::x509::X509>>>,
}

impl samotop::mail::net::tls::TlsUpgrade for TLSUpgrade {
    fn upgrade_to_tls(&self, stream: Box<dyn samotop::io::client::tls::Io>, _name: String) -> samotop_core::common::S3Fut<std::io::Result<Box<dyn samotop::io::client::tls::Io>>> {
        let cert_stack = self.cert_stack.clone();
        let pkey = self.pkey.clone();
        Box::pin(async move {
            let cert_stack = cert_stack.read().await;
            let pkey = pkey.read().await;

            let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_server()).unwrap();
            ctx.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_1)).unwrap();
            ctx.set_certificate(cert_stack.get(0).unwrap()).unwrap();
            ctx.set_private_key(&pkey).unwrap();

            for cert in cert_stack.iter().skip(1) {
                ctx.add_extra_chain_cert(cert.to_owned()).unwrap();
            }

            let ssl = openssl::ssl::Ssl::new(&ctx.build())?;
            let mut ssl_stream = async_std_openssl::SslStream::new(ssl, stream)?;
            match std::pin::Pin::new(&mut ssl_stream).accept().await {
                Ok(()) => {}
                Err(err) => return match err.into_io_error() {
                    Ok(io_err) => Err(io_err),
                    Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))
                }
            }
            let stream: Box<dyn samotop::io::client::tls::Io> = Box::new(ssl_stream);
            Ok(stream)
        })
    }
}

#[derive(Debug)]
struct Extensions;

impl<T: samotop::mail::AcceptsSessionService> samotop::mail::MailSetup<T> for Extensions {
    fn setup(self, config: &mut T) {
        config.add_last_session_service(self)
    }
}

impl samotop::smtp::SessionService for Extensions {
    fn prepare_session<'a, 'i, 's, 'f>(&'a self, _io: &'i mut Box<dyn samotop::io::client::tls::MayBeTls>, state: &'s mut samotop::smtp::SmtpContext) -> samotop_core::common::S1Fut<'f, ()> where 'a: 'f, 'i: 'f, 's: 'f {
        Box::pin(async move {
            if !state.session.extensions.is_enabled(&samotop::smtp::extension::EIGHTBITMIME) {
                state.session.extensions.enable(&samotop::smtp::extension::EIGHTBITMIME);
            }
            if !state.session.extensions.is_enabled(&samotop::smtp::extension::PIPELINING) {
                state.session.extensions.enable(&samotop::smtp::extension::PIPELINING);
            }
        })
    }
}

#[derive(Debug)]
struct IPAcl;

impl<T: samotop::mail::AcceptsSessionService> samotop::mail::MailSetup<T> for IPAcl {
    fn setup(self, config: &mut T) {
        config.add_last_session_service(self)
    }
}

impl samotop::smtp::SessionService for IPAcl {
    fn prepare_session<'a, 'i, 's, 'f>(&'a self, _io: &'i mut Box<dyn samotop::io::client::tls::MayBeTls>, state: &'s mut samotop::smtp::SmtpContext) -> samotop_core::common::S1Fut<'f, ()> where 'a: 'f, 'i: 'f, 's: 'f {
        Box::pin(async move {
            let (peer_addr, _peer_port) = match state.session.connection.peer_addr.rsplit_once(':') {
                Some(p) => {
                    match std::net::IpAddr::from_str(p.0) {
                        Ok(a) => {
                            (a, p.1.to_string())
                        }
                        Err(err) => {
                            error!("Cannot parse IP: {}", err);
                            state.session.shutdown();
                            return;
                        }
                    }
                }
                None => {
                    state.session.shutdown();
                    return;
                }
            };

            if !peer_addr.is_loopback() {
                state.session.say_shutdown(samotop::smtp::SmtpReply::ServiceNotAvailableError(format!("{} is not a permitted IP;", peer_addr)));
            }
        })
    }
}

struct SMIMESigner {
    p12_dir: async_std::path::PathBuf,
    p12_pass: String,
    client_id: String,
    transport: lettre::transport::smtp::AsyncSmtpTransport<lettre::AsyncStd1Executor>,
}

impl std::fmt::Debug for SMIMESigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SMIMESigner")
            .field("p12", &self.p12_dir)
            .field("p12_pass", &"<redacted>")
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: samotop::mail::AcceptsDispatch> samotop::mail::MailSetup<T> for SMIMESigner {
    fn setup(self, config: &mut T) {
        config.add_last_dispatch(self)
    }
}

impl samotop::mail::MailDispatch for SMIMESigner {
    fn open_mail_body<'a: 'f, 's: 'f, 'f>(&'a self, session: &'s mut samotop::smtp::SmtpSession) -> samotop_core::common::S1Fut<'f, samotop::mail::DispatchResult> {
        if session.transaction.sink.is_none() {
            session.transaction.sink.replace(Box::pin(match SMIMESink::new(
                self.p12_dir.clone(), self.p12_pass.clone(), self.client_id.clone(),
                session, self.transport.clone(),
            ) {
                Ok(s) => s,
                Err(err) => return Box::pin(samotop_core::common::ready(Err(err)))
            }));
        };
        Box::pin(samotop_core::common::ready(Ok(())))
    }
}

struct SMIMESinkInner {
    p12_dir: async_std::path::PathBuf,
    p12_pass: String,
    client_id: String,
    buf: Vec<u8>,
    mail_from: samotop::smtp::command::SmtpMail,
    recipients: Vec<samotop::mail::Recipient>,
    id: String,
    peer_name: Option<String>,
    connection: samotop::io::ConnectionInfo,
    transport: lettre::transport::smtp::AsyncSmtpTransport<lettre::AsyncStd1Executor>,
}

struct SMIMESink {
    inner: Option<SMIMESinkInner>,
    close_fut: Option<std::sync::Mutex<std::pin::Pin<Box<dyn Future<Output=async_std::io::Result<()>> + Send>>>>,
}

impl SMIMESink {
    fn new(
        p12_dir: async_std::path::PathBuf, p12_pass: String, client_id: String, session: &samotop::smtp::SmtpSession,
        transport: lettre::transport::smtp::AsyncSmtpTransport<lettre::AsyncStd1Executor>,
    ) -> Result<Self, samotop::mail::DispatchError> {
        Ok(Self {
            inner: Some(SMIMESinkInner {
                p12_dir,
                p12_pass,
                client_id,
                buf: vec![],
                mail_from: session.transaction.mail.clone().ok_or(samotop::mail::DispatchError::Permanent)?,
                recipients: session.transaction.rcpts.clone(),
                id: session.transaction.id.clone(),
                peer_name: session.peer_name.clone(),
                connection: session.connection.clone(),
                transport,
            }),
            close_fut: None,
        })
    }

    async fn close(inner: SMIMESinkInner) -> async_std::io::Result<()> {
        let email = match mailparse::parse_mail(&inner.buf) {
            Ok(m) => m,
            Err(err) => {
                warn!("Invalid email received: {}", err);
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::InvalidData, err.to_string(),
                ));
            }
        };

        let mail_headers = email.get_headers();
        let from_email = match mail_headers.get_first_header("From") {
            Some(f) => f,
            None => {
                warn!("Invalid email received: no From header");
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::InvalidData, "No From header".to_string(),
                ));
            }
        };
        let from_email_parsed = match mailparse::addrparse_header(from_email) {
            Ok(m) => m,
            Err(err) => {
                warn!("Invalid email received: {}", err);
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::InvalidData, err.to_string(),
                ));
            }
        };
        let from_email_single = match from_email_parsed.extract_single_info() {
            Some(f) => f,
            None => {
                warn!("Invalid email received: From header had more than one address");
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::InvalidData, "From header had more than one address".to_string(),
                ));
            }
        };

        let p12_file = inner.p12_dir.join(from_email_single.addr);
        let smime_cert = match async_std::fs::read(p12_file).await {
            Ok(c) => {
                let p12 = match openssl::pkcs12::Pkcs12::from_der(&c) {
                    Ok(p12) => p12,
                    Err(err) => {
                        error!("Unable to parse S/MIME cert: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                };
                let parsed_p12 = match p12.parse(&inner.p12_pass) {
                    Ok(p12) => p12,
                    Err(err) => {
                        error!("Unable to parse S/MIME cert: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                };
                Some(parsed_p12)
            }
            Err(err) => match err.kind() {
                async_std::io::ErrorKind::NotFound => None,
                _ => {
                    error!("Unable to open S/MIME cert: {}", err);
                    return Err(err);
                }
            }
        };

        let mut signed_message = vec![];

        signed_message.extend_from_slice(format!("Return-Path: <{}>\r\n", inner.mail_from.sender().address()).as_bytes());

        let (peer_addr, _peer_port) = match inner.connection.peer_addr.rsplit_once(':') {
            Some(p) => {
                match std::net::IpAddr::from_str(p.0) {
                    Ok(a) => {
                        (a, p.1.to_string())
                    }
                    Err(err) => {
                        error!("Cannot parse IP: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                }
            }
            None => {
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::Other, "".to_string(),
                ));
            }
        };
        let (local_addr, _local_port) = match inner.connection.local_addr.rsplit_once(':') {
            Some(p) => {
                match std::net::IpAddr::from_str(p.0) {
                    Ok(a) => {
                        (a, p.1.to_string())
                    }
                    Err(err) => {
                        error!("Cannot parse IP: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                }
            }
            None => {
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::Other, "".to_string(),
                ));
            }
        };

        let peer_address_literal = match peer_addr {
            std::net::IpAddr::V4(ipv4) => format!("[{}]", ipv4.to_string()),
            std::net::IpAddr::V6(ipv6) => format!("[IPv6:{}]", ipv6.to_string()),
        };
        let local_address_literal = match local_addr {
            std::net::IpAddr::V4(ipv4) => format!("[{}]", ipv4.to_string()),
            std::net::IpAddr::V6(ipv6) => format!("[IPv6:{}]", ipv6.to_string()),
        };

        signed_message.extend_from_slice(format!(
            "Received: from {} ({}) by {} ({}) via {} with {} id {}; {}\r\n",
            inner.peer_name.as_ref().unwrap_or(&peer_address_literal), peer_address_literal,
            inner.client_id, local_address_literal, "TCP", "SMTP", inner.id, chrono::Utc::now().to_rfc2822()
        ).as_bytes());

        fn add_to_inner_msg(inner_msg: &mut Vec<u8>, parsed_mail: &mailparse::ParsedMail, first: bool) {
            let content_type = &parsed_mail.ctype;

            let mime_headers = parsed_mail.headers.iter()
                .filter(|h| {
                    let v = h.get_key().to_ascii_lowercase();
                    v == "content-type" || v == "content-transfer-encoding"
                });

            if first {
                for header in mime_headers {
                    inner_msg.extend_from_slice(header.get_key_raw());
                    inner_msg.extend_from_slice(b": ");
                    inner_msg.extend_from_slice(header.get_value_raw());
                    inner_msg.extend_from_slice(b"\r\n");
                }
            } else {
                for header in parsed_mail.headers.iter() {
                    inner_msg.extend_from_slice(header.get_key_raw());
                    inner_msg.extend_from_slice(b": ");
                    inner_msg.extend_from_slice(header.get_value_raw());
                    inner_msg.extend_from_slice(b"\r\n");
                }
            }
            inner_msg.extend_from_slice(b"\r\n");

            let boundary = match content_type.params.get("boundary") {
                Some(b) => b.as_bytes(),
                None => b""
            };

            if parsed_mail.subparts.is_empty() {
                let body = match parsed_mail.get_body_encoded() {
                    mailparse::body::Body::Base64(b) | mailparse::body::Body::QuotedPrintable(b) => b.get_raw(),
                    mailparse::body::Body::Binary(b) => b.get_raw(),
                    mailparse::body::Body::EightBit(b) | mailparse::body::Body::SevenBit(b) => b.get_raw()
                };
                inner_msg.extend_from_slice(body);
            } else {
                for sub_part in parsed_mail.subparts.iter() {
                    inner_msg.extend_from_slice(b"--");
                    inner_msg.extend_from_slice(boundary);
                    inner_msg.extend_from_slice(b"\r\n");
                    add_to_inner_msg(inner_msg, sub_part, false)
                }
                inner_msg.extend_from_slice(b"--");
                inner_msg.extend_from_slice(boundary);
                inner_msg.extend_from_slice(b"--\r\n");
            }
        }

        match smime_cert {
            Some(p12) => {
                for outer_header in email.headers.iter()
                    .filter(|h| {
                        let v = h.get_key().to_ascii_lowercase();
                        v != "content-type" && v != "content-transfer-encoding" && v != "mime-version"
                            && v != "dkim-signature"
                    }) {
                    signed_message.extend_from_slice(outer_header.get_key_raw());
                    signed_message.extend_from_slice(b": ");
                    signed_message.extend_from_slice(outer_header.get_value_raw());
                    signed_message.extend_from_slice(b"\r\n");
                }

                let mut inner_msg = vec![];

                add_to_inner_msg(&mut inner_msg, &email, true);

                let cert_stack = openssl::stack::Stack::new().unwrap();
                let sig = match openssl::pkcs7::Pkcs7::sign(
                    &p12.cert, &p12.pkey, p12.chain.as_ref().unwrap_or_else(|| &cert_stack),
                    &inner_msg, openssl::pkcs7::Pkcs7Flags::DETACHED,
                ) {
                    Ok(sig) => sig,
                    Err(err) => {
                        error!("Unable to sign email: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                };

                signed_message.append(&mut match sig.to_smime(&inner_msg, openssl::pkcs7::Pkcs7Flags::DETACHED) {
                    Ok(sig) => sig,
                    Err(err) => {
                        error!("Unable to sign email: {}", err);
                        return Err(async_std::io::Error::new(
                            async_std::io::ErrorKind::Other, err.to_string(),
                        ));
                    }
                });
            }
            None => {
                add_to_inner_msg(&mut signed_message, &email, false);
            }
        }

        let envelope = lettre::address::Envelope::new(
            Some(inner.mail_from.sender().address().parse::<lettre::address::Address>().unwrap()),
            inner.recipients.into_iter().map(|r| r.address.address().parse::<lettre::address::Address>().unwrap()).collect(),
        ).unwrap();

        match inner.transport.send_raw(&envelope, &signed_message).await {
            Ok(_) => {}
            Err(err) => {
                error!("Unable to forward email: {}", err);
                return Err(async_std::io::Error::new(
                    async_std::io::ErrorKind::Other, err.to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl async_std::io::Write for SMIMESink {
    fn poll_flush(self: samotop_core::common::Pin<&mut Self>, _cx: &mut samotop_core::common::Context<'_>) -> samotop_core::common::Poll<async_std::io::Result<()>> {
        samotop_core::common::Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: samotop_core::common::Pin<&mut Self>, cx: &mut samotop_core::common::Context<'_>) -> samotop_core::common::Poll<async_std::io::Result<()>> {
        if let Some(fut) = &mut self.close_fut {
            fut.lock().unwrap().as_mut().poll(cx)
        } else {
            let inner = self.inner.take().unwrap();
            let mut new_fut = Box::pin(Self::close(inner));
            let res = std::pin::Pin::as_mut(&mut new_fut).poll(cx);
            self.close_fut.replace(std::sync::Mutex::new(new_fut));
            res
        }
    }

    fn poll_write(
        mut self: samotop_core::common::Pin<&mut Self>,
        _cx: &mut samotop_core::common::Context<'_>,
        buf: &[u8],
    ) -> samotop_core::common::Poll<std::io::Result<usize>> {
        self.inner.as_mut().unwrap().buf.extend_from_slice(buf);
        samotop_core::common::Poll::Ready(Ok(buf.len()))
    }
}