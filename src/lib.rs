use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

use std::net::ToSocketAddrs;

use tokio::runtime::Runtime;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use tlsn_common::config::ProtocolConfig;
use tlsn_core::request::RequestConfig;
use tlsn_prover::{Prover, ProverConfig};
use notary_client::{NotarizationRequest, NotaryClient};
use notary_server::{
    NotaryServerProperties, ServerProperties, NotarizationProperties,
    TLSProperties, NotarySigningKeyProperties, LoggingProperties,
    AuthorizationProperties, run_server,
};

use tokio_util::compat::TokioAsyncReadCompatExt;

/// A Python-friendly wrapper around the TLS Notary Prover.
/// 
/// # Thread Safety
/// This class is marked as `unsendable`, meaning it cannot be shared between Python threads.
/// This is necessary because:
/// - The prover maintains internal state that must be accessed sequentially
/// - It contains a Tokio runtime which is not `Sync`
/// - Network operations and proof generation must happen in order
/// 
/// # Usage
/// Create one instance per thread if you need concurrent operations.
/// Do not try to share instances between threads as this will raise a TypeError in Python.
#[pyclass(unsendable)]
pub struct PyProver {
    notary_host: String,
    notary_port: u16,
    server_name: String,
    rt: Runtime,
    inner: Option<ProverState>,
}

#[derive(Debug)]
enum ProverState {
    Setup(Prover<tlsn_prover::state::Setup>),
    Closed(Prover<tlsn_prover::state::Closed>),
    Notarize(Prover<tlsn_prover::state::Notarize>),
}

#[pymethods]
impl PyProver {
    #[new]
    fn new(notary_host: String, notary_port: u16, server_name: String) -> PyResult<Self> {
        Ok(Self {
            notary_host,
            notary_port,
            server_name,
            rt: Runtime::new().unwrap(),
            inner: None,
        })
    }

    fn reset(&mut self) -> PyResult<()> {
        let prover = self.rt.block_on(async {
            let notary_client = NotaryClient::builder()
                .host(self.notary_host.clone())
                .port(self.notary_port)
                .enable_tls(false)
                .build()?;

            let request = NotarizationRequest::builder()
                .max_sent_data(10000)
                .max_recv_data(10000)
                .build()?;

            let accepted = notary_client.request_notarization(request).await?;

            let config = ProverConfig::builder()
                .server_name(self.server_name.as_str())
                .protocol_config(
                    ProtocolConfig::builder()
                        .max_sent_data(10000)
                        .max_recv_data(10000)
                        .build()?,
                )
                .crypto_provider(tlsn_core::CryptoProvider::default())
                .build()?;

            let setup = Prover::new(config).setup(accepted.io.compat()).await?;
            Ok::<_, anyhow::Error>(setup)
        }).map_err(|e| PyRuntimeError::new_err(format!("Setup failed: {e}")))?;

        self.inner = Some(ProverState::Setup(prover));
        Ok(())
    }

    fn connect(&mut self, server_host: String, server_port: u16) -> PyResult<()> {
        let prover = match self.inner.take() {
            Some(ProverState::Setup(prover)) => prover,
            _ => return Err(PyRuntimeError::new_err("No setup prover available")),
        };

        let closed = self.rt.block_on(async move {
            let addr = (server_host.as_str(), server_port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Invalid server address"))?;
            let conn = TcpStream::connect(addr).await?;
            let (_, fut) = prover.connect(conn.compat()).await?;
            let closed = fut.await?;
            Ok::<_, anyhow::Error>(closed)
        }).map_err(|e| PyRuntimeError::new_err(format!("Connect failed: {e}")))?;

        self.inner = Some(ProverState::Closed(closed));
        Ok(())
    }

    fn start_notarize(&mut self) -> PyResult<()> {
        let prover = match self.inner.take() {
            Some(ProverState::Closed(prover)) => prover.start_notarize(),
            _ => return Err(PyRuntimeError::new_err("No closed prover available")),
        };

        self.inner = Some(ProverState::Notarize(prover));
        Ok(())
    }

    fn finalize_notarize(&mut self) -> PyResult<Vec<u8>> {
        let prover = match self.inner.take() {
            Some(ProverState::Notarize(prover)) => prover,
            _ => return Err(PyRuntimeError::new_err("No notarize prover available")),
        };

        let result = self.rt.block_on(async move {
            let request_config = RequestConfig::default();
            let (attestation, _secrets) = prover.finalize(&request_config).await?;
            Ok::<_, anyhow::Error>(bincode::serialize(&attestation)?)
        }).map_err(|e| PyRuntimeError::new_err(format!("Finalization failed: {e}")))?;

        self.reset().map_err(|e| PyRuntimeError::new_err(format!("Reset failed after finalize: {e}")))?;
        Ok(result)
    }
}

/// A Python-friendly wrapper around the TLS Notary Server.
/// 
/// # Thread Safety
/// This class is marked as `unsendable`, meaning it cannot be shared between Python threads.
/// This is necessary because it contains a Tokio runtime which is not `Sync`.
/// 
/// # Usage
/// Create one instance to handle multiple concurrent notarization sessions.
/// Use start() to begin accepting connections and stop() to gracefully shutdown.
#[pyclass(unsendable)]
pub struct PyNotary {
    rt: Runtime,
    config: NotaryServerProperties,
    server_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

#[pymethods]
impl PyNotary {
    #[new]
    fn new(
        host: String,
        port: u16,
        max_sent_data: usize,
        max_recv_data: usize,
        timeout_seconds: u64,
        tls_enabled: bool,
        tls_cert_path: Option<String>,
        tls_key_path: Option<String>,
        notary_key_path: String,
        notary_pub_key_path: String,
    ) -> PyResult<Self> {
        let config = NotaryServerProperties {
            server: ServerProperties {
                name: "PyNotary".to_string(),
                host,
                port,
                html_info: String::new(),
            },
            notarization: NotarizationProperties {
                max_sent_data,
                max_recv_data,
                timeout: timeout_seconds,
            },
            tls: TLSProperties {
                enabled: tls_enabled,
                private_key_pem_path: tls_key_path,
                certificate_pem_path: tls_cert_path,
            },
            notary_key: NotarySigningKeyProperties {
                private_key_pem_path: notary_key_path,
                public_key_pem_path: notary_pub_key_path,
            },
            logging: LoggingProperties {
                level: "info".to_string(),
                filter: None,
                ..Default::default()
            },
            authorization: AuthorizationProperties {
                enabled: false,
                whitelist_csv_path: None,
            },
        };

        Ok(Self {
            rt: Runtime::new().unwrap(),
            config,
            server_handle: None,
            shutdown_tx: None,
        })
    }

    fn start(&mut self) -> PyResult<()> {
        // Create a new shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Clone config for the server task
        let config = self.config.clone();

        // Spawn the server task
        let handle = self.rt.spawn(async move {
            // Create a future that completes when shutdown signal is received
            let shutdown = async {
                let _ = shutdown_rx.await;
            };

            // Run the server in a separate task so we can select between it and shutdown
            let server_config = config.clone();
            let server = tokio::spawn(async move {
                run_server(&server_config).await
            });

            // Wait for either server completion or shutdown signal
            tokio::select! {
                _ = shutdown => {
                    // Shutdown signal received, server will be dropped
                    println!("Notary server shutting down...");
                }
                result = server => {
                    match result {
                        Ok(Ok(())) => println!("Notary server stopped normally"),
                        Ok(Err(e)) => eprintln!("Notary server error: {e}"),
                        Err(e) => eprintln!("Notary server task error: {e}"),
                    }
                }
            }
        });

        self.server_handle = Some(handle);
        Ok(())
    }

    fn stop(&mut self) -> PyResult<()> {
        // Send shutdown signal if we have a sender
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the server task to complete
        if let Some(handle) = self.server_handle.take() {
            self.rt.block_on(async {
                let _ = handle.await;
            });
        }

        Ok(())
    }
}

/// The Python module combining both TLS Notary Prover and Server functionality.
#[pymodule]
fn tlsnpy(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProver>()?;
    m.add_class::<PyNotary>()?;
    Ok(())
}
