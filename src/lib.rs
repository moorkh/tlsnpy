use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

use std::net::ToSocketAddrs;
use tokio::runtime::Runtime;

use tlsn_common::config::ProtocolConfig;
use tlsn_core::request::RequestConfig;
use tlsn_prover::{Prover, ProverConfig};
use notary_client::{NotarizationRequest, NotaryClient};

use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[pyclass]
pub struct PyProver {
    notary_host: String,
    notary_port: u16,
    server_name: String,
    rt: Runtime,
    inner: Option<ProverState>,
}

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
                .server_name(self.server_name.clone())
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

        let (closed, _) = self.rt.block_on(async move {
            let addr = (server_host.as_str(), server_port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| PyRuntimeError::new_err("Invalid server address"))?;
            let conn = tokio::net::TcpStream::connect(addr).await?;
            let (_tls_conn, fut) = prover.connect(conn.compat()).await?;
            let closed = tokio::spawn(fut).await??;
            Ok::<_, anyhow::Error>(closed)
        }).map_err(|e| PyRuntimeError::new_err(format!("Connect failed: {e}")))?;

        self.inner = Some(ProverState::Closed(closed));
        Ok(())
    }

    fn notarize(&mut self) -> PyResult<Vec<u8>> {
        let prover = match self.inner.take() {
            Some(ProverState::Closed(prover)) => prover.start_notarize(),
            _ => return Err(PyRuntimeError::new_err("No closed prover available")),
        };

        let result = self.rt.block_on(async move {
            let request_config = RequestConfig::default();
            let (attestation, _secrets) = prover.finalize(&request_config).await?;
            Ok::<_, anyhow::Error>(bincode::serialize(&attestation)?)
        }).map_err(|e| PyRuntimeError::new_err(format!("Notarization failed: {e}")))?;

        let reset_result = self.reset();
        reset_result.map_err(|e| PyRuntimeError::new_err(format!("Reset failed after notarize: {e}")))?;

        Ok(result)
    }
}

#[pymodule]
fn pyprover(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProver>()?;
    Ok(())
}
