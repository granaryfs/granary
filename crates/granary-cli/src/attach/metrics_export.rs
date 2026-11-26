// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Mount-side configuration and lifecycle for its metrics export.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use granary_client::{FailureClass, OperationKind, op_failed};
use granary_net::metrics_listener::{Configuration, Endpoint};

const FILE_CAP: u64 = 65_536;

#[derive(Debug, Default)]
pub(super) struct Options {
    endpoint: Option<Endpoint>,
    token: Option<PathBuf>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

impl Options {
    pub(super) fn configured(&self) -> bool {
        self.endpoint.is_some()
    }

    pub(super) fn option(&mut self, flag: &str, value: OsString) -> Result<(), String> {
        let duplicate = if flag == "--metrics-listen" {
            if self.endpoint.is_some() {
                true
            } else {
                let endpoint = value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--metrics-listen requires 127.0.0.1 or [::1] with a nonzero port")?;
                self.endpoint = Some(endpoint);
                false
            }
        } else {
            let path = match flag {
                "--metrics-token-file" => &mut self.token,
                "--metrics-tls-cert" => &mut self.cert,
                "--metrics-tls-key" => &mut self.key,
                _ => return Err("unknown metrics option".into()),
            };
            if value.is_empty() {
                return Err(format!("{flag} needs a nonempty file path"));
            }
            path.replace(value.into()).is_some()
        };
        if duplicate {
            return Err(format!("{flag} was given more than once"));
        }
        Ok(())
    }

    pub(super) fn check(&self) -> Result<(), String> {
        match [&self.token, &self.cert, &self.key].map(Option::is_some) {
            [true, true, true] if self.endpoint.is_some() => Ok(()),
            [false, false, false] if self.endpoint.is_none() => Ok(()),
            _ => Err("--metrics-listen, --metrics-token-file, --metrics-tls-cert and --metrics-tls-key are required together".into()),
        }
    }

    pub(super) fn prepare(&self, euid: u32) -> Result<Option<Configuration>, &'static str> {
        let (Some(endpoint), Some(token), Some(cert), Some(key)) =
            (self.endpoint, &self.token, &self.cert, &self.key)
        else {
            return Ok(None);
        };
        read_configuration(endpoint, token, cert, key, euid)
            .map(Some)
            .map_err(|(message, class)| {
                op_failed(OperationKind::Session, class);
                message
            })
    }
}

fn read_configuration(
    endpoint: Endpoint,
    token: &Path,
    cert: &Path,
    key: &Path,
    euid: u32,
) -> Result<Configuration, (&'static str, FailureClass)> {
    let refused = |message| (message, FailureClass::Refused);
    let failed = |message| (message, FailureClass::Io);
    let token = granary_client::open_private_key(token, euid, "metrics token")
        .map_err(|_| refused("metrics token file custody refused"))?;
    let token = read_bounded(token, 64).map_err(|error| match error.kind() {
        io::ErrorKind::InvalidData => refused("invalid metrics token file"),
        _ => failed("could not read metrics token file"),
    })?;
    let key = granary_client::open_private_key(key, euid, "metrics TLS key")
        .map_err(|_| refused("metrics tls key custody refused"))?;
    let key = read_bounded(key, FILE_CAP).map_err(|error| match error.kind() {
        io::ErrorKind::InvalidData => refused("metrics tls key exceeds 65536 bytes"),
        _ => failed("could not read metrics tls key"),
    })?;
    #[expect(
        clippy::disallowed_methods,
        reason = "open the public certificate once and check the descriptor before its bounded read"
    )]
    let cert = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(cert)
        .map_err(|_| failed("could not open metrics tls certificate"))?;
    if !cert
        .metadata()
        .map_err(|_| failed("could not inspect metrics tls certificate"))?
        .is_file()
    {
        return Err(refused("metrics tls certificate must be a regular file"));
    }
    let cert = read_bounded(cert, FILE_CAP).map_err(|error| match error.kind() {
        io::ErrorKind::InvalidData => refused("metrics tls certificate exceeds 65536 bytes"),
        _ => failed("could not read metrics tls certificate"),
    })?;
    Configuration::new(endpoint, &token, &cert, &key).map_err(|error| {
        use granary_net::metrics_listener::ConfigurationError;
        refused(match error {
            ConfigurationError::Address => "invalid metrics listener address",
            ConfigurationError::Token => "invalid metrics token file",
            ConfigurationError::Tls => "invalid metrics tls certificate or private key",
        })
    })
}

fn read_bounded(file: impl Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", test))]
fn start_with<T>(
    config: Option<Configuration>,
    metrics: &granary_client::ClientMetrics,
    bind: impl FnOnce(Configuration) -> Result<T, granary_net::metrics_listener::StartError>,
) -> Option<T> {
    let config = config?;
    metrics.set_metrics_listener_up(false);
    bind(config)
        .map_err(|_| {
            op_failed(OperationKind::Session, FailureClass::Io);
        })
        .ok()
}

#[cfg(target_os = "linux")]
pub(super) fn start(
    config: Option<Configuration>,
    metrics: &granary_client::ClientMetrics,
) -> Option<granary_net::metrics_listener::Listener> {
    use granary_net::metrics_listener::{self, Failure};
    start_with(config, metrics, |config| {
        let renderer = metrics.clone();
        let events = metrics.clone();
        metrics_listener::start(
            config,
            move || {
                let result = renderer
                    .snapshot()
                    .and_then(|snapshot| snapshot.render_prometheus())
                    .map(String::into_bytes)
                    .map_err(|_| Failure::Internal);
                std::future::ready(result)
            },
            move |event| record_event(&events, event),
        )
    })
}

#[cfg(any(target_os = "linux", test))]
fn record_event(
    metrics: &granary_client::ClientMetrics,
    event: granary_net::metrics_listener::Event,
) {
    use granary_client::{ClientEvent, MetricsFailureClass, ScrapeResult};
    use granary_net::metrics_listener::{Event, Failure, ScrapeResult as ConnectionResult};

    match event {
        Event::Started => metrics.set_metrics_listener_up(true),
        Event::Stopped => metrics.set_metrics_listener_up(false),
        Event::Failed(class) => {
            metrics.set_metrics_listener_up(false);
            ClientEvent::metrics_export_failed(match class {
                Failure::Io => MetricsFailureClass::Io,
                Failure::Internal => MetricsFailureClass::Internal,
            })
            .emit();
        }
        Event::Scrape(result) => metrics.record_metrics_scrape(match result {
            ConnectionResult::Ok => ScrapeResult::Ok,
            ConnectionResult::Refused => ScrapeResult::Refused,
            ConnectionResult::Limited => ScrapeResult::Limited,
            ConnectionResult::Failed | ConnectionResult::Cancelled => ScrapeResult::Failed,
        }),
    }
}

#[cfg(test)]
mod tests;
