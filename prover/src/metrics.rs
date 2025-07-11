use std::net::{IpAddr, SocketAddr};
// third-party
use metrics_exporter_prometheus::PrometheusBuilder;
// use metrics_util::MetricKindMask;
use tracing::{
    // debug,
    // error,
    info,
};

pub struct Metric {
    pub name: &'static str,
    description: &'static str,
}

pub const USER_REGISTERED_REQUESTS: Metric = Metric {
    name: "user_registered_requests",
    description: "",
};
pub const USER_REGISTERED: Metric = Metric {
    name: "user_registered",
    description: "",
};

pub const COUNTERS: [Metric; 2] = [USER_REGISTERED, USER_REGISTERED_REQUESTS];
pub const GAUGES: [Metric; 0] = [];
pub const HISTOGRAMS: [Metric; 0] = [];

pub fn init_metrics(ip: IpAddr, port: &u16) {
    info!("Initializing metrics exporter (port: {})", port);

    // Install in the current tokio runtime
    PrometheusBuilder::new()
        // .idle_timeout(
        //     MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
        //     Some(Duration::from_secs(10)),
        // )
        .with_http_listener(SocketAddr::new(
            // IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ip,
            port.to_owned(),
        ))
        .install()
        .expect("failed to install Prometheus recorder");

    for name in COUNTERS {
        register_counter(name)
    }

    for name in GAUGES {
        register_gauge(name)
    }

    for name in HISTOGRAMS {
        register_histogram(name)
    }
}

/// Registers a counter with the given name.
fn register_counter(metric: Metric) {
    metrics::describe_counter!(metric.name, metric.description);
    let _counter = metrics::counter!(metric.name);
}

/// Registers a gauge with the given name.
fn register_gauge(metric: Metric) {
    metrics::describe_gauge!(metric.name, metric.description);
    let _gauge = ::metrics::gauge!(metric.name);
}

/// Registers a histogram with the given name.
fn register_histogram(metric: Metric) {
    metrics::describe_histogram!(metric.name, metric.description);
    let _histogram = ::metrics::histogram!(metric.name);
}
