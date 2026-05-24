use serde::{Deserialize, Serialize};

use nezha_proto::{GeoIp as PbGeoIp, Host as PbHost, Ip as PbIp, State as PbState};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SensorTemperature {
    pub name: String,
    pub temperature: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HostState {
    pub cpu: f64,
    pub mem_used: u64,
    pub swap_used: u64,
    pub disk_used: u64,
    pub net_in_transfer: u64,
    pub net_out_transfer: u64,
    pub net_in_speed: u64,
    pub net_out_speed: u64,
    pub uptime: u64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub tcp_conn_count: u64,
    pub udp_conn_count: u64,
    pub process_count: u64,
    pub temperatures: Vec<SensorTemperature>,
    pub gpu: Vec<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Host {
    pub platform: String,
    pub platform_version: String,
    pub cpu: Vec<String>,
    pub mem_total: u64,
    pub disk_total: u64,
    pub swap_total: u64,
    pub arch: String,
    pub virtualization: String,
    pub boot_time: u64,
    pub version: String,
    pub gpu: Vec<String>,
}

impl Host {
    pub fn filtered(&self) -> Self {
        Self {
            platform: self.platform.clone(),
            platform_version: String::new(),
            cpu: self.cpu.clone(),
            mem_total: self.mem_total,
            disk_total: self.disk_total,
            swap_total: self.swap_total,
            arch: self.arch.clone(),
            virtualization: self.virtualization.clone(),
            boot_time: self.boot_time,
            version: String::new(),
            gpu: self.gpu.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ip {
    pub ipv4_addr: String,
    pub ipv6_addr: String,
}

impl Ip {
    pub fn join(&self) -> String {
        match (self.ipv4_addr.is_empty(), self.ipv6_addr.is_empty()) {
            (false, false) => format!("{}/{}", self.ipv4_addr, self.ipv6_addr),
            (false, true) => self.ipv4_addr.clone(),
            (true, false) => self.ipv6_addr.clone(),
            (true, true) => String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoIp {
    pub ip: Ip,
    pub country_code: String,
}

impl From<PbHost> for Host {
    fn from(value: PbHost) -> Self {
        Self {
            platform: value.platform,
            platform_version: value.platform_version,
            cpu: value.cpu,
            mem_total: value.mem_total,
            disk_total: value.disk_total,
            swap_total: value.swap_total,
            arch: value.arch,
            virtualization: value.virtualization,
            boot_time: value.boot_time,
            version: value.version,
            gpu: value.gpu,
        }
    }
}

impl From<Host> for PbHost {
    fn from(value: Host) -> Self {
        Self {
            platform: value.platform,
            platform_version: value.platform_version,
            cpu: value.cpu,
            mem_total: value.mem_total,
            disk_total: value.disk_total,
            swap_total: value.swap_total,
            arch: value.arch,
            virtualization: value.virtualization,
            boot_time: value.boot_time,
            version: value.version,
            gpu: value.gpu,
        }
    }
}

impl From<PbState> for HostState {
    fn from(value: PbState) -> Self {
        Self {
            cpu: value.cpu,
            mem_used: value.mem_used,
            swap_used: value.swap_used,
            disk_used: value.disk_used,
            net_in_transfer: value.net_in_transfer,
            net_out_transfer: value.net_out_transfer,
            net_in_speed: value.net_in_speed,
            net_out_speed: value.net_out_speed,
            uptime: value.uptime,
            load1: value.load1,
            load5: value.load5,
            load15: value.load15,
            tcp_conn_count: value.tcp_conn_count,
            udp_conn_count: value.udp_conn_count,
            process_count: value.process_count,
            temperatures: value
                .temperatures
                .into_iter()
                .map(|t| SensorTemperature {
                    name: t.name,
                    temperature: t.temperature,
                })
                .collect(),
            gpu: value.gpu,
        }
    }
}

impl From<HostState> for PbState {
    fn from(value: HostState) -> Self {
        Self {
            cpu: value.cpu,
            mem_used: value.mem_used,
            swap_used: value.swap_used,
            disk_used: value.disk_used,
            net_in_transfer: value.net_in_transfer,
            net_out_transfer: value.net_out_transfer,
            net_in_speed: value.net_in_speed,
            net_out_speed: value.net_out_speed,
            uptime: value.uptime,
            load1: value.load1,
            load5: value.load5,
            load15: value.load15,
            tcp_conn_count: value.tcp_conn_count,
            udp_conn_count: value.udp_conn_count,
            process_count: value.process_count,
            temperatures: value
                .temperatures
                .into_iter()
                .map(|t| nezha_proto::StateSensorTemperature {
                    name: t.name,
                    temperature: t.temperature,
                })
                .collect(),
            gpu: value.gpu,
        }
    }
}

impl From<PbGeoIp> for GeoIp {
    fn from(value: PbGeoIp) -> Self {
        let ip = value.ip.unwrap_or_default();
        Self {
            ip: Ip {
                ipv4_addr: ip.ipv4,
                ipv6_addr: ip.ipv6,
            },
            country_code: value.country_code,
        }
    }
}

impl From<GeoIp> for PbGeoIp {
    fn from(value: GeoIp) -> Self {
        Self {
            use6: false,
            ip: Some(PbIp {
                ipv4: value.ip.ipv4_addr,
                ipv6: value.ip.ipv6_addr,
            }),
            country_code: value.country_code,
            dashboard_boot_time: 0,
        }
    }
}
