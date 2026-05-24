pub mod proto {
    tonic::include_proto!("proto");
}

pub use proto::*;

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    const RUST_PROTO: &str = include_str!("../proto/nezha.proto");
    const GO_AGENT_PROTO: &str = include_str!("../../../upstream/agent/proto/nezha.proto");
    const GO_DASHBOARD_PROTO: &str = include_str!("../../../upstream/nezha/proto/nezha.proto");

    #[test]
    fn go_dashboard_proto_matches_rust_agent_contract() {
        assert_eq!(
            normalized_proto(RUST_PROTO),
            normalized_proto(GO_DASHBOARD_PROTO)
        );
        assert_service_shape(GO_DASHBOARD_PROTO);
    }

    #[test]
    fn rust_dashboard_proto_matches_go_agent_contract() {
        assert_eq!(
            normalized_proto(RUST_PROTO),
            normalized_proto(GO_AGENT_PROTO)
        );
        assert_service_shape(GO_AGENT_PROTO);
    }

    #[test]
    fn task_wire_tags_match_go_generated_protocol() {
        let task = Task {
            id: 150,
            r#type: 7,
            data: "abc".into(),
        };
        let mut encoded = Vec::new();
        task.encode(&mut encoded).unwrap();

        assert_eq!(
            encoded,
            vec![
                0x08, 0x96, 0x01, // id = 150
                0x10, 0x07, // type = 7
                0x1a, 0x03, b'a', b'b', b'c', // data = "abc"
            ]
        );
    }

    #[test]
    fn geoip_wire_tags_match_go_generated_protocol() {
        let geoip = GeoIp {
            use6: true,
            ip: Some(Ip {
                ipv4: "1.1.1.1".into(),
                ipv6: "::1".into(),
            }),
            country_code: "US".into(),
            dashboard_boot_time: 42,
        };
        let mut encoded = Vec::new();
        geoip.encode(&mut encoded).unwrap();

        assert_eq!(
            encoded,
            vec![
                0x08, 0x01, // use6 = true
                0x12, 0x0e, // ip message, 14 bytes
                0x0a, 0x07, b'1', b'.', b'1', b'.', b'1', b'.', b'1', 0x12, 0x03, b':', b':', b'1',
                0x1a, 0x02, b'U', b'S', // country_code = "US"
                0x20, 0x2a, // dashboard_boot_time = 42
            ]
        );
    }

    fn normalized_proto(raw: &str) -> String {
        raw.replace("\r\n", "\n")
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_service_shape(raw: &str) {
        for rpc in [
            "rpc ReportSystemState(stream State) returns (stream Receipt)",
            "rpc ReportSystemInfo(Host) returns (Receipt)",
            "rpc RequestTask(stream TaskResult) returns (stream Task)",
            "rpc IOStream(stream IOStreamData) returns (stream IOStreamData)",
            "rpc ReportGeoIP(GeoIP) returns (GeoIP)",
            "rpc ReportSystemInfo2(Host) returns (Uint64Receipt)",
        ] {
            assert!(raw.contains(rpc), "{rpc}");
        }
    }
}
