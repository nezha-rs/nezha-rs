use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum TaskType {
    HttpGet = 1,
    IcmpPing = 2,
    TcpPing = 3,
    Command = 4,
    Terminal = 5,
    Upgrade = 6,
    Keepalive = 7,
    TerminalGrpc = 8,
    Nat = 9,
    ReportHostInfoDeprecated = 10,
    FileManager = 11,
    ReportConfig = 12,
    ApplyConfig = 13,
}

impl TaskType {
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::HttpGet),
            2 => Some(Self::IcmpPing),
            3 => Some(Self::TcpPing),
            4 => Some(Self::Command),
            5 => Some(Self::Terminal),
            6 => Some(Self::Upgrade),
            7 => Some(Self::Keepalive),
            8 => Some(Self::TerminalGrpc),
            9 => Some(Self::Nat),
            10 => Some(Self::ReportHostInfoDeprecated),
            11 => Some(Self::FileManager),
            12 => Some(Self::ReportConfig),
            13 => Some(Self::ApplyConfig),
            _ => None,
        }
    }

    pub fn as_u64(self) -> u64 {
        self as u64
    }
}
