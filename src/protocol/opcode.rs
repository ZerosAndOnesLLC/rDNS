/// DNS opcodes (RFC 1035 Section 4.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,  // Inverse Query (obsolete)
    Status = 2,
    Notify = 4,  // RFC 1996
    Update = 5,  // RFC 2136
    Unknown(u8),
}

impl From<u8> for Opcode {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Query,
            1 => Self::IQuery,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            v => Self::Unknown(v),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(val: Opcode) -> u8 {
        match val {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Unknown(v) => v,
        }
    }
}
