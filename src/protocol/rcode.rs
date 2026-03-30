/// DNS response codes (RFC 1035 Section 4.1.1, extended by RFC 6895)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,   // Format error
    ServFail = 2,  // Server failure
    NxDomain = 3,  // Name does not exist
    NotImp = 4,    // Not implemented
    Refused = 5,   // Query refused
    YxDomain = 6,  // Name exists when it should not
    YxRrset = 7,   // RR set exists when it should not
    NxRrset = 8,   // RR set does not exist when it should
    NotAuth = 9,   // Not authorized
    NotZone = 10,  // Name not in zone
    Unknown(u8),
}

impl From<u8> for Rcode {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRrset,
            8 => Self::NxRrset,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            v => Self::Unknown(v),
        }
    }
}

impl From<Rcode> for u8 {
    fn from(val: Rcode) -> u8 {
        match val {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NxDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::YxDomain => 6,
            Rcode::YxRrset => 7,
            Rcode::NxRrset => 8,
            Rcode::NotAuth => 9,
            Rcode::NotZone => 10,
            Rcode::Unknown(v) => v,
        }
    }
}
