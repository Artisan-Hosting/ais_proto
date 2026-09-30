//! Generated *messages only*, for the wire-format pin tests in `tests/`.
//! Nothing outside this package depends on it.

pub mod secret_service {
    include!(concat!(env!("OUT_DIR"), "/secret_service.rs"));
}
pub mod session_manager {
    include!(concat!(env!("OUT_DIR"), "/session_manager.rs"));
}
pub mod accounts {
    include!(concat!(env!("OUT_DIR"), "/accounts.rs"));
}
pub mod billing {
    include!(concat!(env!("OUT_DIR"), "/billing.rs"));
}

pub mod domains {
    include!(concat!(env!("OUT_DIR"), "/domains.rs"));
}

/// The compiled descriptor set of all five files.
pub const DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));
