#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_agent_lib::{proto::message::Request, ssh_encoding::Decode as _};

fuzz_target!(|data: &[u8]| {
    let _ = Request::decode(&mut &data[..]);
});
