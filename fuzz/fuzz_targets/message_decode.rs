#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_agent_lib::proto::message::Message;
use ssh_encoding::Decode;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(&mut &data[..]);
});
