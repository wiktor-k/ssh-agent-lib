use std::path::PathBuf;

use rstest::rstest;
use ssh_agent_lib::proto::Message;
use ssh_encoding::{Decode, Encode};
use testresult::TestResult;

#[rstest]
fn roundtrip(#[files("tests/messages/*.bin")] path: PathBuf) -> TestResult {
    let serialized = std::fs::read(path)?;
    let mut bytes: &[u8] = &serialized;
    let message = Message::decode(&mut bytes)?;
    let mut out = vec![];
    message.encode(&mut out)?;
    assert_eq!(serialized, out);
    Ok(())
}
