use rstest::rstest;
use ssh_agent_lib::proto::Message;
use ssh_encoding::{Decode /*, Encode*/};
use std::path::PathBuf;
use testresult::TestResult;

#[rstest]
fn main(#[files("tests/messages/*.bin")] path: PathBuf) -> TestResult {
    let bytes = std::fs::read(path)?;
    let mut bytes: &[u8] = &bytes;
    let _message = Message::decode(&mut bytes)?;
    // FIXME: Uncomment when the roundtrip works
    //let mut out = vec![];
    //message.encode(&mut out)?;
    //assert_eq!(bytes, out);
    Ok(())
}
