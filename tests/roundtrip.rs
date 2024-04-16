use std::path::PathBuf;

use rstest::rstest;
use ssh_agent_lib::proto::{Request, Response};
use ssh_encoding::{Decode, Encode};
use testresult::TestResult;

fn roundtrip<T: Decode + Encode + std::fmt::Debug>(path: PathBuf) -> TestResult
where
    T::Error: std::fmt::Display,
{
    let serialized = std::fs::read(path)?;
    let mut bytes: &[u8] = &serialized;
    let message = T::decode(&mut bytes)?;
    eprintln!("Message: {message:#?}");
    let mut out = vec![];
    message.encode(&mut out)?;
    assert_eq!(serialized, out);
    Ok(())
}

#[rstest]
fn roundtrip_requests(#[files("tests/messages/req-*.bin")] path: PathBuf) -> TestResult {
    roundtrip::<Request>(path)
}

#[rstest]
fn roundtrip_responses(#[files("tests/messages/resp-*.bin")] path: PathBuf) -> TestResult {
    roundtrip::<Response>(path)
}
