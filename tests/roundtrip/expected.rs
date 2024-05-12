#[macro_use]
mod macros;

use ssh_agent_lib::proto::{Request, Response};

// This macro generates a function with the following signature:
//
// `fn request(path: impl AsRef<Path>) -> Option<Request>`
//
// When called, it will take the filename without extension from the provided path (replacing any
// dashes with underscores) and compare that string to the list of modules in the bracketed list.
// If one of the listed modules matches the filename (e.g. `req-example-test.bin`), the function
// `req_example_test::expected()` will be called, which must have the signature `pub fn expected()
// -> Request`. (If none of the modules match the filename, `None` will be returned.)
//
// The roundtrip test code calls this to enhance `Encode`/`Decode` roundtrip tests with a known
// static object that must match the deserialized bytes.
//
// The macro also declares the listed modules.
make_expected_fn!(request -> Request, {
});

make_expected_fn!(response -> Response, {
});
