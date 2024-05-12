//!
//! The macro in this file takes 3 arguments:
//!     1. The name of the function to generate
//!     2. The return type of the function
//!     3. A brace-enclosed, comma-separated list of module
//!        names
//!
//!  Each module in (3) should match the basename of a file in `tests/messages` but with dashes
//!  replaced by underscores to make it a valid Rust identifier. When the generated function is
//!  called with a filename that matches one of these modules, it will call the `expected()`
//!  function of that module, which should return an object of the return type specified in the
//!  macro, which will be returned as Some(expected()). If the generated function is called with a
//!  filename that does not match any module, it will return `None`.
//!
//!  # Example #
//!
//!  ## Macro call ##
//!
//!  ```ignore
//!  use ssh_agent_lib::proto::Request;
//!
//!  make_expected_fn!(get_expected_request -> Request, {
//!      req_hello
//!  });
//!  ```
//!
//!  ## Usage of generated function in test code ##
//!
//!  ```ignore
//!  let test_data_path = PathBuf::from("test/messages/req-hello.bin");
//!  if let Some(expected) = path::to::get_expected_request(&test_data_path) {
//!      assert_eq!(expected, ...);
//!  }
//!  ```
//!
//!  ## `path/to/req_hello.rs` ##
//!
//!  ```ignore
//!  pub fn expected() -> Request {
//!      ...
//!  }
//!  ```

macro_rules! make_expected_fn {
    ($fn_name:ident -> $ty:ty, { $($case:ident),+ } ) => {
        $( mod $case; )+

        pub fn $fn_name(path: impl ::core::convert::AsRef<::std::path::Path>) -> ::core::option::Option<$ty> {
            let cases: &[(&str, &dyn ::core::ops::Fn() -> $ty)] = &[
                $( (::core::stringify!($case), &self::$case::expected,) ),+
            ];

            let path_case_name = path
                .as_ref()
                .file_stem()
                .expect("test path has no filename")
                .to_str()
                .expect("test filename not UTF-8")
                .replace("-", "_");

            cases
                .into_iter()
                .find(|(c, _)| c == &path_case_name)
                .map(|(_, f)| f())
        }
    };
}
