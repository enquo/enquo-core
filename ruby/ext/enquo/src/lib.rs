//! Ruby extension for enquo-core
//!
//!

// magnus::init spews an error that I *cannot*, for the life of me, figure out how to suppress, so
// we'll just have to suppress it globally and remember to write docs where appropriate
#![allow(missing_docs)]

mod field;
mod root;
mod root_key;

/// Tell Ruby to initialise everything
#[magnus::init]
fn init() -> Result<(), magnus::Error> {
    let base_mod = magnus::define_module("Enquo")?;

    root::init(base_mod)?;
    root_key::init(base_mod)?;
    field::init(base_mod)?;

    Ok(())
}

/// Dig up the Enquo exception class
fn enquo_exception() -> Result<magnus::ExceptionClass, magnus::Error> {
    magnus::ExceptionClass::from_value(magnus::eval("::Enquo::Error")?).ok_or_else(|| {
        magnus::Error::new(
            magnus::exception::runtime_error(),
            "failed to get RClass from Enquo::Error value".to_string(),
        )
    })
}

/// Check if the value passed in is an error, and if so, turn it into something that Magnus will
/// recognise as an Enquo exception to be raised.
fn maybe_raise<T, E: std::error::Error>(
    r: Result<T, E>,
    s: Option<&str>,
) -> Result<T, magnus::Error> {
    let ex_class = enquo_exception()?;

    r.map_err(|e| {
        magnus::Error::new(
            ex_class,
            match &s {
                None => e.to_string(),
                Some(s) => format!("{s}: {e}"),
            },
        )
    })
}

/// Turn an `RString`'s contents into a Vec<u8>
///
/// Useful when the string's contents aren't UTF-8 text, or we just want to muck around with it in
/// some low-levelish way.  Strange that Magnus doesn't seem to have a safe function already to do
/// this.
fn string_to_bytes(s: magnus::RString) -> Vec<u8> {
    #[allow(unsafe_code)]
    // SAFETY: we don't let Ruby GC while we hold the ref
    unsafe {
        s.as_slice().to_owned()
    }
}
