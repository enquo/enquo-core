mod field;
mod root;
mod root_key;

#[magnus::init]
fn init() -> Result<(), magnus::Error> {
    let base_mod = magnus::define_module("Enquo")?;

    root::init(&base_mod)?;
    root_key::init(&base_mod)?;
    field::init(&base_mod)?;

    Ok(())
}

fn enquo_exception() -> Result<magnus::ExceptionClass, magnus::Error> {
    magnus::ExceptionClass::from_value(magnus::eval("::Enquo::Error")?).ok_or_else(|| {
        magnus::Error::new(
            magnus::exception::runtime_error(),
            "failed to get RClass from Enquo::Error value".to_string(),
        )
    })
}

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
