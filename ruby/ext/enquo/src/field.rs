//! Everything related to `Enquo::Field`
//!

use enquo_core::{
    datatype::{Boolean, Date, Text, I64},
    Error,
};
use magnus::{
    class, eval, exception, function, method,
    prelude::*,
    scan_args::{get_kwargs, scan_args},
    RClass, RModule, RString, TryConvert,
};
use std::ops::Deref;

use crate::{maybe_raise, string_to_bytes};

/// Wrapper struct for the `enquo_core` `Field` struct
#[magnus::wrap(class = "Enquo::Field")]
pub(crate) struct Field(pub(crate) enquo_core::Field);

impl Deref for Field {
    type Target = enquo_core::Field;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The results of parsing all the various options that can be passed when encrypting a value
struct EncryptOpts<T>
where
    T: TryConvert,
{
    /// The value to be encrypted
    input: T,
    /// The encryption context
    context: Vec<u8>,
    /// Whether the ciphertext should be created with unsafe parts included
    unsafe_ok: bool,
    /// Whether the ciphertext should have all querying portions removed
    no_query: bool,
    /// (Text only) how long to make the ordering code
    order_prefix_length: Option<u8>,
}

/// Convert *actual* Ruby booleans into Rust `bool`
///
/// Magnus supports converting into a Rust `bool`, but it takes Ruby's extremely laissez-faire
/// approach, where basically everything is `true` unless it's strictly defined as `false`
/// (basically just `false` and `nil`).
///
/// I, on the other hand, want to accept only *actual booleans* when encrypting a bool, so... here
/// we are.
///
fn strict_bool(value: Option<magnus::Value>, e: &str) -> Result<Option<bool>, magnus::Error> {
    match value {
        None => Ok(None),
        Some(v) => {
            if v.is_kind_of(class::true_class()) {
                Ok(Some(true))
            } else if v.is_kind_of(class::false_class()) {
                Ok(Some(false))
            } else {
                Err(magnus::Error::new(
                    exception::type_error(),
                    format!("{e} (got an instance of {})", v.class().inspect()),
                ))
            }
        }
    }
}

/// Convert *actual* Ruby Integers into Rust integer types
///
/// Magnus will accept various floaty-type things and truncate them into integers, which we really,
/// absolutely, do not want.
///
fn strict_int<T: TryConvert>(
    value: Option<magnus::Value>,
    e: &str,
) -> Result<Option<T>, magnus::Error> {
    match value {
        None => Ok(None),
        Some(v) => {
            if v.is_kind_of(class::integer()) {
                Ok(Some(v.try_convert::<T>()?))
            } else {
                Err(magnus::Error::new(
                    exception::type_error(),
                    format!("{e} (got an instance of {})", v.class().inspect()),
                ))
            }
        }
    }
}

/// Transmogrify the range of options that can be passed to an encrypt function into a more
/// appealing structure
///
fn parse_encrypt_args<T>(args: &[magnus::Value]) -> Result<EncryptOpts<T>, magnus::Error>
where
    T: TryConvert,
{
    let args = scan_args::<_, (), (), (), _, ()>(args)?;
    let (input, context_str): (T, RString) = args.required;

    let kwargs = get_kwargs::<_, (), _, ()>(
        args.keywords,
        &[],
        &["unsafe", "no_query", "order_prefix_length"],
    )?;

    let (unsafe_ok_val, no_query_val, order_prefix_length_val): (
        Option<magnus::Value>,
        Option<magnus::Value>,
        Option<magnus::Value>,
    ) = kwargs.optional;

    let unsafe_ok = strict_bool(unsafe_ok_val, "unsafe can only accept booleans")?.unwrap_or(false);
    let no_query = strict_bool(no_query_val, "no_query can only accept booleans")?.unwrap_or(false);
    let order_prefix_length = strict_int(
        order_prefix_length_val,
        "order_prefix_length must be an Integer",
    )?;

    Ok(EncryptOpts::<T> {
        input,
        context: string_to_bytes(context_str),
        unsafe_ok,
        no_query,
        order_prefix_length,
    })
}

#[allow(clippy::missing_docs_in_private_items)] // I think the names speak for themselves, really
impl Field {
    fn key_id(&self) -> Result<String, magnus::Error> {
        maybe_raise(self.0.key_id().map(hex::encode), None)
    }

    fn encrypt_boolean(&self, args: &[magnus::Value]) -> Result<String, magnus::Error> {
        let opts = parse_encrypt_args::<magnus::Value>(args)?;

        let b = strict_bool(
            Some(opts.input),
            "Enquo::Field#encrypt_boolean can only encrypt booleans",
        )?
        .ok_or_else(|| {
            magnus::Error::new(
                exception::runtime_error(),
                "CAN'T HAPPEN: got None from strict_bool(Some(opts.input))",
            )
        })?;

        let mut res = maybe_raise(
            if opts.unsafe_ok {
                Boolean::new_with_unsafe_parts(b, &opts.context, self)
            } else {
                Boolean::new(b, &opts.context, self)
            },
            None,
        )?;

        if opts.no_query {
            maybe_raise(res.make_unqueryable(), None)?;
        }

        maybe_raise(
            serde_json::to_string(&res),
            Some("failed to encode ciphertext"),
        )
    }

    #[allow(clippy::needless_pass_by_value)] // Magnus is not friends with &str args
    fn decrypt_boolean(&self, ciphertext: String, context: String) -> Result<bool, magnus::Error> {
        let ct: Boolean = maybe_raise(
            serde_json::from_str(&ciphertext),
            Some("failed to decode ciphertext"),
        )?;

        maybe_raise(ct.decrypt(context.as_bytes(), self), None)
    }

    fn encrypt_i64(&self, args: &[magnus::Value]) -> Result<String, magnus::Error> {
        let opts = parse_encrypt_args::<magnus::Value>(args)?;

        // Yes, I am aware that Magnus will turn anything that responds to
        // `#to_int` into an i64, but that includes instances of Float, and...
        // well, nope.
        let i: i64 = if opts.input.is_kind_of(class::integer()) {
            opts.input.try_convert()
        } else {
            Err(magnus::Error::new(
                exception::type_error(),
                format!(
                    "Enquo::Field#encrypt_i64 can only encrypt Integers (got an instance of {})",
                    opts.input.class().inspect()
                ),
            ))
        }?;

        let mut res = maybe_raise(
            if opts.unsafe_ok {
                I64::new_with_unsafe_parts(i, &opts.context, self)
            } else {
                I64::new(i, &opts.context, self)
            },
            None,
        )?;

        if opts.no_query {
            maybe_raise(res.make_unqueryable(), None)?;
        }

        maybe_raise(
            serde_json::to_string(&res),
            Some("failed to encode ciphertext"),
        )
    }

    #[allow(clippy::needless_pass_by_value)] // Magnus is not friends with &str args
    fn decrypt_i64(&self, ciphertext: String, context: String) -> Result<i64, magnus::Error> {
        let ct: I64 = maybe_raise(
            serde_json::from_str(&ciphertext),
            Some("failed to decode ciphertext"),
        )?;

        maybe_raise(ct.decrypt(context.as_bytes(), self), None)
    }

    fn encrypt_date(&self, args: &[magnus::Value]) -> Result<String, magnus::Error> {
        let opts = parse_encrypt_args::<magnus::Value>(args)?;

        // Safe as we're not storing the result of classname
        if opts.input.class().inspect() != "Date" {
            return Err(magnus::Error::new(
                exception::type_error(),
                format!(
                    "Enquo::Field#encrypt_date can only encrypt Date objects (got instance of {})",
                    opts.input.class().inspect()
                ),
            ));
        }

        let y: i16 = opts.input.funcall("year", ())?;
        let m: u8 = opts.input.funcall("month", ())?;
        let d: u8 = opts.input.funcall("day", ())?;

        let mut res = maybe_raise(
            if opts.unsafe_ok {
                Date::new_with_unsafe_parts((y, m, d), &opts.context, self)
            } else {
                Date::new((y, m, d), &opts.context, self)
            },
            None,
        )?;

        if opts.no_query {
            maybe_raise(res.make_unqueryable(), None)?;
        }

        maybe_raise(
            serde_json::to_string(&res),
            Some("failed to encode ciphertext"),
        )
    }

    #[allow(clippy::needless_pass_by_value)] // Magnus is not friends with &str args
    fn decrypt_date(
        &self,
        ciphertext: String,
        context: String,
    ) -> Result<magnus::Value, magnus::Error> {
        let ct: Date = maybe_raise(
            serde_json::from_str(&ciphertext),
            Some("failed to decode ciphertext"),
        )?;

        let (y, m, d) = maybe_raise(ct.decrypt(context.as_bytes(), self), None)?;

        let date_class = maybe_raise(
            RClass::from_value(eval("::Date")?).ok_or_else(|| {
                Error::OperationError("failed to get RClass from Date value".to_string())
            }),
            None,
        )?;

        date_class.new_instance((y, m, d))
    }

    fn encrypt_text(&self, args: &[magnus::Value]) -> Result<String, magnus::Error> {
        let opts = parse_encrypt_args::<magnus::Value>(args)?;

        // Yes, I am aware that Magnus will turn anything that responds to
        // `#to_s` into a String if we ask it to, but we want to be far more strict,
        // and only allow actual Ruby String objects to be passed in.
        let t: String = if opts.input.is_kind_of(class::string()) {
            opts.input.try_convert::<RString>()?.to_string()
        } else {
            Err(magnus::Error::new(
                exception::type_error(),
                format!(
                    "Enquo::Field#encrypt_text can only encrypt Strings (got an instance of {})",
                    opts.input.class().inspect()
                ),
            ))
        }?;

        let mut res = maybe_raise(
            if opts.unsafe_ok {
                Text::new_with_unsafe_parts(&t, &opts.context, self, opts.order_prefix_length)
            } else if opts.order_prefix_length.is_some() {
                return Err(magnus::Error::new(exception::arg_error(), "Cannot specify an order_prefix_length unless reduced_security_operations is set"));
            } else {
                Text::new(&t, &opts.context, self)
            },
            None,
        )?;

        if opts.no_query {
            maybe_raise(res.make_unqueryable(), None)?;
        }

        maybe_raise(
            serde_json::to_string(&res),
            Some("failed to encode ciphertext"),
        )
    }

    #[allow(clippy::needless_pass_by_value)] // Magnus is not friends with &str args
    fn decrypt_text(&self, ciphertext: String, context: String) -> Result<String, magnus::Error> {
        let ct: Text = maybe_raise(
            serde_json::from_str(&ciphertext),
            Some("failed to decode ciphertext"),
        )?;

        maybe_raise(ct.decrypt(context.as_bytes(), self), None)
    }

    fn encrypt_text_length_query(&self, len: u32) -> Result<String, magnus::Error> {
        let value_set = maybe_raise(Text::query_length(len, self), None)?;
        maybe_raise(
            serde_json::to_string(&value_set),
            Some("failed to encode value set"),
        )
    }
}

/// Create the Field class and setup all its methods
pub(crate) fn init(base: RModule) -> Result<(), magnus::Error> {
    let class = base.define_class("Field", class::object())?;

    class.define_singleton_method(
        "new",
        function!(
            || -> Result<(), _> {
                Err(magnus::Error::new(
                    exception::no_method_error(),
                    "Enquo::Field.new should not be called directly; use Enquo::Root#field instead"
                        .to_string(),
                ))
            },
            0
        ),
    )?;
    class.define_method("key_id", method!(Field::key_id, 0))?;
    class.define_method("encrypt_boolean", method!(Field::encrypt_boolean, -1))?;
    class.define_method("decrypt_boolean", method!(Field::decrypt_boolean, 2))?;
    class.define_method("encrypt_date", method!(Field::encrypt_date, -1))?;
    class.define_method("decrypt_date", method!(Field::decrypt_date, 2))?;
    class.define_method("encrypt_i64", method!(Field::encrypt_i64, -1))?;
    class.define_method("decrypt_i64", method!(Field::decrypt_i64, 2))?;
    class.define_method("encrypt_text", method!(Field::encrypt_text, -1))?;
    class.define_method("decrypt_text", method!(Field::decrypt_text, 2))?;
    class.define_method(
        "encrypt_text_length_query",
        method!(Field::encrypt_text_length_query, 1),
    )?;

    Ok(())
}
