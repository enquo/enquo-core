#[macro_use]
extern crate rutie;

use enquo_core::{key_provider, Boolean, Date, Field, Root, Text, I64};
use rutie::{
    AnyObject, Boolean as RBoolean, Class, Integer, Module, Object, RString, Symbol,
    VerifiedObject, VM,
};

class!(EnquoRoot);
class!(EnquoRootKeyStatic);
class!(EnquoField);

wrappable_struct!(Root<'static>, RootWrapper, ROOT_WRAPPER);
wrappable_struct!(
    key_provider::Static,
    StaticRootKeyWrapper,
    STATIC_ROOT_KEY_WRAPPER
);
wrappable_struct!(Field, FieldWrapper, FIELD_WRAPPER);

fn maybe_raise<T, E: std::error::Error>(r: Result<T, E>, s: &str) -> T {
    r.map_err(|e| {
        VM::raise(
            Class::from_existing("Enquo").get_nested_class("Error"),
            &format!("{s}: {e}"),
        )
    })
    .unwrap()
}

unsafe_methods!(
    EnquoRoot,
    rbself,
    fn enquo_root_new_from_static_root_key(root_key_obj: EnquoRootKeyStatic) -> EnquoRoot {
        let rk = root_key_obj.get_data(&*STATIC_ROOT_KEY_WRAPPER);
        let root = maybe_raise(Root::new(rk), "Failed to create Enquo::Root");

        let klass = Module::from_existing("Enquo").get_nested_class("Root");
        klass.wrap_data(root, &*ROOT_WRAPPER)
    },
    fn enquo_root_field(relation_obj: RString, name_obj: RString) -> EnquoField {
        let relation = relation_obj.to_vec_u8_unchecked();
        let name = name_obj.to_vec_u8_unchecked();

        let root = rbself.get_data(&*ROOT_WRAPPER);

        let field = maybe_raise(
            root.field(&relation, &name),
            "Failed to create Enquo::Field",
        );

        let klass = Module::from_existing("Enquo").get_nested_class("Field");
        klass.wrap_data(field, &*FIELD_WRAPPER)
    }
);

unsafe_methods!(
    EnquoRootKeyStatic,
    _rbself,
    fn enquo_root_key_static_new(root_key_obj: RString) -> EnquoRootKeyStatic {
        let root_key = root_key_obj.to_vec_u8_unchecked();

        let k = key_provider::Static::new(&root_key);
        let klass = Module::from_existing("Enquo")
            .get_nested_class("RootKey")
            .get_nested_class("Static");
        klass.wrap_data(k, &*STATIC_ROOT_KEY_WRAPPER)
    },
);

impl VerifiedObject for EnquoRootKeyStatic {
    fn is_correct_type<T: Object>(object: &T) -> bool {
        let klass = Module::from_existing("Enquo")
            .get_nested_class("RootKey")
            .get_nested_class("Static");
        klass.case_equals(object)
    }

    fn error_message() -> &'static str {
        "Provided object is not an Enquo::RootKey::Static instance"
    }
}

// rustfmt fucks this so it doesn't compile
#[rustfmt::skip]
unsafe_methods!(
    EnquoField,
    rbself,
    fn enquo_field_encrypt_bool(b_obj: RBoolean, context_obj: RString, mode_obj: Symbol) -> RString {
        let b = b_obj.to_bool();
        let context = context_obj.to_vec_u8_unchecked();
        let mode = mode_obj.to_str();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let mut res = maybe_raise(
            if mode == "unsafe" {
                Boolean::new_with_unsafe_parts(b, &context, field)
            } else {
                Boolean::new(b, &context, field)
            },
            "Failed to create encrypted bool",
        );
        if mode == "no_query" {
            res.make_unqueryable();
        }

        RString::new_utf8(&maybe_raise(serde_json::to_string(&res), "Failed to JSONify ciphertext"))
    },
    fn enquo_field_decrypt_bool(ciphertext_obj: RString, context_obj: RString) -> RBoolean {
        let ct = ciphertext_obj.to_str_unchecked();
        let context = context_obj.to_vec_u8_unchecked();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let e_value: Boolean =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");

        let value = maybe_raise(
            e_value.decrypt(&context, field),
            "Failed to decrypt bool value",
        );
        RBoolean::new(value)
    },
    fn enquo_field_encrypt_i64(i_obj: Integer, context_obj: RString, mode_obj: Symbol) -> RString {
        let i = i_obj.to_i64();
        let context = context_obj.to_vec_u8_unchecked();
        let mode = mode_obj.to_str();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let mut res = maybe_raise(
            if mode == "unsafe" {
                I64::new_with_unsafe_parts(i, &context, field)
            } else {
                I64::new(i, &context, field)
            },
            "Failed to create encrypted i64",
        );
        if mode == "no_query" {
            res.make_unqueryable();
        }

        RString::new_utf8(&maybe_raise(serde_json::to_string(&res), "Failed to JSONify ciphertext"))
    },
    fn enquo_field_decrypt_i64(ciphertext_obj: RString, context_obj: RString) -> Integer {
        let ct = ciphertext_obj.to_str_unchecked();
        let context = context_obj.to_vec_u8_unchecked();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let e_value: I64 =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");


        let value = maybe_raise(
            e_value.decrypt(&context, field),
            "Failed to decrypt i64 value",
        );
        Integer::from(value)
    },
    fn enquo_field_encrypt_date(
        y_obj: Integer,
        m_obj: Integer,
        d_obj: Integer,
        context_obj: RString,
        mode_obj: Symbol
    ) -> RString {
        let y = y_obj.to_i32() as i16;
        let m = m_obj.to_i32() as u8;
        let d = d_obj.to_i32() as u8;
        let context = context_obj.to_vec_u8_unchecked();
        let mode = mode_obj.to_str();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let mut res = maybe_raise(
            if mode == "unsafe" {
                Date::new_with_unsafe_parts(
                    (y, m, d),
                    &context,
                    field,
                )
            } else {
                Date::new((y, m, d), &context, field)
            },
            "Failed to create encrypted date",
        );
        if mode == "no_query" {
            res.make_unqueryable();
        }

        RString::new_utf8(&maybe_raise(serde_json::to_string(&res), "Failed to JSONify ciphertext"))
    },
    fn enquo_field_decrypt_date(ciphertext_obj: RString, context_obj: RString) -> AnyObject {
        let ct = ciphertext_obj.to_str_unchecked();
        let context = context_obj.to_vec_u8_unchecked();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let e_value: Date =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");

        let (y, m, d) = maybe_raise(
            e_value.decrypt(&context, field),
            "Failed to decrypt date value",
        );
        let klass = Class::from_existing("Date");
        let args: [AnyObject; 3] = [
            Integer::from(y as i32).into(),
            Integer::from(m as i32).into(),
            Integer::from(d as i32).into(),
        ];
        klass.protect_send("new", &args).unwrap()
    }
    fn enquo_field_encrypt_text(
        text_obj: RString,
        context_obj: RString,
        mode_obj: Symbol
    ) -> RString {
        let text = text_obj.to_str();
        let context = context_obj.to_vec_u8_unchecked();
        let mode = mode_obj.to_str();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let mut res = maybe_raise(
            if mode == "unsafe" {
                Text::new_with_unsafe_parts(
                    text,
                    &context,
                    field,
                )
            } else {
                Text::new(text, &context, field)
            },
            "Failed to create encrypted date",
        );
        if mode == "no_query" {
            res.make_unqueryable();
        }

        RString::new_utf8(&maybe_raise(serde_json::to_string(&res), "Failed to JSONify ciphertext"))
    },
    fn enquo_field_decrypt_text(ciphertext_obj: RString, context_obj: RString) -> RString {
        let ct = ciphertext_obj.to_str_unchecked();
        let context = context_obj.to_vec_u8_unchecked();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let e_value: Text =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");

        let s = maybe_raise(e_value.decrypt(&context, field), "Failed to decrypt text value");

        RString::new_utf8(&s)
    }
);

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Init_enquo() {
    Module::from_existing("Enquo").define(|topmod| {
        topmod
            .define_nested_class("Root", None)
            .define(|rootklass| {
                rootklass.singleton_class().def_private(
                    "_new_from_static_root_key",
                    enquo_root_new_from_static_root_key,
                );
                rootklass.def_private("_field", enquo_root_field);
            });
        topmod
            .define_nested_class("Field", None)
            .define(|fieldklass| {
                fieldklass.def_private("_encrypt_bool", enquo_field_encrypt_bool);
                fieldklass.def_private("_decrypt_bool", enquo_field_decrypt_bool);
                fieldklass.def_private("_encrypt_i64", enquo_field_encrypt_i64);
                fieldklass.def_private("_decrypt_i64", enquo_field_decrypt_i64);
                fieldklass.def_private("_encrypt_date", enquo_field_encrypt_date);
                fieldklass.def_private("_decrypt_date", enquo_field_decrypt_date);
                fieldklass.def_private("_encrypt_text", enquo_field_encrypt_text);
                fieldklass.def_private("_decrypt_text", enquo_field_decrypt_text);
            });
        topmod.define_nested_module("RootKey").define(|rkmod| {
            rkmod
                .define_nested_class("Static", None)
                .define(|statickeyklass| {
                    statickeyklass
                        .singleton_class()
                        .def_private("_new", enquo_root_key_static_new);
                });
        });
    });
}
