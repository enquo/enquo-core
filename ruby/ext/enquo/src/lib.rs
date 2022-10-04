#[macro_use]
extern crate rutie;

use enquo_core::{Date, Field, Root, I64};
use rutie::{AnyObject, Class, Integer, Module, Object, RString, Symbol, VerifiedObject, VM};

class!(EnquoRoot);
class!(EnquoRootKeyStatic);
class!(EnquoField);

type StaticRootKey = Vec<u8>;

wrappable_struct!(Root<'static>, RootWrapper, ROOT_WRAPPER);
wrappable_struct!(StaticRootKey, StaticRootKeyWrapper, STATIC_ROOT_KEY_WRAPPER);
wrappable_struct!(Field, FieldWrapper, FIELD_WRAPPER);

fn maybe_raise<T, E: std::error::Error>(r: Result<T, E>, s: &str) -> T {
    r.map_err(|e| {
        VM::raise(
            Class::from_existing("Enquo").get_nested_class("Error"),
            &format!("{}: {}", s, e),
        )
    })
    .unwrap()
}

methods!(
    EnquoRoot,
    rbself,
    fn enquo_root_new_from_static_root_key(root_key_obj: EnquoRootKeyStatic) -> EnquoRoot {
        let root_key = root_key_obj.unwrap();
        // Not so needless after all, Clippy...
        #[allow(clippy::needless_borrow)]
        let rk = root_key.get_data(&*STATIC_ROOT_KEY_WRAPPER);
        let root = maybe_raise(Root::new(rk), "Failed to create Enquo::Root");

        let klass = Module::from_existing("Enquo").get_nested_class("Root");
        klass.wrap_data(root, &*ROOT_WRAPPER)
    },
    fn enquo_root_field(relation: RString, name: RString) -> EnquoField {
        let root = rbself.get_data(&*ROOT_WRAPPER);

        let field = maybe_raise(
            root.field(
                &relation.unwrap().to_vec_u8_unchecked(),
                &name.unwrap().to_vec_u8_unchecked(),
            ),
            "Failed to create Enquo::Field",
        );

        let klass = Module::from_existing("Enquo").get_nested_class("Field");
        klass.wrap_data(field, &*FIELD_WRAPPER)
    }
);

methods!(
    EnquoRootKeyStatic,
    _rbself,
    fn enquo_root_key_static_new(root_key: RString) -> EnquoRootKeyStatic {
        #[allow(clippy::redundant_clone)]
        let k = root_key.unwrap().to_vec_u8_unchecked().to_owned();
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
methods!(
    EnquoField,
    rbself,
    fn enquo_field_encrypt_i64(value: Integer, context: RString, mode: Symbol) -> RString {
        let i = value.unwrap().to_i64();
        let field = rbself.get_data(&*FIELD_WRAPPER);
        let r_mode = mode.unwrap();
        let s_mode = r_mode.to_str();

        let mut res = maybe_raise(
            if s_mode == "unsafe" {
                I64::new_with_unsafe_parts(i, &context.unwrap().to_vec_u8_unchecked(), field)
            } else {
                I64::new(i, &context.unwrap().to_vec_u8_unchecked(), field)
            },
            "Failed to create encrypted i64",
        );
        if s_mode == "no_query" {
            res.drop_ore_ciphertext();
        }

        RString::new_utf8(&serde_json::to_string(&res).unwrap())
    },
    fn enquo_field_decrypt_i64(ciphertext: RString, context: RString) -> Integer {
        let ct_r = ciphertext.unwrap();
        let ct = ct_r.to_str_unchecked();
        let e_value: I64 =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let value = maybe_raise(
            e_value.decrypt(&context.unwrap().to_vec_u8_unchecked(), field),
            "Failed to decrypt i64 value",
        );
        Integer::from(value)
    },
    fn enquo_field_encrypt_date(
        y_r: Integer,
        m_r: Integer,
        d_r: Integer,
        context: RString,
        mode: Symbol
    ) -> RString {
        let y = y_r.unwrap().to_i32() as i16;
        let m = m_r.unwrap().to_i32() as u8;
        let d = d_r.unwrap().to_i32() as u8;
        let field = rbself.get_data(&*FIELD_WRAPPER);
        let r_mode = mode.unwrap();
        let s_mode = r_mode.to_str();

        let mut res = maybe_raise(
            if s_mode == "unsafe" {
                Date::new_with_unsafe_parts(
                    (y, m, d),
                    &context.unwrap().to_vec_u8_unchecked(),
                    field,
                )
            } else {
                Date::new((y, m, d), &context.unwrap().to_vec_u8_unchecked(), field)
            },
            "Failed to create encrypted date",
        );
        if s_mode == "no_query" {
            res.drop_ore_ciphertexts();
        }

        RString::new_utf8(&serde_json::to_string(&res).unwrap())
    },
    fn enquo_field_decrypt_date(ciphertext: RString, context: RString) -> AnyObject {
        let ct_r = ciphertext.unwrap();
        let ct = ct_r.to_str_unchecked();
        let e_value: Date =
            maybe_raise(serde_json::from_str(ct), "Failed to deserialize ciphertext");

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let (y, m, d) = maybe_raise(
            e_value.decrypt(&context.unwrap().to_vec_u8_unchecked(), field),
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
                fieldklass.def_private("_encrypt_i64", enquo_field_encrypt_i64);
                fieldklass.def_private("_decrypt_i64", enquo_field_decrypt_i64);
                fieldklass.def_private("_encrypt_date", enquo_field_encrypt_date);
                fieldklass.def_private("_decrypt_date", enquo_field_decrypt_date);
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
