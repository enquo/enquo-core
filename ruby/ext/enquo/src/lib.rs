#[macro_use]
extern crate rutie;

use enquo_core::{Field, Root, I64};
use rutie::{Class, Integer, Module, Object, RString, Symbol, VerifiedObject, VM};

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
        let k = root_key.unwrap().to_vec_u8_unchecked();
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
