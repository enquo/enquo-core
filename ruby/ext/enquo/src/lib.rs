#[macro_use]
extern crate rutie;

use enquo_core::{Field, Root, I64};
use rutie::{Class, Integer, Module, Object, RString, VM};

class!(EnquoRoot);
class!(EnquoField);

wrappable_struct!(Root, RootWrapper, ROOT_WRAPPER);
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
    fn enquo_root_new(root_key: RString) -> EnquoRoot {
        let root = maybe_raise(
            Root::new(&root_key.unwrap().to_vec_u8_unchecked()),
            "Failed to create Enquo::Root",
        );

        let klass = Module::from_existing("Enquo").get_nested_class("Root");
        klass.wrap_data(root, &*ROOT_WRAPPER)
    },
    fn enquo_root_field(relation: RString, name: RString) -> EnquoField {
        let root = rbself.get_data(&*ROOT_WRAPPER);

        let field = root.field(
            &relation.unwrap().to_vec_u8_unchecked(),
            &name.unwrap().to_vec_u8_unchecked(),
        );

        let klass = Module::from_existing("Enquo").get_nested_class("Field");
        klass.wrap_data(field, &*FIELD_WRAPPER)
    }
);

methods!(
    EnquoField,
    rbself,
    fn enquo_field_encrypt_i64(value: Integer, context: RString) -> RString {
        let i = value.unwrap().to_i64();
        let field = rbself.get_data(&*FIELD_WRAPPER);

        let res = maybe_raise(
            field.i64(i, &context.unwrap().to_vec_u8_unchecked()),
            "Failed to create encrypted i64",
        );
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
                rootklass
                    .singleton_class()
                    .def_private("_new", enquo_root_new);
                rootklass.def_private("_field", enquo_root_field);
            });
        topmod
            .define_nested_class("Field", None)
            .define(|fieldklass| {
                fieldklass.def_private("_encrypt_i64", enquo_field_encrypt_i64);
                fieldklass.def_private("_decrypt_i64", enquo_field_decrypt_i64);
            });
    });
}
