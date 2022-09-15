#[macro_use]
extern crate rutie;

use rutie::{Class, Integer, Module, Object, RString, VM};
use enquo_core::{Crypto, Field, EncryptedValue};

class!(EnquoCrypto);
class!(EnquoField);

wrappable_struct!(Crypto, CryptoWrapper, CRYPTO_WRAPPER);
wrappable_struct!(Field, FieldWrapper, FIELD_WRAPPER);

methods!(
    EnquoCrypto,
    rbself,

    fn enquo_crypto_new(root_key: RString) -> EnquoCrypto {
        let crypto_r = Crypto::new(root_key.unwrap().to_vec_u8_unchecked());
        let crypto = crypto_r.map_err(|e| VM::raise(Class::from_existing("ArgumentError"), &format!("Failed to create Enquo::Crypto: {:?}", e))).unwrap();

        let klass = Module::from_existing("Enquo").get_nested_class("Crypto");
        return klass.wrap_data(crypto, &*CRYPTO_WRAPPER);
    }

    fn enquo_crypto_field(relation: RString, name: RString) -> EnquoField {
        let crypto = rbself.get_data(&*CRYPTO_WRAPPER);

        let field = crypto.field(relation.unwrap().to_string(), name.unwrap().to_string());

        let klass = Module::from_existing("Enquo").get_nested_class("Field");
        return klass.wrap_data(field, &*FIELD_WRAPPER);
    }
);

methods!(
    EnquoField,
    rbself,

    fn enquo_field_encrypt_i64(value: Integer, context: RString) -> RString {
        let i = value.unwrap().to_i64();
        let field = rbself.get_data(&*FIELD_WRAPPER);

        let res = field.encrypt_i64(i, &context.unwrap().to_vec_u8_unchecked());
        RString::new_utf8(&serde_json::to_string(&res).unwrap())
    }

    fn enquo_field_decrypt_i64(ciphertext: RString, context: RString) -> Integer {
        let ct_r = ciphertext.unwrap();
        let ct = ct_r.to_str_unchecked();
        let e_value: EncryptedValue = serde_json::from_str(&ct).map_err(|e| VM::raise(Class::from_existing("ArgumentError"), &format!("Failed to deserialize ciphertext: {:?}", e))).unwrap();

        let field = rbself.get_data(&*FIELD_WRAPPER);

        let value = field.decrypt_i64(e_value, &context.unwrap().to_vec_u8_unchecked()).map_err(|e| VM::raise(Class::from_existing("RuntimeError"), &format!("Failed to decrypt i64 value: {:?}", e))).unwrap();
        Integer::from(value)
    }
);

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Init_enquo() {
    Module::from_existing("Enquo").define(|topmod| {
        topmod.define_nested_class("Crypto", None).define(|cryptoklass| {
            cryptoklass.singleton_class().def_private("_new", enquo_crypto_new);
            cryptoklass.def_private("_field", enquo_crypto_field);
        });
        topmod.define_nested_class("Field", None).define(|fieldklass| {
            fieldklass.def_private("_encrypt_i64", enquo_field_encrypt_i64);
            fieldklass.def_private("_decrypt_i64", enquo_field_decrypt_i64);
        });
    });
}
