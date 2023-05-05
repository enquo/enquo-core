This directory contains the Rust code for the [Enquo](https://enquo.org) core cryptography library.

The Rust Enquo core serves two purposes:

1. a Rust-based queryable encryption library; and

2. the core code for Enquo client functionality in other languages.

As such, there may be things in this library that aren't as "Rustaceous" as might be expected.
This may be either because I didn't know a better way, or else because it's important for cross-language compatibility.


# Usage

The Enquo core is all about encrypting and decrypting *field data*, using keys derived from a *root*.

Creating the root is a matter of initializing a key, and then providing that to the root.

```rust
use enquo_core::{KeyProvider, key_provider::Static, Root};
use rand::{Rng, SeedableRng};
// The generated key *must* be from a cryptographically secure random number generator;
// thread_rng() is not guaranteed to be secure enough.
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
# use enquo_core::Error;
# fn main() -> Result<(), Error> {

let key_data = ChaCha20Rng::from_entropy().gen::<[u8; 32]>();

let root_key = Static::new(&key_data)?;
let root = Root::new(Arc::new(root_key));
# Ok(())
# }
```

Once you have a *root*, you can create a *field*, which represents the derived key for a given group of data values.
All the data that you want to compare together must be encrypted with the same field, but unrelated values should be encrypted with different fields.

```rust
# use enquo_core::{KeyProvider, key_provider::Static, Root, Error};
# use rand::{Rng, SeedableRng};
# use rand_chacha::ChaCha20Rng;
# use std::sync::Arc;
#
# fn main() -> Result<(), Error> {
# let key_data = ChaCha20Rng::from_entropy().gen::<[u8; 32]>();
#
# let root_key = Static::new(&key_data)?;
# let root = Root::new(Arc::new(root_key))?;
let field = root.field(b"some_relation", b"some_field_name")?;
# Ok(())
# }
```

To encrypt a value, you create a ciphertext of that value of the appropriate type, providing the field so that the value can be encrypted with the correct key.

```rust
# use enquo_core::{KeyProvider, key_provider::Static, Root, Error};
# use rand::{Rng, SeedableRng};
# use rand_chacha::ChaCha20Rng;
# use std::sync::Arc;
use enquo_core::datatype::Text;

# fn main() -> Result<(), Error> {
# let key_data = ChaCha20Rng::from_entropy().gen::<[u8; 32]>();
#
# let root_key = Static::new(&key_data)?;
# let root = Root::new(Arc::new(root_key))?;
# let field = root.field(b"some_relation", b"some_field_name")?;

let ciphertext = Text::new("this is some text", b"test", &field)?;
assert_eq!("this is some text", ciphertext.decrypt(b"test", &field)?);
# Ok(())
# }
```

All encrypted data types use [Serde](https://docs.rs/serde/latest/serde/) to provide serialization.

For more details on the full API, consult [the fine manual](https://docs.rs/enquo-core/latest/enquo_core/).
