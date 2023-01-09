This directory contains the Ruby bindings for the [Enquo](https://enquo.org) core cryptography library.

## Note Well

When reading these docs, bear in mind that this is a *low level* cryptographic library.
It is not intended that most users will use `enquo-core` directly.
Instead, typically you will use Enquo via your preferred ORM or other higher-level integration.
This library is intended to be used to build *those* integrations, not to be used in applications directly.


# Installation

Typically you'll want to install [the rubygem]:

```bash
gem install enquo-core
```

If you use a platform for which pre-built binary packages are available, this will Just Work.
Otherwise, you'll need a [Rust toolchain](https://www.rust-lang.org/learn/get-started) to build.


# Usage

The Enquo core is all about encrypting and decrypting *field data*, using keys derived from a *root*.

Load the library:

```ruby
require "enquo-core"
```

Create the root key, from which all other cryptographic keys are derived:

```ruby
root_key = Enquo::RootKey::Static.new(SecureRandom.bytes(32))
```

(In real-world use, you'll want to take that key from somewhere it can be securely stored)

Now, you can create the root itself:

```ruby
root = Enquo::Root.new(root_key)
```

Finally, you can now create a "field" object, which is what is used to do encryption and decryption:

```ruby
f = root.field("some_relation", "some_field_name")
ciphertext = f.encrypt_text("this is some text", "test")
puts f.decrypt_text(ciphertext, "test").inspect  # Should print "this is some text"
```

For more details on the full API, consult [the fine manual](https://www.rubydoc.info/gems/enquo-core).
