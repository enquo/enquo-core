# Encryption Contexts

The `context` argument is intended to be used to prevent attacks where someone is able to modify the data store in such a way that they can take a ciphertext from somewhere and write it somewhere else.

Imagine an attacker who wants to be able to read other users' email addresses, and has managed to obtain a regular user account and also write access to the database.
They could just take the encrypted email addresses of other users, modify their own record in the database to make "their" email address the one from the other user, and then view their account profile in the web application to see what the email address is.

Instead, with an *encryption context*, when each email address is encrypted, some per-user information (such as, say, the primary key of that record in the table) is provided.
When the email address is later decrypted, the same context needs to be provided, or the decryption will fail.
Since the attacker's account's user ID is different to the user whose email address is being substituted, the decryption will fail in the web application and the attacker gets nothing.
