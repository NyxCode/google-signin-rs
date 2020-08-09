Google Sign-In for Rust
=======================

Rust API bindings for Google Sign-in.  
See [authenticating with a backend server](https://developers.google.com/identity/sign-in/web/backend-auth).

## Usage
```rust
let mut client = google_signin::Client::new();
client.audiences.push(YOUR_CLIENT_ID); // required
client.hosted_domains.push(YOUR_HOSTED_DOMAIN); // optional

let id_info = client.verify(&data.token).expect("Expected token to be valid");
println!("Success! Signed-in as {}", id_info.sub);
```
