//! We only declare here intermediate FFI representation with raw types. But we do not generate
//! all the bindings and wrappers here.
//! * Haskell: we expose a C-FFI and [wire-server](https://github.com/wireapp/wire-server) will
//! maintain the Haskell wrapper
//! * WASM: we handle bindings here but we let [core-crypto](https://github.com/wireapp/core-crypto)
//! maintain the Typescript wrapper
//! * Android/iOS: we just expose raw types and let [core-crypto](https://github.com/wireapp/core-crypto)
//! generate the bindings and wrappers

cfg_if::cfg_if! {
    if #[cfg(all(feature = "haskell", not(target_family = "wasm")))] {
        mod haskell;
    } else if #[cfg(all(feature = "mobile", not(target_family = "wasm")))] {
        mod mobile;
    } else if #[cfg(target_family = "wasm")] {
        mod wasm;
    }
}
