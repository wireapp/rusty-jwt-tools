cfg_if::cfg_if! {
    if #[cfg(all(feature = "haskell", not(target_family = "wasm")))] {
        mod haskell;
    } else if #[cfg(target_family = "wasm")] {
        mod wasm;
    }
}
