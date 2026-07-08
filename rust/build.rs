fn main() {
    let target_is_browser_wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("unknown");
    let js_backend_selected =
        std::env::var("CARGO_CFG_GETRANDOM_BACKEND").as_deref() == Ok("wasm_js");
    if target_is_browser_wasm && !js_backend_selected {
        println!(
            "cargo:warning=solana-keychain: building for wasm32-unknown-unknown without a getrandom 0.3 backend. \
             Set RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"' in the final binary's build, \
             otherwise getrandom will fail to compile."
        );
    }
}
