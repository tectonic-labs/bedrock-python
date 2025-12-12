fn main() {
    // On macOS, allow undefined symbols for Python extension modules
    // These symbols will be resolved at runtime when Python loads the extension
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-cdylib-link-arg=-undefined");
        println!("cargo:rustc-cdylib-link-arg=dynamic_lookup");
    }
}
