/// We do this in order to always have an up-to-date Cargo.lock in `ffi` crate because Nix requires
/// one in order to produce deterministic builds of this crate.
/// This is the simplest solution. Others involving detaching this crate from its parent are
/// inconvenient and do not work as long as this project will rely on patches (weird cargo bug it seems)
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // for eagerly running this script, literally all the time
    println!("cargo:rerun-if-changed=*");

    let cwd = std::env::current_dir()?;
    let workspace = cwd.parent().expect("Could not find current working directory parent");
    let cargo_lock = workspace.join("Cargo.lock");

    if !cargo_lock.exists() {
        panic!("Cargo.lock has to be present in order to include it in 'ffi' workspace")
    }

    std::fs::copy(cargo_lock, cwd.join("Cargo.lock"))?;

    Ok(())
}
