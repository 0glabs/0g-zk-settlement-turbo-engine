use std::path::PathBuf;
use std::env;

pub fn get_circuit_paths() -> (PathBuf, PathBuf, PathBuf) {
    let current_dir = std::env::current_dir().expect("Failed to get current directory");
    let build_dir = env::var("BUILD_DIR").unwrap_or_else(|_| "build".to_string());
    let circuit_name = env::var("CIRCUIT_NAME").unwrap_or_else(|_| "main".to_string());

    (
        current_dir.join(format!("{}/{}_js/{}.wasm", build_dir, circuit_name, circuit_name)),
        current_dir.join(format!("{}/{}.r1cs", build_dir, circuit_name)),
        current_dir.join(format!("{}/{}.zkey", build_dir, circuit_name)),
    )
}