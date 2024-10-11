mod groth16;
mod config;
mod error;

use crate::groth16::{AppState, setup, generate_valid_calldata, generate_valid_proof};
use crate::error::AppError;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use serde_json::{json, Value};
use std::sync::Once;
use std::sync::Arc;
use log::{info, error};

static INIT: Once = Once::new();
static mut APP_STATE: Option<Arc<AppState>> = None;

fn init_logger() {
    env_logger::init();
}

#[no_mangle]
pub extern "C" fn init() -> *mut c_char {
    init_logger();
    info!("Initializing...");
    let result = std::panic::catch_unwind(|| {
        INIT.call_once(|| {
            let state = futures::executor::block_on(async {
                match setup().await {
                    Ok(state) => state,
                    Err(e) => {
                        error!("Failed to setup: {:?}", e);
                        panic!("Failed to setup: {:?}", e);
                    },
                }
            });
            unsafe { APP_STATE = Some(Arc::new(state)); }
        });
        "Setup completed successfully".to_string()
    });

    match result {
        Ok(message) => {
            info!("Initialization successful");
            CString::new(message).unwrap().into_raw()
        },
        Err(e) => {
            error!("Setup failed: {:?}", e);
            CString::new("Setup failed").unwrap().into_raw()
        },
    }
}

#[no_mangle]
pub extern "C" fn generate_proof(input_ptr: *const c_char) -> *mut c_char {
    info!("Generating proof...");
    let result = std::panic::catch_unwind(|| {
        if input_ptr.is_null() {
            error!("Null input pointer");
            return Err(AppError::InvalidInput("Null input pointer".to_string()));
        }

        let input_cstr = unsafe { CStr::from_ptr(input_ptr) };
        let input_str = match input_cstr.to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid UTF-8 in input: {:?}", e);
                return Err(AppError::InvalidInput("Invalid UTF-8 in input".to_string()));
            }
        };

        let input: Value = match serde_json::from_str(input_str) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse JSON input: {:?}", e);
                return Err(AppError::InvalidInput("Invalid JSON input".to_string()));
            }
        };

        let state = unsafe {
            match &APP_STATE {
                Some(state) => state,
                None => {
                    error!("AppState not initialized");
                    return Err(AppError::UninitializedState);
                }
            }
        };

        match generate_valid_proof(state, &input) {
            Ok(calldata) => Ok(serde_json::to_string(&calldata).unwrap()),
            Err(e) => {
                error!("Error generating proof: {:?}", e);
                Err(e)
            },
        }
    });

    match result {
        Ok(Ok(output)) => {
            info!("Proof generated successfully");
            CString::new(output).unwrap().into_raw()
        },
        Ok(Err(e)) => {
            error!("Error in generate_proof: {:?}", e);
            CString::new(format!("Error: {:?}", e)).unwrap().into_raw()
        },
        Err(e) => {
            error!("Panic in generate_proof: {:?}", e);
            CString::new("Internal error occurred").unwrap().into_raw()
        },
    }
}

#[no_mangle]
pub extern "C" fn generate_calldata(input_ptr: *const c_char) -> *mut c_char {
    info!("Generating calldata...");
    let result = std::panic::catch_unwind(|| {
        if input_ptr.is_null() {
            error!("Null input pointer");
            return Err(AppError::InvalidInput("Null input pointer".to_string()));
        }

        let input_cstr = unsafe { CStr::from_ptr(input_ptr) };
        let input_str = match input_cstr.to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("Invalid UTF-8 in input: {:?}", e);
                return Err(AppError::InvalidInput("Invalid UTF-8 in input".to_string()));
            }
        };

        let input: Value = match serde_json::from_str(input_str) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to parse JSON input: {:?}", e);
                return Err(AppError::InvalidInput("Invalid JSON input".to_string()));
            }
        };

        let state = unsafe {
            match &APP_STATE {
                Some(state) => state,
                None => {
                    error!("AppState not initialized");
                    return Err(AppError::UninitializedState);
                }
            }
        };

        match generate_valid_calldata(state, &input) {
            Ok(calldata) => Ok(serde_json::to_string(&calldata).unwrap()),
            Err(e) => {
                error!("Error generating calldata: {:?}", e);
                Err(e)
            },
        }
    });

    match result {
        Ok(Ok(output)) => {
            info!("Calldata generated successfully");
            CString::new(output).unwrap().into_raw()
        },
        Ok(Err(e)) => {
            error!("Error in generate_calldata: {:?}", e);
            CString::new(format!("Error: {:?}", e)).unwrap().into_raw()
        },
        Err(e) => {
            error!("Panic in generate_calldata: {:?}", e);
            CString::new("Internal error occurred").unwrap().into_raw()
        },
    }
}