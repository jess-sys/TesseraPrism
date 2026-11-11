//! Thread helpers: internal RAM is scarce once NimBLE + TinyUSB are up, so large stacks of
//! threads that never touch flash go to PSRAM.
//!
//! RULE: a thread whose stack lives in PSRAM must NEVER write/erase flash (NVS, the vault
//! partition, OTA): the cache — and therefore PSRAM — is disabled during flash operations.
//! The core actor (persists the vault, NVS) and the power manager (NVS) keep internal stacks.

use esp_idf_svc::sys;

/// Spawn a named thread whose stack is allocated in PSRAM.
pub fn spawn_psram<F>(name: &str, stack_size: usize, f: F) -> anyhow::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    // esp_pthread_set_cfg applies to threads created *by the calling task*; restore afterwards.
    unsafe {
        let mut cfg = sys::esp_pthread_get_default_config();
        cfg.stack_alloc_caps = (sys::MALLOC_CAP_SPIRAM | sys::MALLOC_CAP_8BIT) as _;
        sys::esp!(sys::esp_pthread_set_cfg(&cfg))?;
    }
    let res = std::thread::Builder::new().name(name.into()).stack_size(stack_size).spawn(f);
    unsafe {
        let cfg = sys::esp_pthread_get_default_config();
        sys::esp_pthread_set_cfg(&cfg);
    }
    res.map(|_| ()).map_err(|e| anyhow::anyhow!("spawning thread {name} ({stack_size} B, PSRAM): {e}"))
}

/// Log internal/PSRAM heap state (free and largest free block).
pub fn log_heap(stage: &str) {
    unsafe {
        let int_caps = sys::MALLOC_CAP_INTERNAL | sys::MALLOC_CAP_8BIT;
        log::info!(
            "heap [{stage}]: internal free {} B (largest {} B, min ever {} B), PSRAM free {} B",
            sys::heap_caps_get_free_size(int_caps),
            sys::heap_caps_get_largest_free_block(int_caps),
            sys::heap_caps_get_minimum_free_size(int_caps),
            sys::heap_caps_get_free_size(sys::MALLOC_CAP_SPIRAM),
        );
    }
}

/// Log the stack high-water mark (minimum free bytes ever) of the app's larger threads.
pub fn log_stacks() {
    for name in [c"core", c"ctap", c"ui", c"power", c"tp-fwd", c"transport-cmd"] {
        unsafe {
            let h = sys::xTaskGetHandle(name.as_ptr());
            if !h.is_null() {
                // On ESP-IDF the high-water mark is in bytes.
                log::info!("stack [{}]: min free {} B", name.to_string_lossy(), sys::uxTaskGetStackHighWaterMark(h));
            }
        }
    }
}
