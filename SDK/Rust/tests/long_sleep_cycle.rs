#![cfg(all(windows, feature = "long_sleep"))]

use std::time::{Duration, Instant};

#[test]
fn long_sleep_teardown_then_ab_call_rebuilds() {
    unsafe {
        activebreach::activebreach_launch().expect("activebreach_launch failed");
    }

    // Speed the test up: minimum enforced by library is 1000ms.
    activebreach::ab_set_long_sleep_idle_ms(1_000);

    // One call to ensure the dispatcher has touched both the syscall table and stub pool.
    let cpu = unsafe { activebreach::ab_call("NtGetCurrentProcessorNumber", &[]) };
    assert!(cpu < 4096);

    // Confirm syscall table is currently initialized.
    assert!(activebreach::internal::exports::syscall_table_is_init());

    // Wait until long_sleep tears down resources.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if !activebreach::internal::exports::syscall_table_is_init() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !activebreach::internal::exports::syscall_table_is_init(),
        "syscall table never deinitialized (long_sleep teardown did not trigger)"
    );

    // Next call should wake dispatcher, rebuild syscall table + stub pool, and succeed.
    let cpu2 = unsafe { activebreach::ab_call("NtGetCurrentProcessorNumber", &[]) };
    assert!(cpu2 < 4096);

    // Table should be back after the call.
    assert!(activebreach::internal::exports::syscall_table_is_init());
}
