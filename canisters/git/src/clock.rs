//! The clock both sides read: IC time, or a settable one in tests.

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(1_700_000_000_000_000_000) };
}

/// Nanoseconds since the epoch; settable in tests.
pub fn now_ns() -> u64 {
    #[cfg(test)]
    {
        TEST_NOW.with(|t| t.get())
    }
    #[cfg(not(test))]
    {
        ic_cdk::api::time()
    }
}

#[cfg(test)]
pub fn set_test_now(ns: u64) {
    TEST_NOW.with(|t| t.set(ns));
}
