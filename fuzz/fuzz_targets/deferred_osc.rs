#![no_main]

//! The OSC scanner. A peer refuses a whole screen if one entry is wrong, so:
//! the running byte total equals what is retained, neither bound is exceeded,
//! and no entry carries a control character — including the C1 and DEL a
//! byte-level `0x00..=0x1f` filter cannot see.

use braid_server::defer::{DEFERRED_BYTES, DEFERRED_ENTRIES, DeferredOsc, OSC_SCAN_LIMIT};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut defer = DeferredOsc::new();
    let start = defer.mark();

    // Split, because carrying state between two reads is the whole point.
    for chunk in data.chunks(17) {
        defer.feed(chunk);
    }

    let (entries, bytes) = defer.held();
    assert!(
        entries <= DEFERRED_ENTRIES,
        "{entries} entries retained past a bound of {DEFERRED_ENTRIES}"
    );
    assert!(
        bytes <= DEFERRED_BYTES,
        "{bytes} bytes retained past a bound of {DEFERRED_BYTES}"
    );

    let held = defer.since(start);
    assert_eq!(held.len(), entries, "the entry count drifted from the list");
    assert_eq!(
        held.iter().map(String::len).sum::<usize>(),
        bytes,
        "the running byte total drifted from the entries it counts"
    );
    for entry in &held {
        assert!(
            !entry.chars().any(char::is_control),
            "a control-bearing entry would make the peer refuse the whole screen: {entry:?}"
        );
        assert!(
            entry.len() <= OSC_SCAN_LIMIT,
            "an entry of {} bytes survived a {OSC_SCAN_LIMIT}-byte scan limit",
            entry.len()
        );
    }

    // Nothing outside the list is ever carried, or the client replays a
    // sequence out of nowhere.
    assert_eq!(defer.carry(start, usize::MAX), held);
    for entry in defer.carry(start, DEFERRED_BYTES / 2) {
        assert!(held.contains(&entry), "carried an entry nothing holds");
    }

    // Nothing is newer than a mark taken now.
    let now = defer.mark();
    assert!(defer.since(now).is_empty());
    defer.forget_before(now);
    assert_eq!(defer.held(), (0, 0));
});
