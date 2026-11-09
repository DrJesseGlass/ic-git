//! The label a repo name maps to, and ic-name-service's rule for one: pure
//! string rules both sides apply (store.rs when a repo is created, names.rs
//! when it is announced).

/// Longest label a repo name may map to: ic-name-service's segment limit,
/// and DNS's.
pub const MAX_LABEL: usize = 63;

/// ic-name-service's rule for a handle or a label: 1 to MAX_LABEL bytes of
/// a-z, 0-9 and '-', not starting or ending with '-'.
pub fn check_segment(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_LABEL {
        return Err(format!("{what} must be 1 to {MAX_LABEL} bytes"));
    }
    if !s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
        return Err(format!("{what} may only contain a-z, 0-9 and '-'"));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(format!("{what} may not start or end with '-'"));
    }
    Ok(())
}

/// The lower-kebab label a repo name maps to: lowercased, '.' and '_' made
/// '-', runs of '-' collapsed, and '-' trimmed from both ends. "My_App"
/// and "my-app" map to the same "my-app". Refused when the result breaks
/// `check_segment` (empty, over MAX_LABEL bytes, or a character outside
/// a-z, 0-9 and '-'). It is what the repo is announced under in
/// ic-name-service (names.rs), whose names are lower kebab case only.
pub fn repo_label(name: &str) -> Result<String, String> {
    let mut label = String::with_capacity(name.len());
    for c in name.chars() {
        let c = match c {
            '.' | '_' | '-' => '-',
            c => c.to_ascii_lowercase(),
        };
        if !(c == '-' && label.ends_with('-')) {
            label.push(c);
        }
    }
    let label = label.trim_matches('-').to_string();
    check_segment("label", &label).map_err(|e| {
        format!("repo name '{name}' maps to the label '{label}' (lowercased, '.' and '_' as '-'): {e}")
    })?;
    Ok(label)
}
