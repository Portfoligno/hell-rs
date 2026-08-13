pub(crate) fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase full Git SHA"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_exact_lowercase_nonzero_hex() {
        assert!(require_git_sha(&"a".repeat(40), "commit").is_ok());
        assert!(require_git_sha(&"0".repeat(40), "commit").is_err());
    }
}
