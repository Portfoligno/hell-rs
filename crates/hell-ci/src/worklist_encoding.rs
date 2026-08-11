//! Canonical escaping for reviewer worklist output formats.

pub(crate) fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(crate) fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

pub(crate) fn json_field(value: &str) -> String {
    format!("{value:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_target_worklist_escaping_keeps_untrusted_values_inside_fields() {
        for seed in 0..=u8::MAX {
            let value = format!(
                "prefix-{seed}-<script>&\"'\n\r\t\\-{}",
                char::from(seed.max(32))
            );
            let html = html_escape(&value);
            assert!(!html.contains("<script>"));
            assert!(html.contains("&lt;script&gt;&amp;&quot;&#39;"));
            let csv = csv_field(&value);
            assert!(csv.starts_with('"') && csv.ends_with('"'));
            assert!(!csv[1..csv.len() - 1].replace("\"\"", "").contains('"'));
            let json = json_field(&value);
            assert!(json.starts_with('"') && json.ends_with('"'));
            assert!(!json.contains('\n'));
            assert!(!json.contains('\r'));
        }
    }
}
