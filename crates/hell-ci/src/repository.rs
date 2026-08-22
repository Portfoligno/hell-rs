use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Default)]
struct Options {
    repository_root: Option<PathBuf>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|value| value == "repository")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("check-text-files") {
        return Err(usage());
    }
    let options = parse_options(&arguments[2..])?;
    let repository_root = options
        .repository_root
        .ok_or_else(|| format!("--repository-root is required\n{}", usage()))?;
    crate::policy::check_text_files(&repository_root)?;
    Ok(format!(
        "tracked text files match repository policy in {}",
        repository_root.display()
    ))
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut arguments = arguments.iter();
    while let Some(flag) = arguments.next() {
        let flag = flag
            .to_str()
            .ok_or_else(|| "repository option name must be UTF-8".to_owned())?;
        if flag != "--repository-root" {
            return Err(format!("unknown repository option {flag}\n{}", usage()));
        }
        if options.repository_root.is_some() {
            return Err("--repository-root was provided more than once".to_owned());
        }
        options.repository_root =
            Some(PathBuf::from(arguments.next().ok_or_else(|| {
                "--repository-root requires PATH".to_owned()
            })?));
    }
    Ok(options)
}

fn usage() -> String {
    "usage: hell-ci repository check-text-files --repository-root PATH".to_owned()
}
