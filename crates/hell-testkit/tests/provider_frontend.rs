#![cfg(unix)]

use std::ffi::OsString;
use std::path::Path;

use hell_testkit::provider_frontend::linux_frontend_arguments;

#[test]
fn provider_frontend_keeps_runner_uid_and_exact_nested_target_authority() {
    let target = [
        OsString::from("--sealed"),
        OsString::from("--"),
        OsString::from("/usr/bin/sudo"),
        OsString::from("--user"),
        OsString::from("candidate-user"),
        OsString::from("--"),
        OsString::from("/candidate/operation"),
        OsString::from("one native argument"),
    ];
    let args =
        linux_frontend_arguments(1001, 995, Path::new("/runtime/memcordon"), &target).unwrap();
    let runtime = args
        .iter()
        .position(|arg| arg == "/runtime/memcordon")
        .unwrap();
    assert_eq!(&args[runtime + 1..], &target);
    assert!(args.windows(2).any(|pair| pair == ["--reuid", "1001"]));
    assert!(args.windows(2).any(|pair| pair == ["--regid", "995"]));
    assert!(args.iter().any(|arg| arg == "--init-groups"));
    assert!(!args.iter().any(|arg| arg == "--no-new-privs"));
    assert!(args.iter().any(|arg| arg == "--inh-caps=-all"));
    assert!(args.iter().any(|arg| arg == "--ambient-caps=-all"));
}

#[test]
fn provider_frontend_rejects_root_ids_and_relative_programs() {
    assert!(linux_frontend_arguments(0, 995, Path::new("/runtime/memcordon"), &[]).is_err());
    assert!(linux_frontend_arguments(1001, 0, Path::new("/runtime/memcordon"), &[]).is_err());
    assert!(linux_frontend_arguments(1001, 995, Path::new("relative/memcordon"), &[]).is_err());
}
