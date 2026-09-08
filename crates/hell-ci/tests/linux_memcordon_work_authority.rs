use syn::visit::{self, Visit};

#[derive(Default)]
struct WorkDirectoryCalls {
    runner_creates: usize,
    privileged_modes: usize,
    unprivileged_modes: usize,
}

impl<'ast> Visit<'ast> for WorkDirectoryCalls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            match segments.as_slice() {
                [module, function] if module == "fs" && function == "create_dir" => {
                    self.runner_creates += 1
                }
                [module, function] if module == "fs" && function == "set_permissions" => {
                    self.unprivileged_modes += 1
                }
                [function] if function == "trusted_tool_status_before" => {
                    self.privileged_modes += 1;
                    assert!(
                        matches!(call.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("deadline")),
                        "privileged setup must use the acquisition deadline"
                    );
                    assert!(
                        matches!(call.args.last(), Some(syn::Expr::Array(_))),
                        "chmod arguments must remain a typed array"
                    );
                }
                _ => {}
            }
        }
        visit::visit_expr_call(self, call);
    }
}

#[test]
fn foreign_group_work_directory_mode_uses_bounded_privilege_without_changing_creator() {
    let source = syn::parse_file(include_str!("../src/release/platform.rs")).unwrap();
    let function = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "prepare_linux_memcordon_work_directories" =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("Linux work-directory setup contract");
    let mut calls = WorkDirectoryCalls::default();
    calls.visit_block(&function.block);
    assert_eq!(
        calls.runner_creates, 1,
        "trusted runner must retain directory ownership"
    );
    assert_eq!(
        calls.privileged_modes, 1,
        "foreign-group SGID requires trusted mode authority"
    );
    assert_eq!(
        calls.unprivileged_modes, 0,
        "unprivileged chmod strips foreign-group SGID on Linux"
    );
}

#[derive(Default)]
struct StageContract {
    literals: Vec<String>,
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for StageContract {
    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        if invocation.path.is_ident("vec") {
            use syn::parse::Parser as _;
            let values = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(invocation.tokens.clone())
                .expect("typed vector arguments");
            let mut nested = StageContract::default();
            for value in &values {
                nested.visit_expr(value);
            }
            self.calls.extend(nested.calls);
            self.literals.extend(nested.literals);
        }
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.literals.push(literal.value());
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }
}

#[test]
fn staged_workspace_uses_closed_git_snapshot_and_bound_auxiliary_inputs() {
    let source = syn::parse_file(include_str!("../src/release/platform.rs")).unwrap();
    let implementation = source.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("LinuxMemcordonWorkspace")) => Some(item),
        _ => None,
    }).expect("workspace authority implementation");
    let mut contract = StageContract::default();
    contract.visit_item_impl(implementation);
    for expected in [
        "--no-local",
        "--no-checkout",
        "--template=",
        "--detach",
        "a-w",
        "ci-out/linux-release-oracle",
        "ci-out/dependency-policy.json",
    ] {
        assert!(
            contract.literals.iter().any(|value| value == expected),
            "missing workspace authority invariant: {expected}"
        );
    }
    for expected in [
        "source_inventory",
        "require_source_inventory",
        "validate_trusted_cargo_cache_tree",
        "posix_object_identity",
        "validate_posix_adapter_installation_root",
    ] {
        assert!(
            contract.calls.iter().any(|value| value == expected),
            "missing workspace authority check: {expected}"
        );
    }
}

#[test]
fn candidate_path_preflight_checks_identity_inputs_and_work_creation() {
    let source = syn::parse_file(include_str!("../src/release/platform.rs")).unwrap();
    let function = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "run_linux_memcordon_path_preflight" =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("candidate preflight");
    let mut contract = StageContract::default();
    contract.visit_item_fn(function);
    for expected in [
        "geteuid",
        "getegid",
        "symlink_metadata",
        "canonicalize",
        "remove_file",
        "preflight_tool_requirements",
        "prove_operation_dependencies_offline",
    ] {
        assert!(
            contract.calls.iter().any(|value| value == expected),
            "missing candidate preflight check: {expected}"
        );
    }
    for expected in [
        "Cargo.toml",
        "Cargo.lock",
        "compat/assurance-mutants.toml",
        "ci/fuzz-targets.toml",
        "CARGO",
        "RUSTC",
        "--version",
    ] {
        assert!(
            contract.literals.iter().any(|value| value == expected),
            "missing candidate probe: {expected}"
        );
    }
}

#[test]
fn fuzz_launch_binds_operation_tools_and_offline_dependency_authority() {
    let source = syn::parse_file(include_str!("../src/release/platform.rs")).unwrap();
    let implementation = source.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("LinuxMemcordonLaunchAuthority")) => Some(item),
        _ => None,
    }).expect("Linux launch authority");
    let acquire = implementation
        .items
        .iter()
        .find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "acquire_until" => Some(method),
            _ => None,
        })
        .expect("Linux launch acquisition");
    let mut contract = StageContract::default();
    contract.visit_impl_item_fn(acquire);
    for call in [
        "tool_requirements",
        "resolve_posix_cargo_authority_for_toolchain",
        "stage_posix_executable",
        "stage_operation_dependencies",
    ] {
        assert!(
            contract.calls.iter().any(|value| value == call),
            "missing required authority: {call}"
        );
    }
    assert!(
        !contract.calls.iter().any(|value| value == "from_process"),
        "candidate tool PATH must not reuse ambient runner search paths"
    );
    for value in ["cargo-fuzz", "/usr/bin", "/bin"] {
        assert!(
            contract.literals.iter().any(|literal| literal == value),
            "missing protected tool search binding: {value}"
        );
    }
}
