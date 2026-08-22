mod github_runtime {
    struct GithubRuntime;

    impl GithubRuntime {
        fn from_process() {
            let _ = std::env::var("GITHUB_SHA");
        }
    }
}
