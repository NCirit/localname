#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    localname::cli::run().await
}
