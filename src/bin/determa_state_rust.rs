use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(determa_state::cli::run(std::env::args().collect()) as u8)
}
