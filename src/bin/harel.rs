use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(harel::cli::run(std::env::args().collect()) as u8)
}
