fn main() {
    let exit_code = match aedo_cli::run(std::env::args_os()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            2
        }
    };
    std::process::exit(exit_code);
}
