use std::io::Write;

pub fn fatal_err(msg: &str) -> ! {
    let _ = writeln!(std::io::stderr(), "{}", msg);
    std::process::exit(1);
}