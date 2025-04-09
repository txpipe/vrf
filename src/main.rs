use vrf_dalek::cli::{get_args, run};

fn main() {
    if let Err(e) = get_args().and_then(run) {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
