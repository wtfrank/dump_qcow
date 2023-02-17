mod qcow;
use clap::Parser;

/// show structures of a backed qcow file
#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None )]
struct Params {
    /// Name of the kvm qcow file to dump
    paths: Vec::<std::path::PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Params::parse();
    for path in args.paths {
      qcow::dump(path)?;
    }

    Ok(())
}
