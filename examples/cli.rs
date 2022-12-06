use std::path::PathBuf;

use clap::Parser;
use home::home_dir;

use keyring::KeysSubcmd;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: KeysSubcmd,

    /// The directory where encrypted key files are stored
    #[arg(long)]
    pub dir: Option<PathBuf>,
}

fn main() {
    // parse command line arguments
    let Cli {
        subcommand,
        dir,
    } = Cli::parse();

    // dir is default to `~/.keyring`
    let dir = dir.unwrap_or_else(|| {
        home_dir()
            .expect("Failed to find the user home directory")
            .join(".keyring")
    });

    subcommand.run(dir).unwrap_or_else(|err| {
        panic!("{err}");
    });
}
