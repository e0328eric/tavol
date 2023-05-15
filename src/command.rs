use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
pub struct Command {
    #[command(subcommand)]
    pub subcmd: Subcmd,
}

#[derive(Debug, Subcommand)]
pub enum Subcmd {
    Encrypt {
        key: String,
        input: String,
        output: String,
    },
    Decrypt {
        key: String,
        input: String,
        output: String,
    },
}
