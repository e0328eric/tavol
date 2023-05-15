#![allow(unused)]

mod command;
mod error;

use std::fs;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::ptr;

use aes::cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use clap::Parser;
use error_stack::{IntoReport, ResultExt};
use sha2::{Digest, Sha256};

use crate::error::TavolErr;

fn main() -> error::Result<()> {
    let cmd = command::Command::parse();

    match cmd.subcmd {
        command::Subcmd::Encrypt { key, input, output } => encrypt_file(key, input, output),
        command::Subcmd::Decrypt { key, input, output } => decrypt_file(key, input, output),
    }
}

fn encrypt_file(key: String, input: String, output: String) -> error::Result<()> {
    let mut key_hasher = Sha256::new();
    key_hasher.update(key.as_bytes());
    let result = key_hasher.finalize();

    let cipher = Aes256::new_from_slice(&result[..])
        .map_err(|_| TavolErr::AesErr)
        .into_report()?;

    let mut input_file = BufReader::new(
        fs::File::open(&input)
            .into_report()
            .change_context(TavolErr::IoErr)
            .attach_printable_lazy(|| format!("cannot open a file `{input}`."))?,
    );
    let mut buf = Vec::with_capacity(1000);
    input_file
        .read_to_end(&mut buf)
        .into_report()
        .change_context(TavolErr::IoErr)
        .attach_printable_lazy(|| format!("cannot read datas from a file `{input}`."))?;

    let mut ciphertext = Vec::with_capacity(buf.len());
    for chunk in buf.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        // SAFETY: the length of chunk is less or equal than 16, which is a length of the block.
        // As block is already full with zero bytes and both inner types are same,
        // memcpy is fine
        unsafe {
            ptr::copy_nonoverlapping(chunk.as_ptr(), block.as_mut_ptr(), chunk.len());
        }
        cipher.encrypt_block(&mut block);
        ciphertext.append(&mut block.to_vec());
    }

    let mut output_file = BufWriter::new(
        fs::File::create(&output)
            .into_report()
            .change_context(TavolErr::IoErr)
            .attach_printable_lazy(|| format!("cannot create/open a file `{output}`."))?,
    );

    output_file
        .write_all(&ciphertext)
        .into_report()
        .change_context(TavolErr::IoErr)
        .attach_printable_lazy(|| format!("cannot write datas into a file `{output}`."))?;

    Ok(())
}

fn decrypt_file(key: String, input: String, output: String) -> error::Result<()> {
    let mut key_hasher = Sha256::new();
    key_hasher.update(key.as_bytes());
    let result = key_hasher.finalize();

    let cipher = Aes256::new_from_slice(&result[..])
        .map_err(|_| TavolErr::AesErr)
        .into_report()?;

    let mut input_file = BufReader::new(
        fs::File::open(&input)
            .into_report()
            .change_context(TavolErr::IoErr)
            .attach_printable_lazy(|| format!("cannot open a file `{input}`."))?,
    );
    let mut buf = Vec::with_capacity(1000);
    input_file
        .read_to_end(&mut buf)
        .into_report()
        .change_context(TavolErr::IoErr)
        .attach_printable_lazy(|| format!("cannot read datas from a file `{input}`."))?;

    let mut plaintext = Vec::with_capacity(buf.len());
    for chunk in buf.chunks(16) {
        let mut block = GenericArray::from([0u8; 16]);
        // SAFETY: the length of chunk is less or equal than 16, which is a length of the block.
        // As block is already full with zero bytes and both inner types are same,
        // memcpy is fine
        unsafe {
            ptr::copy_nonoverlapping(chunk.as_ptr(), block.as_mut_ptr(), chunk.len());
        }
        cipher.decrypt_block(&mut block);
        plaintext.append(&mut block.to_vec());
    }

    let mut output_file = BufWriter::new(
        fs::File::create(&output)
            .into_report()
            .change_context(TavolErr::IoErr)
            .attach_printable_lazy(|| format!("cannot create/open a file `{output}`."))?,
    );

    output_file
        .write_all(&plaintext)
        .into_report()
        .change_context(TavolErr::IoErr)
        .attach_printable_lazy(|| format!("cannot write datas into a file `{output}`."))?;

    Ok(())
}
