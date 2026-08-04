use std::fs::File;
use std::io::Write;

pub fn write_file(file_name: &str, buf: &[u8]) -> std::io::Result<usize> {
    let mut file = File::create(file_name)?;
    // Explanation of why write_all() at reverse_engineering_notes.md
    file.write_all(buf)?;
    Ok(buf.len())
}