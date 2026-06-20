use serde::Serialize;

use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

impl OutputMode {
    pub fn from_json_flag(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }
}

pub fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[expect(dead_code, reason = "reserved for follow-up human output rendering")]
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths = headers
        .iter()
        .map(|header| header.len())
        .collect::<Vec<_>>();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index >= widths.len() {
                widths.push(0);
            }
            widths[index] = widths[index].max(cell.len());
        }
    }

    print_row(
        headers.iter().map(|value| value.to_string()).collect(),
        &widths,
    );
    print_row(
        widths.iter().map(|width| "-".repeat(*width)).collect(),
        &widths,
    );
    for row in rows {
        print_row(row.clone(), &widths);
    }
}

#[expect(dead_code, reason = "reserved for follow-up human output rendering")]
pub fn print_kv(rows: &[(&str, String)]) {
    let width = rows
        .iter()
        .map(|(key, _value)| key.len())
        .max()
        .unwrap_or(0);
    for (key, value) in rows {
        println!("{key:width$}  {value}", width = width);
    }
}

fn print_row(row: Vec<String>, widths: &[usize]) {
    for (index, cell) in row.iter().enumerate() {
        if index > 0 {
            print!("  ");
        }
        let width = widths[index];
        print!("{cell:width$}");
    }
    println!();
}
