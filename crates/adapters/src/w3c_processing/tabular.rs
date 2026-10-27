//! Conventional quoted CSV/TSV, retained as inert strings without type/formula evaluation.
use super::{
    Budget, MAX_ITEMS, MAX_SCALAR, ProcessedDocument, Section, diagnostic, limit, malformed,
};
use devres_domain::Result;

#[derive(Clone, Copy)]
enum State {
    Start,
    Plain,
    Quoted,
    AfterQuote,
}
fn grammar(source: &[u8], delimiter: u8, budget: &Budget) -> Result<()> {
    let mut state = State::Start;
    for (index, &byte) in source.iter().enumerate() {
        if index % 4096 == 0 {
            budget.check()?;
        }
        state = match (state, byte) {
            (State::Start, b'"') => State::Quoted,
            (State::Start, b'\r' | b'\n') => State::Start,
            (State::Start, value) if value == delimiter => State::Start,
            (State::Start, _) => State::Plain,
            (State::Plain, b'"') => return Err(malformed()),
            (State::Plain, b'\r' | b'\n') => State::Start,
            (State::Plain, value) if value == delimiter => State::Start,
            (State::Plain, _) => State::Plain,
            (State::Quoted, b'"') => State::AfterQuote,
            (State::Quoted, _) => State::Quoted,
            (State::AfterQuote, b'"') => State::Quoted,
            (State::AfterQuote, b'\r' | b'\n') => State::Start,
            (State::AfterQuote, value) if value == delimiter => State::Start,
            (State::AfterQuote, _) => return Err(malformed()),
        };
    }
    if matches!(state, State::Quoted) {
        return Err(malformed());
    }
    Ok(())
}
pub(super) fn project(
    path: &str,
    source: &str,
    tsv: bool,
    budget: &Budget,
) -> Result<ProcessedDocument> {
    let delimiter = if tsv { b'\t' } else { b',' };
    grammar(source.as_bytes(), delimiter, budget)?;
    let mut parser = csv_core::ReaderBuilder::new().delimiter(delimiter).build();
    let mut input = source.as_bytes();
    let mut output = vec![0; super::MAX_STRUCTURED_INPUT + 1];
    let mut ends = [0; 1025];
    let mut written = 0;
    let mut fields = 0;
    let mut document = ProcessedDocument {
        format: if tsv { "tsv" } else { "csv" }.into(),
        title: path.rsplit('/').next().unwrap_or(path).into(),
        ..Default::default()
    };
    loop {
        budget.check()?;
        let (status, consumed, emitted, ended) =
            parser.read_record(input, &mut output[written..], &mut ends[fields..]);
        input = &input[consumed..];
        written += emitted;
        fields += ended;
        if written > super::MAX_STRUCTURED_INPUT || fields > 1024 {
            return Err(limit());
        }
        match status {
            csv_core::ReadRecordResult::End => break,
            csv_core::ReadRecordResult::Record => {
                budget.node()?;
                if document.sections.len() >= MAX_ITEMS {
                    return Err(limit());
                }
                let mut start = 0;
                let mut record = String::new();
                for (index, &end) in ends[..fields].iter().enumerate() {
                    budget.node()?;
                    let cell = std::str::from_utf8(output.get(start..end).ok_or_else(malformed)?)
                        .map_err(|_| malformed())?;
                    if cell.len() > MAX_SCALAR {
                        return Err(limit());
                    }
                    if !record.is_empty() {
                        record.push('\n');
                    }
                    record.push_str(&format!("column {}: {cell}", index + 1));
                    start = end;
                }
                if !document.text.is_empty() {
                    document.text.push('\n');
                }
                document.text.push_str(&record);
                let row = document.sections.len() + 1;
                document.sections.push(Section {
                    anchor: format!("row-{row}"),
                    title: format!("Row {row}"),
                    text: record,
                });
                written = 0;
                fields = 0;
            }
            csv_core::ReadRecordResult::OutputFull | csv_core::ReadRecordResult::OutputEndsFull => {
                return Err(limit());
            }
            csv_core::ReadRecordResult::InputEmpty => {
                if input.is_empty() && consumed == 0 && emitted == 0 && ended == 0 {
                    return Err(malformed());
                }
            }
        }
    }
    document.gap("tabular_semantics_unasserted", "Rows and columns are inert strings; header identity, types, formulas, and schema semantics are unasserted.");
    document.validate().map_err(diagnostic)?;
    Ok(document)
}
