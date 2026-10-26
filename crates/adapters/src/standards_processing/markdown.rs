use super::{Budget, MAX_INPUT, ProcessedDocument, limit, safe_target};
use devres_domain::Result;
use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

fn escaped(output: &mut String, text: &str) -> Result<()> {
    for ch in text.chars() {
        match ch {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(ch),
        }
        if output.len() > MAX_INPUT * 2 {
            return Err(limit());
        }
    }
    Ok(())
}
pub(super) fn project(source: &str, budget: &Budget) -> Result<ProcessedDocument> {
    let mut output = String::new();
    let mut nesting = 0usize;
    let mut events = 0usize;
    for event in Parser::new_ext(
        source,
        Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_HEADING_ATTRIBUTES,
    ) {
        budget.check()?;
        events += 1;
        if events > 4_000_000 {
            return Err(limit());
        }
        match event {
            Event::Start(tag) => {
                nesting += 1;
                if nesting > 256 {
                    return Err(limit());
                }
                match tag {
                    Tag::Heading { level, id, .. } => {
                        output.push('<');
                        output.push_str(&level.to_string());
                        if let Some(id) = id {
                            output.push_str(" id=\"");
                            escaped(&mut output, &id)?;
                            output.push('"');
                        }
                        output.push('>');
                    }
                    Tag::Link { dest_url, .. } if safe_target(&dest_url) => {
                        output.push_str("<a href=\"");
                        escaped(&mut output, &dest_url)?;
                        output.push_str("\">");
                    }
                    Tag::Paragraph => output.push_str("<p>"),
                    Tag::Item => output.push_str("<li>"),
                    Tag::CodeBlock(_) => output.push_str("<pre>"),
                    Tag::TableRow => output.push_str("<tr>"),
                    Tag::TableCell => output.push_str("<td>"),
                    _ => {}
                }
            }
            Event::End(tag) => {
                nesting = nesting.saturating_sub(1);
                match tag {
                    TagEnd::Heading(level) => {
                        output.push_str("</");
                        output.push_str(&level.to_string());
                        output.push('>');
                    }
                    TagEnd::Link => output.push_str("</a>"),
                    TagEnd::Paragraph => output.push_str("</p>"),
                    TagEnd::Item => output.push_str("</li>"),
                    TagEnd::CodeBlock => output.push_str("</pre>"),
                    TagEnd::TableRow => output.push_str("</tr>"),
                    TagEnd::TableCell => output.push_str("</td>"),
                    _ => {}
                }
            }
            Event::Text(text)
            | Event::Code(text)
            | Event::InlineMath(text)
            | Event::DisplayMath(text) => escaped(&mut output, &text)?,
            Event::Html(html) | Event::InlineHtml(html) => output.push_str(&html),
            Event::SoftBreak | Event::HardBreak | Event::Rule => output.push('\n'),
            Event::FootnoteReference(text) => escaped(&mut output, &text)?,
            Event::TaskListMarker(checked) => {
                output.push_str(if checked { "[x] " } else { "[ ] " })
            }
        }
        if output.len() > MAX_INPUT * 2 {
            return Err(limit());
        }
    }
    super::html::project(&output, budget)
}

#[cfg(test)]
mod tests {
    use tokio_util::sync::CancellationToken;
    #[test]
    fn markdown_preserves_code_links_and_hides_raw_scripts() {
        let doc=super::super::process_document("README.md",b"# Standard\n\n## Examples {#examples}\n\n`<script>inert()</script>` [reference](https://url.spec.whatwg.org/)\n\n<script>hidden()</script>\n",CancellationToken::new()).unwrap();
        assert!(doc.text.contains("<script>inert()</script>"));
        assert!(!doc.text.contains("hidden()"));
        assert!(doc.sections.iter().any(|s| s.anchor == "examples"));
        assert_eq!(doc.references[0].label, "reference");
    }
}
