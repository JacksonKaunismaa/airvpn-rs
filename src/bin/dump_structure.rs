//! Dump the top-level XML structure of the manifest (element names only, no values).
//! This is safe to share — it shows structure, not credentials.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

fn main() -> anyhow::Result<()> {
    let provider_config = airvpn::api::load_provider_config()?;
    let (username, password) = airvpn::config::resolve_credentials(None, None)?;
    let xml = airvpn::api::fetch_manifest(&provider_config, &username, &password)?;

    println!("=== Manifest XML Structure (element names only) ===\n");
    println!("Total XML length: {} bytes\n", xml.len());

    let mut reader = Reader::from_str(&xml);
    let mut depth = 0;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attrs: Vec<String> = e.attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| String::from_utf8_lossy(a.key.as_ref()).to_string())
                    .collect();
                let indent = "  ".repeat(depth);
                if attrs.is_empty() {
                    println!("{}<{}>", indent, name);
                } else {
                    println!("{}<{} [attrs: {}]>", indent, name, attrs.join(", "));
                }
                depth += 1;
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attrs: Vec<String> = e.attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| String::from_utf8_lossy(a.key.as_ref()).to_string())
                    .collect();
                let indent = "  ".repeat(depth);
                if attrs.is_empty() {
                    println!("{}<{}/>", indent, name);
                } else {
                    println!("{}<{} [attrs: {}]/>", indent, name, attrs.join(", "));
                }
            }
            Ok(Event::End(e)) => {
                depth -= 1;
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let indent = "  ".repeat(depth);
                println!("{}</{}>", indent, name);
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                println!("XML parse error: {}", e);
                break;
            }
        }
        buf.clear();
    }

    Ok(())
}
