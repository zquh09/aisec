use chrono::Local;
use printpdf::*;
use std::fs;
use std::path::Path;

const PAGE_WIDTH_MM: f32 = 210.0;
const PAGE_HEIGHT_MM: f32 = 297.0;
const MARGIN_MM: f32 = 15.0;
const FONT_SIZE_PT: f32 = 9.0;
const LINE_HEIGHT_MM: f32 = 5.0;
const MAX_CHARS_PER_LINE: usize = 90;

fn wrap_line(line: &str, max_chars: usize) -> Vec<String> {
    if line.is_empty() { return vec![String::new()]; }
    let mut result = Vec::new();
    let mut current = String::new();
    let mut count = 0;
    for ch in line.chars() {
        if count >= max_chars { result.push(current); current = String::new(); count = 0; }
        current.push(ch);
        count += 1;
    }
    if !current.is_empty() { result.push(current); }
    result
}

pub fn export_pdf(path: &str, title: &str, content: &str) -> Result<(), String> {
    if path.trim().is_empty() { return Err("Путь к PDF не указан".to_string()); }
    let output_path = Path::new(path);
    if output_path.is_dir() { return Err("Указанный путь — каталог".to_string()); }

    let mut doc = PdfDocument::new(title);
    let date = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut lines: Vec<(String, f32)> = Vec::new();
    lines.push((title.to_string(), 16.0));
    lines.push((format!("Date: {}", date), 9.0));
    lines.push((String::new(), 9.0));
    lines.push(("=".repeat(60), 9.0));
    lines.push((String::new(), 9.0));

    for source_line in content.lines() {
        for line in wrap_line(source_line, MAX_CHARS_PER_LINE) {
            lines.push((line, FONT_SIZE_PT));
        }
    }
    if content.is_empty() { lines.push(("(Empty report)".to_string(), FONT_SIZE_PT)); }

    let usable_height = PAGE_HEIGHT_MM - MARGIN_MM * 2.0;
    let lines_per_page = (usable_height / LINE_HEIGHT_MM) as usize;
    let mut pages = Vec::new();

    for chunk in lines.chunks(lines_per_page.max(1)) {
        let mut ops = Vec::new();
        for (index, (line, font_size)) in chunk.iter().enumerate() {
            let y = PAGE_HEIGHT_MM - MARGIN_MM - (index as f32 * LINE_HEIGHT_MM);
            ops.push(Op::StartTextSection);
            
            // Используем встроенный Courier
            ops.push(Op::SetFont { 
                font: PdfFontHandle::Builtin(BuiltinFont::Courier), 
                size: Pt(*font_size) 
            });
            
            ops.push(Op::SetTextCursor { pos: Point { x: Mm(MARGIN_MM).into(), y: Mm(y).into() } });
            ops.push(Op::ShowText { items: vec![TextItem::Text(line.clone())] });
            ops.push(Op::EndTextSection);
        }
        pages.push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
    }

    doc.with_pages(pages);
    let mut save_warnings = Vec::new();
    let pdf_bytes = doc.save(&PdfSaveOptions::default(), &mut save_warnings);
    fs::write(output_path, pdf_bytes).map_err(|e| format!("Не удалось сохранить PDF: {}", e))?;
    Ok(())
}