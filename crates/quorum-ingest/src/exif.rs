//! Pure-Rust TIFF/EXIF IFD parser with GPS (tag 0x8825), XMP and IPTC location extraction.
//!
//! Handles the TIFF structure embedded in JPEG APP1 (`Exif\0\0`), PNG `eXIf`, and WebP
//! `EXIF` chunks: byte order (`II`/`MM`), IFD0 entries, the Exif sub-IFD (0x8769) and the
//! GPS sub-IFD (0x8825). GPS latitude/longitude are three unsigned RATIONALs
//! (degrees, minutes, seconds) converted to signed decimal degrees using the N/S and E/W
//! reference tags. All offsets are bounds-checked; malformed input yields `None` fields,
//! never a panic.

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ExifData {
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub software: Option<String>,
    pub date_time_original: Option<String>,
    pub image_description: Option<String>,
    pub iso_speed: Option<u32>,
    pub f_number: Option<f32>,
    pub exposure_time: Option<String>,
    pub focal_length_mm: Option<f32>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude_m: Option<f64>,
    pub gps_date_stamp: Option<String>,
    /// Windows "XPKeywords" / XMP dc:subject keywords.
    pub keywords: Vec<String>,
}

/// Location text fields from XMP / IPTC metadata (photographer- or app-assigned).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TaggedLocation {
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub sublocation: Option<String>,
    pub keywords: Vec<String>,
    pub description: Option<String>,
}

#[derive(Clone, Copy)]
struct Tiff<'a> {
    data: &'a [u8],
    le: bool,
}

impl<'a> Tiff<'a> {
    fn u16_at(&self, off: usize) -> Option<u16> {
        let b = self.data.get(off..off + 2)?;
        Some(if self.le { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
    }
    fn u32_at(&self, off: usize) -> Option<u32> {
        let b = self.data.get(off..off + 4)?;
        Some(if self.le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }
}

/// One IFD entry with its raw value location resolved.
#[derive(Clone, Copy)]
struct Entry {
    tag: u16,
    typ: u16,
    count: u32,
    /// Offset of the value bytes (inline value field or pointed-to data).
    value_off: usize,
}

fn type_size(typ: u16) -> usize {
    match typ {
        1 | 2 | 6 | 7 => 1, // BYTE, ASCII, SBYTE, UNDEFINED
        3 | 8 => 2,         // SHORT, SSHORT
        4 | 9 | 11 => 4,    // LONG, SLONG, FLOAT
        5 | 10 | 12 => 8,   // RATIONAL, SRATIONAL, DOUBLE
        _ => 0,
    }
}

fn read_ifd(t: &Tiff, ifd_off: usize) -> Vec<Entry> {
    let mut out = Vec::new();
    let Some(n) = t.u16_at(ifd_off) else { return out };
    // Guard against absurd counts in corrupt files.
    let n = (n as usize).min(512);
    for i in 0..n {
        let e = ifd_off + 2 + i * 12;
        let (Some(tag), Some(typ), Some(count)) = (t.u16_at(e), t.u16_at(e + 2), t.u32_at(e + 4)) else {
            break;
        };
        let size = type_size(typ).saturating_mul(count as usize);
        if size == 0 {
            continue;
        }
        let value_off = if size <= 4 {
            e + 8
        } else {
            match t.u32_at(e + 8) {
                Some(o) => o as usize,
                None => continue,
            }
        };
        if value_off.checked_add(size).map_or(true, |end| end > t.data.len()) {
            continue;
        }
        out.push(Entry { tag, typ, count, value_off });
    }
    out
}

fn ascii(t: &Tiff, e: &Entry) -> Option<String> {
    if e.typ != 2 && e.typ != 7 && e.typ != 1 {
        return None;
    }
    let bytes = t.data.get(e.value_off..e.value_off + e.count as usize)?;
    let s: String = bytes
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    let s = s.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn rational(t: &Tiff, off: usize, signed: bool) -> Option<f64> {
    let n = t.u32_at(off)?;
    let d = t.u32_at(off + 4)?;
    if d == 0 {
        return None;
    }
    Some(if signed { (n as i32) as f64 / (d as i32) as f64 } else { n as f64 / d as f64 })
}

fn first_number(t: &Tiff, e: &Entry) -> Option<f64> {
    match e.typ {
        3 => t.u16_at(e.value_off).map(|v| v as f64),
        4 => t.u32_at(e.value_off).map(|v| v as f64),
        5 => rational(t, e.value_off, false),
        10 => rational(t, e.value_off, true),
        _ => None,
    }
}

fn dms_to_decimal(t: &Tiff, e: &Entry) -> Option<f64> {
    if e.typ != 5 || e.count < 3 {
        return None;
    }
    let d = rational(t, e.value_off, false)?;
    let m = rational(t, e.value_off + 8, false)?;
    let s = rational(t, e.value_off + 16, false)?;
    if !(0.0..=180.0).contains(&d) || !(0.0..60.0).contains(&m) || !(0.0..60.0 + 1e-6).contains(&s) {
        return None;
    }
    Some(d + m / 60.0 + s / 3600.0)
}

fn utf16le_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units).trim_matches('\0').trim().to_string()
}

/// Parse a raw TIFF stream (starting at the `II*\0` / `MM\0*` header).
pub fn parse_tiff(data: &[u8]) -> ExifData {
    let mut out = ExifData::default();
    if data.len() < 8 {
        return out;
    }
    let le = match &data[0..4] {
        [b'I', b'I', 0x2A, 0x00] => true,
        [b'M', b'M', 0x00, 0x2A] => false,
        _ => return out,
    };
    let t = Tiff { data, le };
    let Some(ifd0) = t.u32_at(4) else { return out };

    let mut exif_ifd = None;
    let mut gps_ifd = None;
    for e in read_ifd(&t, ifd0 as usize) {
        match e.tag {
            0x010F => out.camera_make = ascii(&t, &e),
            0x0110 => out.camera_model = ascii(&t, &e),
            0x0131 => out.software = ascii(&t, &e),
            0x010E => out.image_description = ascii(&t, &e),
            0x0132 if out.date_time_original.is_none() => out.date_time_original = ascii(&t, &e),
            0x8769 => exif_ifd = t.u32_at(e.value_off),
            0x8825 => gps_ifd = t.u32_at(e.value_off),
            // Windows XPKeywords (UTF-16LE, ';'-separated) and XPSubject
            0x9C9E | 0x9C9F => {
                if let Some(b) = t.data.get(e.value_off..e.value_off + e.count as usize) {
                    for k in utf16le_string(b).split(';') {
                        let k = k.trim();
                        if !k.is_empty() && !out.keywords.iter().any(|x| x.eq_ignore_ascii_case(k)) {
                            out.keywords.push(k.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if let Some(off) = exif_ifd {
        for e in read_ifd(&t, off as usize) {
            match e.tag {
                0x9003 => out.date_time_original = ascii(&t, &e).or(out.date_time_original.take()),
                0x8827 => out.iso_speed = first_number(&t, &e).map(|v| v as u32),
                0x829D => out.f_number = first_number(&t, &e).map(|v| v as f32),
                0x920A => out.focal_length_mm = first_number(&t, &e).map(|v| v as f32),
                0x829A => {
                    if let Some(v) = first_number(&t, &e) {
                        out.exposure_time = Some(if v > 0.0 && v < 1.0 {
                            format!("1/{}", (1.0 / v).round() as u32)
                        } else {
                            format!("{v}")
                        });
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(off) = gps_ifd {
        let mut lat_ref = None;
        let mut lon_ref = None;
        let mut lat = None;
        let mut lon = None;
        let mut alt = None;
        let mut alt_ref_below = false;
        for e in read_ifd(&t, off as usize) {
            match e.tag {
                0x0001 => lat_ref = t.data.get(e.value_off).copied(),
                0x0002 => lat = dms_to_decimal(&t, &e),
                0x0003 => lon_ref = t.data.get(e.value_off).copied(),
                0x0004 => lon = dms_to_decimal(&t, &e),
                0x0005 => alt_ref_below = t.data.get(e.value_off).copied() == Some(1),
                0x0006 => alt = first_number(&t, &e),
                0x001D => out.gps_date_stamp = ascii(&t, &e),
                _ => {}
            }
        }
        if let (Some(la), Some(lo)) = (lat, lon) {
            let la = if matches!(lat_ref, Some(b'S') | Some(b's')) { -la } else { la };
            let lo = if matches!(lon_ref, Some(b'W') | Some(b'w')) { -lo } else { lo };
            if (-90.0..=90.0).contains(&la) && (-180.0..=180.0).contains(&lo) && !(la == 0.0 && lo == 0.0) {
                out.gps_latitude = Some(la);
                out.gps_longitude = Some(lo);
            }
        }
        out.gps_altitude_m = alt.map(|a| if alt_ref_below { -a } else { a });
    }

    out
}

/// Locate the TIFF stream inside a JPEG (APP1 Exif), PNG (eXIf) or WebP (EXIF) file.
pub fn find_tiff_in_image(bytes: &[u8]) -> Option<&[u8]> {
    // JPEG
    if bytes.starts_with(&[0xFF, 0xD8]) {
        let mut off = 2;
        while off + 4 <= bytes.len() {
            if bytes[off] != 0xFF {
                return None;
            }
            let marker = bytes[off + 1];
            if marker == 0xD8 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
                off += 2;
                continue;
            }
            if marker == 0xDA || marker == 0xD9 {
                return None;
            }
            let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            if len < 2 || off + 2 + len > bytes.len() {
                return None;
            }
            let seg = &bytes[off + 4..off + 2 + len];
            if marker == 0xE1 && seg.starts_with(b"Exif\0\0") {
                return Some(&seg[6..]);
            }
            off += 2 + len;
        }
        return None;
    }
    // PNG
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut off = 8;
        while off + 12 <= bytes.len() {
            let len = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize;
            let typ = &bytes[off + 4..off + 8];
            let end = off.checked_add(12)?.checked_add(len)?;
            if end > bytes.len() {
                return None;
            }
            if typ == b"eXIf" {
                return Some(&bytes[off + 8..off + 8 + len]);
            }
            if typ == b"IEND" {
                return None;
            }
            off = end;
        }
        return None;
    }
    // WebP (RIFF....WEBP, chunk "EXIF")
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        let mut off = 12;
        while off + 8 <= bytes.len() {
            let typ = &bytes[off..off + 4];
            let len = u32::from_le_bytes([bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]]) as usize;
            let start = off + 8;
            let end = start.checked_add(len)?;
            if end > bytes.len() {
                return None;
            }
            if typ == b"EXIF" {
                let payload = &bytes[start..end];
                return Some(payload.strip_prefix(b"Exif\0\0").unwrap_or(payload));
            }
            off = end + (len & 1);
        }
        return None;
    }
    // Bare TIFF
    if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        return Some(bytes);
    }
    None
}

fn xml_tag_text(xmp: &str, names: &[&str]) -> Option<String> {
    for name in names {
        // Element form: <photoshop:City>La Grange</photoshop:City>
        let open = format!("<{name}>");
        if let Some(p) = xmp.find(&open) {
            let rest = &xmp[p + open.len()..];
            if let Some(end) = rest.find(&format!("</{name}>")) {
                let v = strip_xml(&rest[..end]);
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        // Attribute form: photoshop:City="La Grange"
        let attr = format!("{name}=\"");
        if let Some(p) = xmp.find(&attr) {
            let rest = &xmp[p + attr.len()..];
            if let Some(end) = rest.find('"') {
                let v = rest[..end].trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

fn strip_xml(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Extract XMP packet location/keyword fields (photoshop:, Iptc4xmpCore:, dc:).
pub fn parse_xmp(bytes: &[u8]) -> TaggedLocation {
    let mut loc = TaggedLocation::default();
    let Some(start) = find_sub(bytes, b"<x:xmpmeta") else { return loc };
    let end = find_sub(&bytes[start..], b"</x:xmpmeta>").map(|e| start + e + 12).unwrap_or(bytes.len().min(start + 256 * 1024));
    let xmp = String::from_utf8_lossy(&bytes[start..end]);
    loc.city = xml_tag_text(&xmp, &["photoshop:City", "Iptc4xmpExt:City"]);
    loc.state = xml_tag_text(&xmp, &["photoshop:State", "Iptc4xmpExt:ProvinceState"]);
    loc.country = xml_tag_text(&xmp, &["photoshop:Country", "Iptc4xmpExt:CountryName"]);
    loc.sublocation = xml_tag_text(&xmp, &["Iptc4xmpCore:Location", "Iptc4xmpExt:Sublocation"]);
    loc.description = xml_tag_text(&xmp, &["dc:description", "dc:title"]);
    if let Some(subj) = xml_tag_text(&xmp, &["dc:subject"]) {
        loc.keywords = subj.split(|c| c == ' ' || c == ',' || c == ';').filter(|s| s.len() > 1).map(str::to_string).collect();
    }
    loc
}

/// Extract IPTC-IIM record 2 location fields from a JPEG APP13 Photoshop block.
pub fn parse_iptc(bytes: &[u8]) -> TaggedLocation {
    let mut loc = TaggedLocation::default();
    let Some(pos) = find_sub(bytes, b"Photoshop 3.0\0") else { return loc };
    let region = &bytes[pos..bytes.len().min(pos + 128 * 1024)];
    let mut i = 0;
    while i + 5 <= region.len() {
        if region[i] == 0x1C && region[i + 1] == 0x02 {
            let ds = region[i + 2];
            let len = u16::from_be_bytes([region[i + 3], region[i + 4]]) as usize;
            let start = i + 5;
            if start + len > region.len() {
                break;
            }
            let text = String::from_utf8_lossy(&region[start..start + len]).trim().to_string();
            if !text.is_empty() {
                match ds {
                    90 => loc.city = Some(text),
                    92 => loc.sublocation = Some(text),
                    95 => loc.state = Some(text),
                    101 => loc.country = Some(text),
                    120 => loc.description = Some(text),
                    25 => loc.keywords.push(text),
                    _ => {}
                }
            }
            i = start + len;
        } else {
            i += 1;
        }
    }
    loc
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Build a minimal little-endian TIFF with Make + GPS IFD for the given DMS values.
    pub fn tiff_with_gps(lat: [u32; 3], lat_ref: u8, lon: [u32; 3], lon_ref: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"II*\0");
        v.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at 8
        // IFD0: 2 entries (Make, GPSInfo)
        let ifd0_entries = 2u16;
        let ifd0_size = 2 + 12 * ifd0_entries as usize + 4;
        let make_off = 8 + ifd0_size;
        let make = b"TestCam\0";
        let gps_ifd_off = make_off + make.len();
        v.extend_from_slice(&ifd0_entries.to_le_bytes());
        // Make (0x010F ASCII)
        v.extend_from_slice(&0x010Fu16.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&(make.len() as u32).to_le_bytes());
        v.extend_from_slice(&(make_off as u32).to_le_bytes());
        // GPSInfo (0x8825 LONG)
        v.extend_from_slice(&0x8825u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&(gps_ifd_off as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // next IFD
        v.extend_from_slice(make);
        // GPS IFD: 4 entries
        let gps_entries = 4u16;
        let gps_size = 2 + 12 * gps_entries as usize + 4;
        let lat_off = gps_ifd_off + gps_size;
        let lon_off = lat_off + 24;
        v.extend_from_slice(&gps_entries.to_le_bytes());
        for (tag, typ, count, val) in [
            (1u16, 2u16, 2u32, u32::from_le_bytes([lat_ref, 0, 0, 0])),
            (2, 5, 3, lat_off as u32),
            (3, 2, 2, u32::from_le_bytes([lon_ref, 0, 0, 0])),
            (4, 5, 3, lon_off as u32),
        ] {
            v.extend_from_slice(&tag.to_le_bytes());
            v.extend_from_slice(&typ.to_le_bytes());
            v.extend_from_slice(&count.to_le_bytes());
            v.extend_from_slice(&val.to_le_bytes());
        }
        v.extend_from_slice(&0u32.to_le_bytes());
        for x in lat.iter().chain(lon.iter()) {
            v.extend_from_slice(&x.to_le_bytes());
            v.extend_from_slice(&1u32.to_le_bytes());
        }
        v
    }

    /// Wrap a TIFF stream in a minimal JPEG (SOI, APP1 Exif, SOF0 1x1, EOI).
    pub fn jpeg_with_tiff(tiff: &[u8]) -> Vec<u8> {
        let mut j = vec![0xFF, 0xD8, 0xFF, 0xE1];
        let len = (2 + 6 + tiff.len()) as u16;
        j.extend_from_slice(&len.to_be_bytes());
        j.extend_from_slice(b"Exif\0\0");
        j.extend_from_slice(tiff);
        // SOF0: len 11, precision 8, height 1, width 1, 1 component
        j.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00]);
        j.extend_from_slice(&[0xFF, 0xD9]);
        j
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn parses_gps_dms_la_grange_texas() {
        // 29 54' 20" N, 96 52' 36" W
        let tiff = tiff_with_gps([29, 54, 20], b'N', [96, 52, 36], b'W');
        let jpeg = jpeg_with_tiff(&tiff);
        let found = find_tiff_in_image(&jpeg).expect("tiff");
        let ex = parse_tiff(found);
        assert_eq!(ex.camera_make.as_deref(), Some("TestCam"));
        let lat = ex.gps_latitude.unwrap();
        let lon = ex.gps_longitude.unwrap();
        assert!((lat - 29.9056).abs() < 1e-3, "lat {lat}");
        assert!((lon + 96.8767).abs() < 1e-3, "lon {lon}");
    }

    #[test]
    fn southern_eastern_refs_flip_sign() {
        let tiff = tiff_with_gps([33, 52, 8], b'S', [151, 12, 33], b'E');
        let ex = parse_tiff(&tiff);
        assert!(ex.gps_latitude.unwrap() < 0.0);
        assert!(ex.gps_longitude.unwrap() > 0.0);
    }

    #[test]
    fn truncated_tiff_does_not_panic() {
        let tiff = tiff_with_gps([29, 54, 20], b'N', [96, 52, 36], b'W');
        for cut in 0..tiff.len() {
            let _ = parse_tiff(&tiff[..cut]);
        }
    }

    #[test]
    fn xmp_and_iptc_location() {
        let xmp = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:Description photoshop:City="La Grange" photoshop:State="Texas"><photoshop:Country>United States</photoshop:Country></rdf:Description></x:xmpmeta>"#;
        let l = parse_xmp(xmp);
        assert_eq!(l.city.as_deref(), Some("La Grange"));
        assert_eq!(l.state.as_deref(), Some("Texas"));
        assert_eq!(l.country.as_deref(), Some("United States"));

        let mut iptc = b"Photoshop 3.0\0".to_vec();
        iptc.extend_from_slice(&[0x1C, 0x02, 90, 0x00, 9]);
        iptc.extend_from_slice(b"La Grange");
        let l2 = parse_iptc(&iptc);
        assert_eq!(l2.city.as_deref(), Some("La Grange"));
    }
}
