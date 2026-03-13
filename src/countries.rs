/// Map ISO 3166-1 alpha-2 country code to English name.
/// Returns the code itself if not found (graceful fallback).
/// Case-insensitive — uses ASCII uppercase comparison (no allocation).
pub fn country_name(code: &str) -> &str {
    let bytes = code.as_bytes();
    if bytes.len() != 2 {
        return code;
    }
    let upper = [bytes[0].to_ascii_uppercase(), bytes[1].to_ascii_uppercase()];
    match &upper {
        b"AL" => "Albania",
        b"AT" => "Austria",
        b"AU" => "Australia",
        b"BE" => "Belgium",
        b"BG" => "Bulgaria",
        b"BR" => "Brazil",
        b"CA" => "Canada",
        b"CH" => "Switzerland",
        b"CL" => "Chile",
        b"CZ" => "Czech Republic",
        b"DE" => "Germany",
        b"DK" => "Denmark",
        b"EE" => "Estonia",
        b"ES" => "Spain",
        b"FI" => "Finland",
        b"FR" => "France",
        b"GB" => "United Kingdom",
        b"GR" => "Greece",
        b"HK" => "Hong Kong",
        b"HR" => "Croatia",
        b"HU" => "Hungary",
        b"IE" => "Ireland",
        b"IL" => "Israel",
        b"IN" => "India",
        b"IS" => "Iceland",
        b"IT" => "Italy",
        b"JP" => "Japan",
        b"KR" => "South Korea",
        b"LT" => "Lithuania",
        b"LU" => "Luxembourg",
        b"LV" => "Latvia",
        b"MD" => "Moldova",
        b"MX" => "Mexico",
        b"MY" => "Malaysia",
        b"NL" => "Netherlands",
        b"NO" => "Norway",
        b"NZ" => "New Zealand",
        b"PH" => "Philippines",
        b"PL" => "Poland",
        b"PT" => "Portugal",
        b"RO" => "Romania",
        b"RS" => "Serbia",
        b"SE" => "Sweden",
        b"SG" => "Singapore",
        b"SI" => "Slovenia",
        b"SK" => "Slovakia",
        b"TH" => "Thailand",
        b"TR" => "Turkey",
        b"TW" => "Taiwan",
        b"UA" => "Ukraine",
        b"US" => "United States",
        b"ZA" => "South Africa",
        _ => return code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_code() {
        assert_eq!(country_name("DE"), "Germany");
        assert_eq!(country_name("de"), "Germany");
        assert_eq!(country_name("De"), "Germany");
    }

    #[test]
    fn unknown_code_returns_input() {
        assert_eq!(country_name("XX"), "XX");
        assert_eq!(country_name(""), "");
        assert_eq!(country_name("USA"), "USA");
    }
}
