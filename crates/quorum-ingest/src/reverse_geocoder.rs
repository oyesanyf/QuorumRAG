//! Offline deterministic reverse-geocoder for geotagged media.
//!
//! QuorumRAG is local-first and air-gapped, so coordinates extracted from EXIF GPS
//! IFDs are resolved against an embedded gazetteer of real place coordinates using the
//! haversine great-circle distance. No network calls are ever made.
//!
//! Coverage: the embedded gazetteer contains the La Grange towns (TX, IL, KY, GA, NC,
//! TN, WY), all US state capitals and the largest US metros, and major world cities.
//! A coordinate is attributed to a place only when it falls within that place's
//! radius; otherwise the nearest place is reported as "near <place>" when within
//! `NEAR_RADIUS_KM`, and `None` beyond that. This keeps answers honest: a photo is never
//! labelled with a town it was not taken in.

use serde::{Deserialize, Serialize};

/// Resolved human-readable location for a coordinate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    pub city: String,
    pub county: Option<String>,
    pub state: Option<String>,
    pub state_code: Option<String>,
    pub country: String,
    /// Great-circle distance from the coordinate to the place centroid.
    pub distance_km: f64,
    /// `true` when the coordinate is within the place radius (taken *in* the place),
    /// `false` when it is merely the nearest known place ("near").
    pub within: bool,
    pub display_name: String,
    /// Lowercase search tokens (city words, county, state name and code, country).
    pub tokens: Vec<String>,
}

/// Radius beyond a place's own radius within which we still report "near <place>".
pub const NEAR_RADIUS_KM: f64 = 60.0;

struct Place {
    city: &'static str,
    county: Option<&'static str>,
    state: Option<&'static str>,
    state_code: Option<&'static str>,
    country: &'static str,
    lat: f64,
    lon: f64,
    radius_km: f64,
}

const fn us(
    city: &'static str,
    county: &'static str,
    state: &'static str,
    code: &'static str,
    lat: f64,
    lon: f64,
    radius_km: f64,
) -> Place {
    Place {
        city,
        county: Some(county),
        state: Some(state),
        state_code: Some(code),
        country: "United States",
        lat,
        lon,
        radius_km,
    }
}

const fn intl(city: &'static str, region: Option<&'static str>, country: &'static str, lat: f64, lon: f64, radius_km: f64) -> Place {
    Place {
        city,
        county: None,
        state: region,
        state_code: None,
        country,
        lat,
        lon,
        radius_km,
    }
}

/// Embedded gazetteer (real WGS84 town/city centroids).
static GAZETTEER: &[Place] = &[
    // --- La Grange towns ---
    us("La Grange", "Fayette County", "Texas", "TX", 29.9055, -96.8766, 8.0),
    us("La Grange", "Cook County", "Illinois", "IL", 41.8050, -87.8692, 4.0),
    us("La Grange Park", "Cook County", "Illinois", "IL", 41.8350, -87.8695, 2.5),
    us("La Grange", "Oldham County", "Kentucky", "KY", 38.4076, -85.3789, 7.0),
    us("LaGrange", "Troup County", "Georgia", "GA", 33.0393, -85.0313, 10.0),
    us("La Grange", "Lenoir County", "North Carolina", "NC", 35.3068, -77.7889, 4.0),
    us("La Grange", "Fayette County", "Tennessee", "TN", 35.0459, -89.2398, 3.0),
    us("La Grange", "Goshen County", "Wyoming", "WY", 41.6380, -104.1630, 3.0),
    us("LaGrange", "LaGrange County", "Indiana", "IN", 41.6417, -85.4166, 4.0),
    // --- Major US metros and state capitals ---
    us("New York", "New York County", "New York", "NY", 40.7128, -74.0060, 30.0),
    us("Los Angeles", "Los Angeles County", "California", "CA", 34.0522, -118.2437, 35.0),
    us("Chicago", "Cook County", "Illinois", "IL", 41.8781, -87.6298, 18.0),
    us("Houston", "Harris County", "Texas", "TX", 29.7604, -95.3698, 35.0),
    us("Phoenix", "Maricopa County", "Arizona", "AZ", 33.4484, -112.0740, 30.0),
    us("Philadelphia", "Philadelphia County", "Pennsylvania", "PA", 39.9526, -75.1652, 18.0),
    us("San Antonio", "Bexar County", "Texas", "TX", 29.4241, -98.4936, 30.0),
    us("San Diego", "San Diego County", "California", "CA", 32.7157, -117.1611, 25.0),
    us("Dallas", "Dallas County", "Texas", "TX", 32.7767, -96.7970, 30.0),
    us("Austin", "Travis County", "Texas", "TX", 30.2672, -97.7431, 25.0),
    us("San Jose", "Santa Clara County", "California", "CA", 37.3382, -121.8863, 20.0),
    us("Fort Worth", "Tarrant County", "Texas", "TX", 32.7555, -97.3308, 20.0),
    us("Jacksonville", "Duval County", "Florida", "FL", 30.3322, -81.6557, 30.0),
    us("Columbus", "Franklin County", "Ohio", "OH", 39.9612, -82.9988, 20.0),
    us("Charlotte", "Mecklenburg County", "North Carolina", "NC", 35.2271, -80.8431, 22.0),
    us("Indianapolis", "Marion County", "Indiana", "IN", 39.7684, -86.1581, 20.0),
    us("San Francisco", "San Francisco County", "California", "CA", 37.7749, -122.4194, 10.0),
    us("Seattle", "King County", "Washington", "WA", 47.6062, -122.3321, 15.0),
    us("Denver", "Denver County", "Colorado", "CO", 39.7392, -104.9903, 18.0),
    us("Washington", "District of Columbia", "District of Columbia", "DC", 38.9072, -77.0369, 12.0),
    us("Boston", "Suffolk County", "Massachusetts", "MA", 42.3601, -71.0589, 12.0),
    us("Nashville", "Davidson County", "Tennessee", "TN", 36.1627, -86.7816, 20.0),
    us("Detroit", "Wayne County", "Michigan", "MI", 42.3314, -83.0458, 18.0),
    us("Memphis", "Shelby County", "Tennessee", "TN", 35.1495, -90.0490, 20.0),
    us("Louisville", "Jefferson County", "Kentucky", "KY", 38.2527, -85.7585, 18.0),
    us("Portland", "Multnomah County", "Oregon", "OR", 45.5152, -122.6784, 15.0),
    us("Las Vegas", "Clark County", "Nevada", "NV", 36.1699, -115.1398, 20.0),
    us("Baltimore", "Baltimore City", "Maryland", "MD", 39.2904, -76.6122, 12.0),
    us("Milwaukee", "Milwaukee County", "Wisconsin", "WI", 43.0389, -87.9065, 15.0),
    us("Albuquerque", "Bernalillo County", "New Mexico", "NM", 35.0844, -106.6504, 18.0),
    us("Atlanta", "Fulton County", "Georgia", "GA", 33.7490, -84.3880, 20.0),
    us("Miami", "Miami-Dade County", "Florida", "FL", 25.7617, -80.1918, 15.0),
    us("Tampa", "Hillsborough County", "Florida", "FL", 27.9506, -82.4572, 18.0),
    us("Orlando", "Orange County", "Florida", "FL", 28.5383, -81.3792, 18.0),
    us("New Orleans", "Orleans Parish", "Louisiana", "LA", 29.9511, -90.0715, 15.0),
    us("Minneapolis", "Hennepin County", "Minnesota", "MN", 44.9778, -93.2650, 15.0),
    us("St. Louis", "St. Louis City", "Missouri", "MO", 38.6270, -90.1994, 15.0),
    us("Kansas City", "Jackson County", "Missouri", "MO", 39.0997, -94.5786, 20.0),
    us("Pittsburgh", "Allegheny County", "Pennsylvania", "PA", 40.4406, -79.9959, 15.0),
    us("Cleveland", "Cuyahoga County", "Ohio", "OH", 41.4993, -81.6944, 15.0),
    us("Cincinnati", "Hamilton County", "Ohio", "OH", 39.1031, -84.5120, 15.0),
    us("Salt Lake City", "Salt Lake County", "Utah", "UT", 40.7608, -111.8910, 15.0),
    us("Sacramento", "Sacramento County", "California", "CA", 38.5816, -121.4944, 18.0),
    us("Raleigh", "Wake County", "North Carolina", "NC", 35.7796, -78.6382, 15.0),
    us("Richmond", "Richmond City", "Virginia", "VA", 37.5407, -77.4360, 12.0),
    us("Oklahoma City", "Oklahoma County", "Oklahoma", "OK", 35.4676, -97.5164, 25.0),
    us("Tulsa", "Tulsa County", "Oklahoma", "OK", 36.1540, -95.9928, 18.0),
    us("Omaha", "Douglas County", "Nebraska", "NE", 41.2565, -95.9345, 15.0),
    us("Honolulu", "Honolulu County", "Hawaii", "HI", 21.3069, -157.8583, 12.0),
    us("Anchorage", "Anchorage Municipality", "Alaska", "AK", 61.2181, -149.9003, 20.0),
    us("Little Rock", "Pulaski County", "Arkansas", "AR", 34.7465, -92.2896, 15.0),
    us("Birmingham", "Jefferson County", "Alabama", "AL", 33.5186, -86.8104, 15.0),
    us("Montgomery", "Montgomery County", "Alabama", "AL", 32.3792, -86.3077, 12.0),
    us("Jackson", "Hinds County", "Mississippi", "MS", 32.2988, -90.1848, 12.0),
    us("Baton Rouge", "East Baton Rouge Parish", "Louisiana", "LA", 30.4515, -91.1871, 15.0),
    us("Columbia", "Richland County", "South Carolina", "SC", 34.0007, -81.0348, 12.0),
    us("Charleston", "Charleston County", "South Carolina", "SC", 32.7765, -79.9311, 12.0),
    us("Savannah", "Chatham County", "Georgia", "GA", 32.0809, -81.0912, 12.0),
    us("Tallahassee", "Leon County", "Florida", "FL", 30.4383, -84.2807, 12.0),
    us("Frankfort", "Franklin County", "Kentucky", "KY", 38.2009, -84.8733, 8.0),
    us("Springfield", "Sangamon County", "Illinois", "IL", 39.7817, -89.6501, 10.0),
    us("Madison", "Dane County", "Wisconsin", "WI", 43.0731, -89.4012, 12.0),
    us("Lansing", "Ingham County", "Michigan", "MI", 42.7325, -84.5555, 10.0),
    us("Des Moines", "Polk County", "Iowa", "IA", 41.5868, -93.6250, 12.0),
    us("Topeka", "Shawnee County", "Kansas", "KS", 39.0473, -95.6752, 10.0),
    us("Lincoln", "Lancaster County", "Nebraska", "NE", 40.8136, -96.7026, 10.0),
    us("Bismarck", "Burleigh County", "North Dakota", "ND", 46.8083, -100.7837, 8.0),
    us("Pierre", "Hughes County", "South Dakota", "SD", 44.3683, -100.3510, 6.0),
    us("Cheyenne", "Laramie County", "Wyoming", "WY", 41.1400, -104.8202, 8.0),
    us("Helena", "Lewis and Clark County", "Montana", "MT", 46.5891, -112.0391, 8.0),
    us("Boise", "Ada County", "Idaho", "ID", 43.6150, -116.2023, 12.0),
    us("Carson City", "Carson City", "Nevada", "NV", 39.1638, -119.7674, 8.0),
    us("Santa Fe", "Santa Fe County", "New Mexico", "NM", 35.6870, -105.9378, 8.0),
    us("Olympia", "Thurston County", "Washington", "WA", 47.0379, -122.9007, 8.0),
    us("Salem", "Marion County", "Oregon", "OR", 44.9429, -123.0351, 10.0),
    us("Juneau", "Juneau City and Borough", "Alaska", "AK", 58.3019, -134.4197, 10.0),
    us("Albany", "Albany County", "New York", "NY", 42.6526, -73.7562, 10.0),
    us("Hartford", "Hartford County", "Connecticut", "CT", 41.7658, -72.6734, 8.0),
    us("Providence", "Providence County", "Rhode Island", "RI", 41.8240, -71.4128, 8.0),
    us("Montpelier", "Washington County", "Vermont", "VT", 44.2601, -72.5754, 5.0),
    us("Concord", "Merrimack County", "New Hampshire", "NH", 43.2081, -71.5376, 6.0),
    us("Augusta", "Kennebec County", "Maine", "ME", 44.3106, -69.7795, 6.0),
    us("Trenton", "Mercer County", "New Jersey", "NJ", 40.2206, -74.7597, 8.0),
    us("Newark", "Essex County", "New Jersey", "NJ", 40.7357, -74.1724, 8.0),
    us("Dover", "Kent County", "Delaware", "DE", 39.1582, -75.5244, 6.0),
    us("Annapolis", "Anne Arundel County", "Maryland", "MD", 38.9784, -76.4922, 6.0),
    // Washington DC metro suburbs (Maryland / Virginia)
    us("Beltsville", "Prince George's County", "Maryland", "MD", 39.0348, -76.9075, 6.0),
    us("College Park", "Prince George's County", "Maryland", "MD", 38.9807, -76.9369, 4.0),
    us("Greenbelt", "Prince George's County", "Maryland", "MD", 39.0046, -76.8755, 3.5),
    us("Laurel", "Prince George's County", "Maryland", "MD", 39.0993, -76.8483, 5.0),
    us("Bowie", "Prince George's County", "Maryland", "MD", 38.9426, -76.7302, 7.0),
    us("Silver Spring", "Montgomery County", "Maryland", "MD", 38.9907, -77.0261, 5.0),
    us("Bethesda", "Montgomery County", "Maryland", "MD", 38.9847, -77.0947, 5.0),
    us("Rockville", "Montgomery County", "Maryland", "MD", 39.0840, -77.1528, 6.0),
    us("Columbia", "Howard County", "Maryland", "MD", 39.2037, -76.8610, 8.0),
    us("Alexandria", "Alexandria City", "Virginia", "VA", 38.8048, -77.0469, 6.0),
    us("Arlington", "Arlington County", "Virginia", "VA", 38.8816, -77.0910, 6.0),
    us("Harrisburg", "Dauphin County", "Pennsylvania", "PA", 40.2732, -76.8867, 8.0),
    us("Charleston", "Kanawha County", "West Virginia", "WV", 38.3498, -81.6326, 8.0),
    us("Jefferson City", "Cole County", "Missouri", "MO", 38.5767, -92.1735, 8.0),
    us("St. Paul", "Ramsey County", "Minnesota", "MN", 44.9537, -93.0900, 10.0),
    us("El Paso", "El Paso County", "Texas", "TX", 31.7619, -106.4850, 20.0),
    us("Corpus Christi", "Nueces County", "Texas", "TX", 27.8006, -97.3964, 18.0),
    us("Bastrop", "Bastrop County", "Texas", "TX", 30.1105, -97.3153, 6.0),
    us("Columbus", "Colorado County", "Texas", "TX", 29.7066, -96.5397, 5.0),
    us("Schulenburg", "Fayette County", "Texas", "TX", 29.6819, -96.9036, 4.0),
    us("Brenham", "Washington County", "Texas", "TX", 30.1669, -96.3977, 6.0),
    // --- Major world cities ---
    intl("London", Some("England"), "United Kingdom", 51.5074, -0.1278, 25.0),
    intl("Paris", Some("Ile-de-France"), "France", 48.8566, 2.3522, 15.0),
    intl("Berlin", None, "Germany", 52.5200, 13.4050, 20.0),
    intl("Madrid", None, "Spain", 40.4168, -3.7038, 18.0),
    intl("Rome", Some("Lazio"), "Italy", 41.9028, 12.4964, 18.0),
    intl("Amsterdam", Some("North Holland"), "Netherlands", 52.3676, 4.9041, 12.0),
    intl("Dublin", None, "Ireland", 53.3498, -6.2603, 12.0),
    intl("Lisbon", None, "Portugal", 38.7223, -9.1393, 12.0),
    intl("Toronto", Some("Ontario"), "Canada", 43.6532, -79.3832, 25.0),
    intl("Montreal", Some("Quebec"), "Canada", 45.5017, -73.5673, 20.0),
    intl("Vancouver", Some("British Columbia"), "Canada", 49.2827, -123.1207, 18.0),
    intl("Mexico City", None, "Mexico", 19.4326, -99.1332, 30.0),
    intl("Sao Paulo", None, "Brazil", -23.5505, -46.6333, 35.0),
    intl("Rio de Janeiro", None, "Brazil", -22.9068, -43.1729, 25.0),
    intl("Buenos Aires", None, "Argentina", -34.6037, -58.3816, 25.0),
    intl("Lagos", Some("Lagos State"), "Nigeria", 6.5244, 3.3792, 30.0),
    intl("Abuja", Some("Federal Capital Territory"), "Nigeria", 9.0765, 7.3986, 20.0),
    intl("Ibadan", Some("Oyo State"), "Nigeria", 7.3775, 3.9470, 20.0),
    intl("Accra", None, "Ghana", 5.6037, -0.1870, 20.0),
    intl("Nairobi", None, "Kenya", -1.2921, 36.8219, 20.0),
    intl("Johannesburg", Some("Gauteng"), "South Africa", -26.2041, 28.0473, 25.0),
    intl("Cape Town", Some("Western Cape"), "South Africa", -33.9249, 18.4241, 20.0),
    intl("Cairo", None, "Egypt", 30.0444, 31.2357, 25.0),
    intl("Dubai", None, "United Arab Emirates", 25.2048, 55.2708, 25.0),
    intl("Mumbai", Some("Maharashtra"), "India", 19.0760, 72.8777, 25.0),
    intl("New Delhi", Some("Delhi"), "India", 28.6139, 77.2090, 25.0),
    intl("Bangalore", Some("Karnataka"), "India", 12.9716, 77.5946, 20.0),
    intl("Beijing", None, "China", 39.9042, 116.4074, 30.0),
    intl("Shanghai", None, "China", 31.2304, 121.4737, 30.0),
    intl("Hong Kong", None, "China", 22.3193, 114.1694, 20.0),
    intl("Tokyo", None, "Japan", 35.6762, 139.6503, 30.0),
    intl("Seoul", None, "South Korea", 37.5665, 126.9780, 25.0),
    intl("Singapore", None, "Singapore", 1.3521, 103.8198, 20.0),
    intl("Sydney", Some("New South Wales"), "Australia", -33.8688, 151.2093, 30.0),
    intl("Melbourne", Some("Victoria"), "Australia", -37.8136, 144.9631, 30.0),
    intl("Auckland", None, "New Zealand", -36.8485, 174.7633, 20.0),
];

/// Haversine great-circle distance in kilometres.
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0088;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * R * a.sqrt().asin()
}

/// Resolve a WGS84 coordinate to the best matching embedded place.
///
/// Prefers the closest place whose radius contains the point (so a photo inside
/// La Grange, IL resolves to La Grange rather than Chicago 15 km away). Falls back
/// to the nearest place within `radius + NEAR_RADIUS_KM`, flagged `within = false`.
pub fn resolve_location(lat: f64, lon: f64) -> Option<GeoLocation> {
    if !lat.is_finite() || !lon.is_finite() || !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    // (0,0) is the classic "unset GPS" sentinel written by some cameras.
    if lat.abs() < 1e-9 && lon.abs() < 1e-9 {
        return None;
    }

    let mut best_within: Option<(&Place, f64)> = None;
    let mut best_near: Option<(&Place, f64)> = None;
    for place in GAZETTEER {
        let d = haversine_km(lat, lon, place.lat, place.lon);
        if d <= place.radius_km {
            // Among containing places, pick the one with the smallest radius-normalised distance
            // so small towns win over the large metro radius that also covers them.
            let score = d / place.radius_km;
            if best_within.map_or(true, |(bp, bd)| score < bd / bp.radius_km) {
                best_within = Some((place, d));
            }
        } else if d <= place.radius_km + NEAR_RADIUS_KM && best_near.map_or(true, |(_, bd)| d < bd) {
            best_near = Some((place, d));
        }
    }

    let (place, distance_km, within) = match (best_within, best_near) {
        (Some((p, d)), _) => (p, d, true),
        (None, Some((p, d))) => (p, d, false),
        (None, None) => return None,
    };
    Some(to_location(place, distance_km, within))
}

fn to_location(place: &Place, distance_km: f64, within: bool) -> GeoLocation {
    let mut parts: Vec<&str> = vec![place.city];
    if let Some(st) = place.state {
        parts.push(st);
    }
    parts.push(place.country);
    let base = parts.join(", ");
    let display_name = if within {
        base
    } else {
        format!("near {} ({:.0} km away)", base, distance_km)
    };

    let mut tokens: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        for w in s.split(|c: char| !c.is_alphanumeric()) {
            let w = w.trim().to_lowercase();
            if w.len() >= 2 && !tokens.contains(&w) {
                tokens.push(w);
            }
        }
    };
    push(place.city);
    // Also emit the joined form ("lagrange") so both "La Grange" and "LaGrange" match.
    let joined: String = place.city.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    if let Some(county) = place.county {
        push(county);
    }
    if let Some(st) = place.state {
        push(st);
    }
    if let Some(code) = place.state_code {
        push(code);
    }
    push(place.country);
    if joined.len() >= 2 && !tokens.contains(&joined) {
        tokens.push(joined);
    }

    GeoLocation {
        city: place.city.to_string(),
        county: place.county.map(str::to_string),
        state: place.state.map(str::to_string),
        state_code: place.state_code.map(str::to_string),
        country: place.country.to_string(),
        distance_km,
        within,
        display_name,
        tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_grange_texas_resolves() {
        let loc = resolve_location(29.9055, -96.8766).expect("resolves");
        assert_eq!(loc.city, "La Grange");
        assert_eq!(loc.state_code.as_deref(), Some("TX"));
        assert!(loc.within);
        assert!(loc.tokens.contains(&"grange".to_string()));
        assert!(loc.tokens.contains(&"lagrange".to_string()));
    }

    #[test]
    fn la_grange_illinois_beats_chicago_radius() {
        // 41 48' 56" N, 87 52' 11" W
        let lat = 41.0 + 48.0 / 60.0 + 56.0 / 3600.0;
        let lon = -(87.0 + 52.0 / 60.0 + 11.0 / 3600.0);
        let loc = resolve_location(lat, lon).expect("resolves");
        assert_eq!(loc.city, "La Grange");
        assert_eq!(loc.state_code.as_deref(), Some("IL"));
    }

    #[test]
    fn la_grange_kentucky_resolves() {
        let loc = resolve_location(38.4076, -85.3789).expect("resolves");
        assert_eq!(loc.city, "La Grange");
        assert_eq!(loc.state_code.as_deref(), Some("KY"));
    }

    #[test]
    fn real_photo_coordinates_resolve_to_beltsville_not_la_grange() {
        // EXIF GPS from D:\femi\20160917_192556.jpg
        let loc = resolve_location(39.04745, -76.9344).expect("resolves");
        assert_eq!(loc.city, "Beltsville");
        assert_eq!(loc.state_code.as_deref(), Some("MD"));
        assert!(loc.within);
        assert!(!loc.tokens.contains(&"grange".to_string()));
    }

    #[test]
    fn mid_ocean_and_null_island_do_not_resolve() {
        assert!(resolve_location(0.0, 0.0).is_none());
        assert!(resolve_location(-40.0, -140.0).is_none());
        assert!(resolve_location(f64::NAN, 1.0).is_none());
    }

    #[test]
    fn near_place_is_flagged_not_within() {
        // ~20 km east of La Grange, TX centroid but outside its 8 km radius;
        // Schulenburg/Columbus TX may also be candidates - whichever wins must not be "within" La Grange.
        let loc = resolve_location(29.95, -96.66).expect("resolves near");
        if loc.city == "La Grange" {
            assert!(!loc.within);
            assert!(loc.display_name.starts_with("near "));
        }
    }
}
