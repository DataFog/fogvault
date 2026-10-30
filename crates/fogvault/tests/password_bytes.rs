use fogvault::{password_utf8_bytes, Engine, Limits};

const VECTORS: &str = include_str!("../../../conformance/password-vectors.tsv");

fn hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&value[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn password_text_vectors_preserve_exact_utf8() {
    let mut valid = 0;
    let mut invalid_utf16 = 0;
    let mut invalid_utf8 = 0;
    for line in VECTORS.lines().filter(|line| !line.starts_with('#')) {
        let row: Vec<_> = line.split('\t').collect();
        assert_eq!(row.len(), 4);
        match row[0] {
            "text" | "invalid_utf16" => {
                let units: Vec<_> = row[2]
                    .split(',')
                    .filter(|unit| !unit.is_empty())
                    .map(|unit| u16::from_str_radix(unit, 16).unwrap())
                    .collect();
                let text = String::from_utf16(&units);
                if row[0] == "text" {
                    let bytes = hex(row[3]);
                    assert_eq!(text.unwrap().as_bytes(), bytes, "{}", row[1]);
                    let borrowed = password_utf8_bytes(&bytes).unwrap();
                    assert_eq!(borrowed, bytes, "{}", row[1]);
                    assert_eq!(borrowed.as_ptr(), bytes.as_ptr());
                    valid += 1;
                } else {
                    assert!(text.is_err(), "{}", row[1]);
                    invalid_utf16 += 1;
                }
            }
            "invalid_utf8" => {
                let bytes = hex(row[2]);
                let error = password_utf8_bytes(&bytes).unwrap_err();
                assert_eq!(error.code(), "InvalidInput", "{}", row[1]);
                assert_eq!(hex(row[2]), bytes);
                invalid_utf8 += 1;
            }
            "raw_bytes" => {}
            other => panic!("unexpected vector kind {other}"),
        }
    }
    // Coverage of the reviewed fixture, not product input limits.
    assert_eq!((valid, invalid_utf16, invalid_utf8), (17, 6, 12));
}

#[test]
fn portable_raw_passwords_keep_binary_and_empty_credentials() {
    for line in VECTORS
        .lines()
        .filter(|line| line.starts_with("raw_bytes\t"))
    {
        let row: Vec<_> = line.split('\t').collect();
        let password = hex(row[2]);
        let limits = Limits {
            max_payload_bytes: 0,
            max_metadata_bytes: 0,
            max_records: 1,
        };
        let mut created = Engine::create(&password, limits).unwrap();
        let descriptor = created.descriptor_bytes().to_vec();
        let head = created.head_bytes().to_vec();
        created.activate_created().unwrap();
        created.lock();
        let mut reopened = Engine::open(&descriptor, limits).unwrap();
        reopened.begin_unlock(&password).unwrap();
        reopened.begin_audit(&head).unwrap();
        reopened.finish_audit(0, 0).unwrap();
        reopened.activate_audit().unwrap();
        assert!(reopened.current_session().is_ok(), "{}", row[1]);
    }
}
