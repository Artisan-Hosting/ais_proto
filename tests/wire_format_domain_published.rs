use ais_proto::domains as dom;
use prost::Message;

mod wire_format {
    use super::*;

    // case TC_A1_01 begin
    #[test]
    fn case_TC_A1_01() {
        let domain = dom::Domain {
            published: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        domain.encode(&mut buf).expect("encode should succeed");
        assert_eq!(buf, vec![0x90, 0x01, 0x01]);
    }
    // case TC_A1_01 end


    // case TC_A1_03 begin
    #[test]
    fn case_TC_A1_03() {
        let domain = dom::Domain {
            published: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        domain.encode(&mut buf).expect("encode should succeed");
        assert!(buf.starts_with(&[0x90, 0x01, 0x01]));
        assert_eq!(&buf[..3], &[0x90, 0x01, 0x01]);
    }
    // case TC_A1_03 end




    // case TC_A3_01 begin
    #[test]
    fn case_TC_A3_01() {
        let domain = dom::Domain::decode(&[0x90, 0x01, 0x01][..]).expect("decode should succeed");
        assert_eq!(domain.published, true);
    }
    // case TC_A3_01 end

    // case TC_A3_02 begin
    #[test]
    fn case_TC_A3_02() {
        let decoded = dom::Domain::decode(&[0x90, 0x01, 0x01][..]).expect("decode should succeed");
        let expected = dom::Domain {
            published: true,
            ..Default::default()
        };
        assert_eq!(decoded, expected);
    }
    // case TC_A3_02 end

// case TC_A3_03 begin
#[test]
fn case_TC_A3_03() {
    use prost::Message;
    let domain = ais_proto::domains::Domain::decode(&[0x90, 0x01, 0x01][..]).expect("decode should succeed");
    assert_eq!(domain.published, true);
    assert_eq!(domain.parent_fqdn, "");
}
// case TC_A3_03 end





// case TC_A5_01 begin
#[test]
fn case_TC_A5_01() {
    use prost::Message;

    let proto_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("domains.proto");
    let proto_text = std::fs::read_to_string(&proto_path).expect("domains.proto must be readable");
    assert!(
        proto_text.contains("bool published = 18;"),
        "domains.proto must include published field 18"
    );

    let domain = ais_proto::domains::Domain {
        parent_fqdn: "sub.example.com".to_string(),
        ..Default::default()
    };
    let mut buf = Vec::new();
    domain.encode(&mut buf).expect("encode should succeed");
    let expected_tag = [0x8a, 0x01];
    assert_eq!(&buf[..2], &expected_tag);
    let decoded = <ais_proto::domains::Domain as Message>::decode(&buf[..]).expect("decode should succeed");
    assert_eq!(decoded.parent_fqdn, "sub.example.com");
}
// case TC_A5_01 end
}
