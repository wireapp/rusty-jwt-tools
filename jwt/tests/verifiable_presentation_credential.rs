use jwt_simple::prelude::*;
use serde_json::json;
use url::Url;

use rusty_jwt_tools::prelude::*;

#[test]
fn verifiable_presentation_credential() {
    let keys: Vec<(JwsAlgorithm, Pem, Pem, HashAlgorithm)> = vec![
        (
            JwsAlgorithm::P256,
            ES256KeyPair::generate().to_pem().unwrap().into(),
            ES256KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA256,
        ),
        (
            JwsAlgorithm::P384,
            ES384KeyPair::generate().to_pem().unwrap().into(),
            ES384KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA384,
        ),
        (
            JwsAlgorithm::Ed25519,
            Ed25519KeyPair::generate().to_pem().into(),
            Ed25519KeyPair::generate().to_pem().into(),
            HashAlgorithm::SHA256,
        ),
    ];

    for (alg, key, _, hash_alg) in keys {
        println!("# {alg:?} - {hash_alg:?}");

        let credential_1 = RustyCredential {
            context: vec![
                Context::CREDENTIAL.try_into().unwrap(),
                "https://openid.net/2014/openid-connect-core/v1".try_into().unwrap(),
                "https://www.w3.org/2006/vcard/ns".try_into().unwrap(),
            ]
                .into(),
            id: Some(Url::parse("https://idp.example.com/credentials/1872").unwrap()),
            types: vec![
                "VerifiableCredential".to_string(),
                "ImUserIdentityCredential".to_string(),
            ]
                .into(),
            credential_subject: CredentialSubject {
                extra_claims: None,
            },
            issuer: Issuer::Obj(IssuerData {
                id: "dns:idp.example.com".parse().unwrap(),
                properties: None,
            }),
            issuance_date: time::macros::datetime!(2022-06-19 15:30:16 UTC).into(),
            expiration_date: Some(time::macros::datetime!(2023-06-19 15:30:16 UTC).into()),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                created: Some(time::macros::datetime!(2022-06-19 15:30:15 UTC).into()),
                value: ProofValue::Jws("LedhVWaZvgklWAsPlGU4aEOuxPgXD16-aL5X7RNAyoXRvHPzYAqH8a3..Yot9dpKNuhWim2EwZUk-rmM876Xex_Con_HGseAqR6o".to_string()),
                purpose: Some(ProofPurpose::AssertionMethod),
                method: "https://idp.example.com/keys/Ed25519/sha256:wF6oONwUJSa3oi8vyBEG8S2CiZANGTN_8ZNXf4RYdyQ".to_string(),
                domain: None,
                expires: None,
                challenge: None,
            }),
        };

        let credential_2 = RustyCredential {
            context: vec![
                Context::CREDENTIAL.try_into().unwrap(),
                "https://ietf.org/2022/oauth/MlsClientCredential/v1".try_into().unwrap(),
            ]
                .into(),
            id: Some(Url::parse("https://im.example.com/credentials/9829381").unwrap()),
            types: vec!["VerifiableCredential".to_string(), "MlsClientIdCredential".to_string()].into(),
            credential_subject: CredentialSubject {
                extra_claims: None
            },
            issuer: Issuer::Obj(IssuerData {
                id: "dns:im.example.com".parse().unwrap(),
                properties: None,
            }),
            issuance_date: time::macros::datetime!(2022-09-08 19:23:24 UTC).into(),
            expiration_date: Some(time::macros::datetime!(2023-09-08 19:23:24 UTC).into()),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                created: Some(time::macros::datetime!(2021-03-19 15:30:15 UTC).into()),
                value: ProofValue::Jws("N8xYGopY8_2wJYuhFX5QMuvMBjzHPJqp06w73UL53BBdhxP9QxtqxTAk..jZrTdfr4kMkCOYhLoFG2L7roGZFmDzVSecfzNwf36lk".to_string()),
                purpose: Some(ProofPurpose::AssertionMethod),
                method: "https://im.example.com/keys/Ed25519/sha256:uZx-Zx68PzlMsd2PgslEWBCF-BDyjMUdVDbZhnCZIls".to_string(),
                domain: None,
                expires: None,
                challenge: None,
            }),
        };

        let patch = json!([
            { "op": "replace", "path": "/verifiableCredential/0/credentialSubject", "value": {
                "sub": "im:%40a_smith@example.com",
                "name": "Smith, Alice (Allie)",
                "preferred_username": "@a_smith@example.com",
                "fn": "Alice M. Smith",
                "hasOrganizationName": "Example Corp",
                "hasOrganizationalUnit": "Engineering",
                "hasInstantMessage": "im:%40a_smith@example.com"
            } },
            { "op": "replace", "path": "/verifiableCredential/1/credentialSubject", "value": {
                "sub": "im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com"
            } },
        ]);

        let presentation = RustyPresentation {
            id: "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5".parse().unwrap(),
            holder: "im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com".parse().unwrap(),
            context: vec![Context::CREDENTIAL.try_into().unwrap()].into(),
            types: vec!["VerifiablePresentation".to_string()].into(),
            verifiable_credential: vec![credential_1, credential_2].into(),
            proof: Some(Proof {
                typ: Proof::ED25519_TYPE.to_string(),
                value: ProofValue::Jws("eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..UIVpxg5CEOSrQtvpse2svUhgzM3iCZOvcJ-XjwNNd0o".to_string()),
                method: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:mJafqNxZWNAIkaDGPlNyhccFSAqnRjhyA3FJNm0f8I8".to_string(),
                created: Some(time::macros::datetime!(2022-09-22 11:10:04 UTC).into()),
                expires: None,
                challenge: Some("Es6R6R4yI66_yw0d4ulfFQ".to_string()),
                domain: Some("im:SvPfLlwBQi-6oddVRrkqpw/04c7@example.com".to_string()),
                purpose: Some(ProofPurpose::Authentication)
            }),
            extra: Some(patch),
        };
        let vp = presentation.try_json_serialize().unwrap();
        // println!("1. verifiable presentation:\n{}\n", serde_json::to_string_pretty(&vp).unwrap());

        let nonce: BackendNonce = "WE88EvOBzbqGerznM+2P/AadVf7374y0cH19sDSZA2A".into(); // generated by wire-server
        let challenge: AcmeNonce = "okAJ33Ym/XS2qmmhhh7aWSbBlYy4Ttm1EysqW8I/9ng".to_string().into(); // generated by ACME server
        let user = uuid::Uuid::new_v4().to_string();
        let client = rand::random::<u64>();
        let (domain, team, handle) = ("wire.com", "wire", "beltram_wire");
        let alice = ClientId::try_new(&user, client, domain).unwrap();
        let htu: Htu = "https://wire.example.com/client/token".try_into().unwrap();
        let htm = Htm::Post;
        let expiry = Duration::from_days(1).into();
        let handle = Handle::from(handle).to_qualified(domain);
        let dpop = Dpop {
            htu: htu.clone(),
            htm,
            challenge: challenge.clone(),
            handle,
            team: team.into(),
            extra_claims: Some(vp),
        };

        let client_dpop = RustyJwtTools::generate_dpop_token(dpop, &alice, nonce.clone(), expiry, alg, &key).unwrap();

        // println!("2. dpop:\nhttps://jwt.io/#id_token={client_dpop}\n");
        println!("https://jwt.io/#id_token={client_dpop}\n");

        println!("---------------------------------------------------------------------\n");
    }
}
