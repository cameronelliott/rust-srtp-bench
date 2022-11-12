use std::time::Instant;

fn main() {
    //let key = &[0u8; 200][..]; // DO NOT USE IT ON PRODUCTION

    // https://datatracker.ietf.org/doc/html/rfc7714#section-16.1.1
    let mut plain = "8040f17b 8041f8d3 5501a0b2 47616c6c
    69612065 7374206f 6d6e6973 20646976
    69736120 696e2070 61727465 73207472
    6573"
        .to_string();
    plain.retain(|c| !c.is_whitespace());
    let mut plain = hex::decode(plain).unwrap();
    //  let mut packet = b"not a valid SRTP packet".to_vec();
    let more: [u8; 1000] = core::array::from_fn(|i| (i) as u8);
    plain.append(&mut more.to_vec());

    //google srtp 128 key 112 salt
    let key: [u8; 128 / 8 + 112 / 8] = core::array::from_fn(|i| (i) as u8);

    println!("key = {:?}", key);
    println!("plain len = {:?}", plain.len());

    //let policy = srtp::CryptoPolicy::aes_gcm_128_16_auth();
    let policy = srtp::CryptoPolicy::aes_cm_128_hmac_sha1_80();
    let mut session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
        key: &key,
        rtp: policy,
        rtcp: policy,
        ..Default::default()
    })
    .unwrap();

    const N: usize = 1e5 as usize;

    let now = Instant::now();
    for x in 1..(N as usize) {
        plain[2] = ((x >> 8) & 0xff) as u8;
        plain[3] = (x & 0xff) as u8;

        // println!("plain  = {:?}", plain);

        match session.protect(&mut plain) {
            Err(err) => println!("Error unprotecting SRTP packet: {}", err),
            Ok(_) => {}
        }
    }

    let elapsed = now.elapsed();
    let nbits = N * plain.len() * 8;
    let secs = elapsed.as_secs_f64();
    println!("Elapsed: {:.1?}", elapsed);
    println!("Throughput: {:.1?} Gbps", nbits as f64 / secs / 1e9);
}
