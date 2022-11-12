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
    let more: [u8; 0] = core::array::from_fn(|i| (i) as u8);
    plain.append(&mut more.to_vec());

    //google srtp 128 key 112 salt
    let key: [u8; 128 / 8 + 112 / 8] = core::array::from_fn(|i| (i) as u8);

    println!("key = {:?}", key);
    println!("plain len = {:?}", plain.len());

    let mut session = srtp::Session::with_inbound_template(srtp::StreamPolicy {
        key: &key,
        rtp: srtp::CryptoPolicy::aes_gcm_128_16_auth(),
        rtcp: srtp::CryptoPolicy::aes_gcm_128_16_auth(),
        ..Default::default()
    })
    .unwrap();

    const n: usize = 1e6 as usize;

    let now = Instant::now();
    for x in 1..(n as usize) {
        plain[2] = ((x >> 8) & 0xff) as u8;
        plain[3] = (x & 0xff) as u8;

        // println!("plain  = {:?}", plain);

        match session.protect(&mut plain) {
            Err(err) => println!("Error unprotecting SRTP packet: {}", err),
            Ok(_) => {}
        }
    }

    let elapsed = now.elapsed();
    let nbits = n * plain.len() * 8;
    let secs = elapsed.as_secs_f64();
    println!("Elapsed: {:.2?}", elapsed);
    println!("Throughput: {:.2?} Gbps", nbits as f64 / secs / 1e9);
}
