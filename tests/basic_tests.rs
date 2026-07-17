//! Integration and performance tests for Custos.

#[cfg(target_os = "linux")]
#[test]
fn test_af_xdp_echo_and_leak_detection() {
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use xsk_rs::{
        config::{Interface, SocketConfig, UmemConfigBuilder},
        Socket, Umem,
    };

    // 1. Create temporary veth pair programmatically inside the container network namespace
    let status = Command::new("ip")
        .args(&[
            "link", "add", "veth_t0", "type", "veth", "peer", "name", "veth_t1",
        ])
        .status()
        .expect("Failed to execute ip link add command");
    if !status.success() {
        panic!("Failed to create temporary veth pair veth_t0 <-> veth_t1");
    }

    let _ = Command::new("ip")
        .args(&["link", "set", "veth_t0", "up"])
        .status();
    let _ = Command::new("ip")
        .args(&["link", "set", "veth_t1", "up"])
        .status();

    // RAII helper to clean up veth interfaces even if the test panics
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(&["link", "del", "veth_t0"])
                .status();
        }
    }
    let _cleanup = Cleanup;

    // 2. Setup UMEM for Device 0 (Custos Echo Server)
    let frame_count = 128;
    let umem_config = UmemConfigBuilder::new()
        .frame_size(2048.try_into().unwrap())
        .frame_headroom(0.try_into().unwrap())
        .fill_queue_size(128.try_into().unwrap())
        .comp_queue_size(128.try_into().unwrap())
        .build()
        .unwrap();

    let (umem_dev0, frame_descs_dev0) = Umem::new(
        umem_config.clone(),
        NonZeroU32::new(frame_count).unwrap(),
        false,
    )
    .unwrap();

    // 3. Setup Socket for Device 0 (binds to veth_t0)
    let if_dev0: Interface = "veth_t0".parse().unwrap();
    let (mut tx_q_dev0, mut rx_q_dev0, fq_and_cq_dev0) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev0, &if_dev0, 0) }.unwrap();
    let (mut fq_dev0, mut cq_dev0) = fq_and_cq_dev0.unwrap();

    // Populate Fill Queue for Dev0 (giving it all descriptors to receive packets)
    let produced = unsafe { fq_dev0.produce(&frame_descs_dev0) };
    assert_eq!(
        produced, frame_count as usize,
        "Failed to load all descriptors into Fill ring"
    );

    // 4. Setup UMEM & Socket for Device 1 (Test Packet Injector / Receiver)
    let (umem_dev1, mut frame_descs_dev1) =
        Umem::new(umem_config, NonZeroU32::new(frame_count).unwrap(), false).unwrap();

    let if_dev1: Interface = "veth_t1".parse().unwrap();
    let (mut tx_q_dev1, mut rx_q_dev1, fq_and_cq_dev1) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev1, &if_dev1, 0) }.unwrap();
    let (mut fq_dev1, mut cq_dev1) = fq_and_cq_dev1.unwrap();

    // Populate Fill Queue for Dev1 (excluding frame 0, reserved for TX)
    let produced_dev1 = unsafe { fq_dev1.produce(&frame_descs_dev1[1..]) };
    assert_eq!(produced_dev1, (frame_count - 1) as usize);

    // 5. Construct a test UDP packet in dev1's UMEM frame 0
    let mut pkt_data = [0u8; 64];
    // Destination MAC: Broadcast
    pkt_data[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Source MAC: Dummy test MAC (02:00:00:00:00:01)
    pkt_data[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // EtherType (IPv4)
    pkt_data[12..14].copy_from_slice(&[0x08, 0x00]);
    // Payload Signature
    pkt_data[14..24].copy_from_slice(b"CUSTOSTEST");

    // Write the test packet via DataMut cursor (which sets the descriptor data length correctly)
    unsafe {
        let mut data_mut = umem_dev1.data_mut(&mut frame_descs_dev1[0]);
        let mut cursor = data_mut.cursor();
        use std::io::Write;
        cursor.write_all(&pkt_data).unwrap();
    }

    // 6. Transmit the packet from Dev1
    let sent = unsafe { tx_q_dev1.produce(&frame_descs_dev1[..1]) };
    assert_eq!(sent, 1, "Failed to produce TX packet from Dev1");
    if tx_q_dev1.needs_wakeup() {
        tx_q_dev1.wakeup().unwrap();
    }

    // 7. Receive on Dev0, filter out background noise, and Echo back
    let mut rx_descs = vec![frame_descs_dev0[0]; 16];
    let mut tx_descs = rx_descs.clone();

    let mut target_desc = None;
    let start = Instant::now();
    while target_desc.is_none() && start.elapsed() < Duration::from_secs(4) {
        let received = unsafe { rx_q_dev0.consume(&mut rx_descs[..]) };
        for desc in rx_descs.iter().take(received) {
            let data = unsafe { umem_dev0.data(desc) };
            let contents = data.contents();
            // Match our unique source MAC address
            if contents.len() >= 12 && &contents[6..12] == &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01] {
                target_desc = Some(*desc);
                break;
            } else {
                // Recycle background non-target packets immediately
                unsafe {
                    fq_dev0.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let mut desc = target_desc.expect("Dev0 failed to receive the injected packet");

    // Verify received frame address maps to expected range and perform swap
    {
        let mut data_mut = unsafe { umem_dev0.data_mut(&mut desc) };
        let contents = data_mut.contents_mut();
        assert!(contents.len() >= 12);

        let mut mac_dst = [0u8; 6];
        let mut mac_src = [0u8; 6];
        mac_dst.copy_from_slice(&contents[0..6]);
        mac_src.copy_from_slice(&contents[6..12]);
        // Swap Destination & Source MAC in-place
        contents[0..6].copy_from_slice(&mac_src);
        contents[6..12].copy_from_slice(&mac_dst);

        tx_descs[0] = desc;
    }

    // Submit back to Dev0 TX (forwarding/echoing)
    let produced = unsafe { tx_q_dev0.produce(&tx_descs[..1]) };
    assert_eq!(produced, 1, "Failed to queue echoed TX packet");
    if tx_q_dev0.needs_wakeup() {
        tx_q_dev0.wakeup().unwrap();
    }

    // 8. Reclaim transmitted descriptor from Completion Ring on Dev0
    let mut comp_descs = rx_descs.clone();
    let mut completed = 0;
    let comp_start = Instant::now();
    while completed == 0 && comp_start.elapsed() < Duration::from_secs(4) {
        completed = unsafe { cq_dev0.consume(&mut comp_descs[..]) };
    }
    assert_eq!(
        completed, 1,
        "Dev0 failed to reclaim sent descriptor from Completion queue"
    );

    // Return the completed descriptor to the Fill ring (Recycle)
    let recycled = unsafe { fq_dev0.produce(&comp_descs[..1]) };
    assert_eq!(
        recycled, 1,
        "Failed to return completed descriptor to Fill ring"
    );

    // 9. Receive the echoed packet on Dev1 and verify MAC Swap & Payload Preservation
    let mut rx_descs_dev1 = vec![frame_descs_dev1[0]; 16];
    let mut target_echoed = None;
    let echo_start = Instant::now();
    while target_echoed.is_none() && echo_start.elapsed() < Duration::from_secs(4) {
        let echoed = unsafe { rx_q_dev1.consume(&mut rx_descs_dev1[..]) };
        for desc in rx_descs_dev1.iter().take(echoed) {
            let data = unsafe { umem_dev1.data(desc) };
            let contents = data.contents();
            // Match our unique source MAC address
            if contents.len() >= 12 && &contents[6..12] == &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff] {
                target_echoed = Some(*desc);
                break;
            } else {
                unsafe {
                    fq_dev1.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let mut echoed_desc = target_echoed.expect("Dev1 failed to receive the echoed packet");

    {
        let data = unsafe { umem_dev1.data(&mut echoed_desc) };
        let contents = data.contents();

        // Assert MAC swap occurred
        // Destination MAC should now be Dev1's original MAC (02:00:00:00:00:01)
        assert_eq!(&contents[0..6], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        // Source MAC should now be original Destination MAC (ff:ff:ff:ff:ff:ff)
        assert_eq!(&contents[6..12], &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Payload preservation
        assert_eq!(&contents[14..24], b"CUSTOSTEST");
    }

    // 10. Reclaim the injector frame on Dev1
    let mut comp_descs_dev1 = rx_descs_dev1.clone();
    let mut completed_dev1 = 0;
    let inject_start = Instant::now();
    while completed_dev1 == 0 && inject_start.elapsed() < Duration::from_secs(4) {
        completed_dev1 = unsafe { cq_dev1.consume(&mut comp_descs_dev1[..]) };
    }
    assert_eq!(completed_dev1, 1, "Dev1 failed to complete TX");

    // Recycle injector frame (we don't put it in fill queue to avoid conflict)
}

#[cfg(target_os = "linux")]
#[test]
fn test_af_xdp_grpc_validation_and_drop_simulation() {
    use custos_grpc_basic::{parse_grpc_packet, ParseError};
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use xsk_rs::{
        config::{Interface, SocketConfig, UmemConfigBuilder},
        Socket, TxQueue, Umem,
    };

    // 1. Create temporary veth pair programmatically
    let status = Command::new("ip")
        .args(&[
            "link", "add", "veth_g0", "type", "veth", "peer", "name", "veth_g1",
        ])
        .status()
        .expect("Failed to execute ip link add command");
    if !status.success() {
        panic!("Failed to create temporary veth pair veth_g0 <-> veth_g1");
    }

    let _ = Command::new("ip")
        .args(&["link", "set", "veth_g0", "up"])
        .status();
    let _ = Command::new("ip")
        .args(&["link", "set", "veth_g1", "up"])
        .status();

    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(&["link", "del", "veth_g0"])
                .status();
        }
    }
    let _cleanup = Cleanup;

    // 2. Setup UMEM & Sockets
    let frame_count = 128;
    let umem_config = UmemConfigBuilder::new()
        .frame_size(2048.try_into().unwrap())
        .frame_headroom(0.try_into().unwrap())
        .fill_queue_size(128.try_into().unwrap())
        .comp_queue_size(128.try_into().unwrap())
        .build()
        .unwrap();

    let (umem_dev0, frame_descs_dev0) = Umem::new(
        umem_config.clone(),
        NonZeroU32::new(frame_count).unwrap(),
        false,
    )
    .unwrap();

    let if_dev0: Interface = "veth_g0".parse().unwrap();
    let (mut _tx_q_dev0, mut rx_q_dev0, fq_and_cq_dev0) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev0, &if_dev0, 0) }.unwrap();
    let (mut fq_dev0, mut _cq_dev0) = fq_and_cq_dev0.unwrap();
    unsafe {
        fq_dev0.produce(&frame_descs_dev0);
    }

    let (umem_dev1, mut frame_descs_dev1) =
        Umem::new(umem_config, NonZeroU32::new(frame_count).unwrap(), false).unwrap();

    let if_dev1: Interface = "veth_g1".parse().unwrap();
    let (mut tx_q_dev1, _rx_q_dev1, fq_and_cq_dev1) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev1, &if_dev1, 0) }.unwrap();
    let (mut fq_dev1, mut cq_dev1) = fq_and_cq_dev1.unwrap();

    // Populate Fill Queue for Dev1 (excluding frames 0 and 1, reserved for TX)
    let produced_dev1 = unsafe { fq_dev1.produce(&frame_descs_dev1[2..]) };
    assert_eq!(produced_dev1, (frame_count - 2) as usize);

    // 3. Helper to build and transmit packet payload
    let transmit_packet =
        |tx_q: &mut TxQueue, umem: &Umem, desc: &mut xsk_rs::FrameDesc, payload: &[u8]| {
            unsafe {
                let mut data_mut = umem.data_mut(desc);
                let mut cursor = data_mut.cursor();
                use std::io::Write;
                cursor.write_all(payload).unwrap();
            }
            let sent = unsafe { tx_q.produce(std::slice::from_mut(desc)) };
            assert_eq!(sent, 1);
            if tx_q.needs_wakeup() {
                tx_q.wakeup().unwrap();
            }
        };

    // 4. Construct a valid gRPC packet payload
    let mut valid_payload = vec![0u8; 80];
    valid_payload[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst
    valid_payload[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src (matching signature)
    valid_payload[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4 ether type
    valid_payload[14] = 0x45; // version / ihl
    valid_payload[23] = 6; // TCP
                           // Valid checksum
    let mut ip_hdr = [0u8; 20];
    ip_hdr.copy_from_slice(&valid_payload[14..34]);
    let csum = custos_grpc_basic::calculate_checksum(&ip_hdr);
    valid_payload[24..26].copy_from_slice(&csum.to_be_bytes());

    valid_payload[36..38].copy_from_slice(&50051u16.to_be_bytes()); // dst port
    valid_payload[46] = 5 << 4; // TCP data offset (5 = 20 bytes)
    valid_payload[54..57].copy_from_slice(&[0, 0, 10]); // HTTP/2 payload length 10
    valid_payload[57] = 0x0; // HTTP/2 DATA frame type
    valid_payload[64] = 0; // gRPC compression flag
    valid_payload[65..69].copy_from_slice(&5u32.to_be_bytes()); // gRPC message length 5

    // 5. Construct a malformed packet (e.g. non-TCP protocol UDP (17))
    let mut malformed_payload = valid_payload.clone();
    malformed_payload[23] = 17; // UDP
                                // Recalculate checksum so it passes IP checksum check
    let mut ip_hdr_mal = [0u8; 20];
    ip_hdr_mal.copy_from_slice(&malformed_payload[14..34]);
    ip_hdr_mal[10] = 0;
    ip_hdr_mal[11] = 0;
    let csum_mal = custos_grpc_basic::calculate_checksum(&ip_hdr_mal);
    malformed_payload[24..26].copy_from_slice(&csum_mal.to_be_bytes());

    // 6. Test Valid Packet Flow (using frame 0 for valid TX)
    transmit_packet(
        &mut tx_q_dev1,
        &umem_dev1,
        &mut frame_descs_dev1[0],
        &valid_payload,
    );

    let mut rx_descs = vec![frame_descs_dev0[0]; 16];
    let mut target_desc = None;
    let start = Instant::now();
    while target_desc.is_none() && start.elapsed() < Duration::from_secs(4) {
        let received = unsafe { rx_q_dev0.consume(&mut rx_descs[..]) };
        for desc in rx_descs.iter().take(received) {
            let data = unsafe { umem_dev0.data(desc) };
            let contents = data.contents();
            if contents.len() >= 12 && &contents[6..12] == &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01] {
                target_desc = Some(*desc);
                break;
            } else {
                unsafe {
                    fq_dev0.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let desc = target_desc.expect("Failed to receive valid packet on dev0");

    // Parse received packet
    {
        let data = unsafe { umem_dev0.data(&desc) };
        let result = parse_grpc_packet(data.contents(), 50051);
        assert!(
            result.is_ok(),
            "Failed to parse valid gRPC packet: {:?}",
            result.err()
        );
    }

    // Recycle dev0 frame
    unsafe {
        fq_dev0.produce(std::slice::from_ref(&desc));
    }

    // Reclaim dev1 frame
    let mut comp_descs = vec![frame_descs_dev1[0]; 16];
    let mut completed = 0;
    let start = Instant::now();
    while completed == 0 && start.elapsed() < Duration::from_secs(4) {
        completed = unsafe { cq_dev1.consume(&mut comp_descs[..]) };
    }
    assert_eq!(completed, 1);

    // 7. Test Malformed Packet Flow (using frame 1 for malformed TX to avoid conflict)
    transmit_packet(
        &mut tx_q_dev1,
        &umem_dev1,
        &mut frame_descs_dev1[1],
        &malformed_payload,
    );

    let mut rx_descs_mal = vec![frame_descs_dev0[0]; 16];
    let mut target_desc_mal = None;
    let start = Instant::now();
    while target_desc_mal.is_none() && start.elapsed() < Duration::from_secs(4) {
        let received_mal = unsafe { rx_q_dev0.consume(&mut rx_descs_mal[..]) };
        for desc in rx_descs_mal.iter().take(received_mal) {
            let data = unsafe { umem_dev0.data(desc) };
            let contents = data.contents();
            if contents.len() >= 12 && &contents[6..12] == &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01] {
                target_desc_mal = Some(*desc);
                break;
            } else {
                unsafe {
                    fq_dev0.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let desc_mal = target_desc_mal.expect("Failed to receive malformed packet on dev0");

    // Parse received packet (must return NonTCP error!)
    {
        let data = unsafe { umem_dev0.data(&desc_mal) };
        let result = parse_grpc_packet(data.contents(), 50051);
        assert_eq!(result.err(), Some(ParseError::NonTCP));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn test_af_xdp_protobuf_shape_validation() {
    use custos_protobuf::{
        validate_grpc_protobuf_packet, ProtoError, ValidationConfig, ValidationError,
    };
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use std::process::Command;
    use std::time::{Duration, Instant};
    use xsk_rs::{
        config::{Interface, SocketConfig, UmemConfigBuilder},
        Socket, TxQueue, Umem,
    };

    // 1. Create temporary veth pair programmatically
    let status = Command::new("ip")
        .args(&[
            "link", "add", "veth_p0", "type", "veth", "peer", "name", "veth_p1",
        ])
        .status()
        .expect("Failed to execute ip link add command");
    if !status.success() {
        panic!("Failed to create temporary veth pair veth_p0 <-> veth_p1");
    }

    let _ = Command::new("ip")
        .args(&["link", "set", "veth_p0", "up"])
        .status();
    let _ = Command::new("ip")
        .args(&["link", "set", "veth_p1", "up"])
        .status();

    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(&["link", "del", "veth_p0"])
                .status();
        }
    }
    let _cleanup = Cleanup;

    // 2. Setup UMEM & Sockets
    let frame_count = 128;
    let umem_config = UmemConfigBuilder::new()
        .frame_size(2048.try_into().unwrap())
        .frame_headroom(0.try_into().unwrap())
        .fill_queue_size(128.try_into().unwrap())
        .comp_queue_size(128.try_into().unwrap())
        .build()
        .unwrap();

    let (umem_dev0, frame_descs_dev0) = Umem::new(
        umem_config.clone(),
        NonZeroU32::new(frame_count).unwrap(),
        false,
    )
    .unwrap();

    let if_dev0: Interface = "veth_p0".parse().unwrap();
    let (mut _tx_q_dev0, mut rx_q_dev0, fq_and_cq_dev0) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev0, &if_dev0, 0) }.unwrap();
    let (mut fq_dev0, mut _cq_dev0) = fq_and_cq_dev0.unwrap();
    unsafe {
        fq_dev0.produce(&frame_descs_dev0);
    }

    let (umem_dev1, mut frame_descs_dev1) =
        Umem::new(umem_config, NonZeroU32::new(frame_count).unwrap(), false).unwrap();

    let if_dev1: Interface = "veth_p1".parse().unwrap();
    let (mut tx_q_dev1, _rx_q_dev1, fq_and_cq_dev1) =
        unsafe { Socket::new(SocketConfig::default(), &umem_dev1, &if_dev1, 0) }.unwrap();
    let (mut fq_dev1, mut cq_dev1) = fq_and_cq_dev1.unwrap();

    // Populate Fill Queue for Dev1 (excluding frames 0 and 1, reserved for TX)
    let produced_dev1 = unsafe { fq_dev1.produce(&frame_descs_dev1[2..]) };
    assert_eq!(produced_dev1, (frame_count - 2) as usize);

    // Helper to transmit packet
    let transmit_packet =
        |tx_q: &mut TxQueue, umem: &Umem, desc: &mut xsk_rs::FrameDesc, payload: &[u8]| {
            unsafe {
                let mut data_mut = umem.data_mut(desc);
                let mut cursor = data_mut.cursor();
                use std::io::Write;
                cursor.write_all(payload).unwrap();
            }
            let sent = unsafe { tx_q.produce(std::slice::from_mut(desc)) };
            assert_eq!(sent, 1);
            if tx_q.needs_wakeup() {
                tx_q.wakeup().unwrap();
            }
        };

    // Helper to build gRPC packet with protobuf payload
    let build_proto_packet = |proto_payload: &[u8]| -> Vec<u8> {
        let mut buf = vec![0u8; 68 + proto_payload.len()];
        // eth
        buf[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst
        buf[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        buf[12..14].copy_from_slice(&[0x08, 0x00]);

        // ip
        let total_len = (54 + proto_payload.len()) as u16;
        buf[14] = 0x45;
        buf[16..18].copy_from_slice(&total_len.to_be_bytes());
        buf[23] = 6; // TCP
                     // Calculate IP checksum
        let mut ip_hdr = [0u8; 20];
        ip_hdr.copy_from_slice(&buf[14..34]);
        let csum = custos_grpc_basic::calculate_checksum(&ip_hdr);
        buf[24..26].copy_from_slice(&csum.to_be_bytes());

        // tcp
        buf[36..38].copy_from_slice(&50051u16.to_be_bytes()); // dst port
        buf[46] = 5 << 4; // TCP data offset (20 bytes)

        // http2
        let http2_len = (proto_payload.len() + 5) as u32;
        buf[54..57].copy_from_slice(&[
            ((http2_len >> 16) & 0xff) as u8,
            ((http2_len >> 8) & 0xff) as u8,
            (http2_len & 0xff) as u8,
        ]);
        buf[57] = 0x0; // DATA

        // grpc
        buf[64] = 0; // compression
        buf[65..69].copy_from_slice(&(proto_payload.len() as u32).to_be_bytes());

        // proto
        buf[68..].copy_from_slice(proto_payload);
        buf
    };

    // 3. Test Valid Shape: [1, 3, 224, 224] (packed varints: tag 0x0a, length 5, values 1, 3, 224, 224)
    let valid_proto = vec![0x0a, 5, 1, 3, 0xe0, 0x01, 0xe0, 0x01];
    let valid_packet = build_proto_packet(&valid_proto);

    transmit_packet(
        &mut tx_q_dev1,
        &umem_dev1,
        &mut frame_descs_dev1[0],
        &valid_packet,
    );

    let mut rx_descs = vec![frame_descs_dev0[0]; 16];
    let mut target_desc = None;
    let start = Instant::now();
    while target_desc.is_none() && start.elapsed() < Duration::from_secs(4) {
        let received = unsafe { rx_q_dev0.consume(&mut rx_descs[..]) };
        for desc in rx_descs.iter().take(received) {
            let data = unsafe { umem_dev0.data(desc) };
            let contents = data.contents();
            if contents.len() >= 12 && &contents[6..12] == &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01] {
                target_desc = Some(*desc);
                break;
            } else {
                unsafe {
                    fq_dev0.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let desc = target_desc.expect("Failed to receive valid protobuf packet on dev0");

    {
        let data = unsafe { umem_dev0.data(&desc) };
        let config = ValidationConfig::default();
        let (shape, len) = validate_grpc_protobuf_packet(data.contents(), &config).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&shape[0..4], &[1, 3, 224, 224]);
    }

    unsafe {
        fq_dev0.produce(std::slice::from_ref(&desc));
    }

    // Reclaim dev1 frame 0
    let mut comp_descs = vec![frame_descs_dev1[0]; 16];
    let mut completed = 0;
    let comp_start = Instant::now();
    while completed == 0 && comp_start.elapsed() < Duration::from_secs(4) {
        completed = unsafe { cq_dev1.consume(&mut comp_descs[..]) };
    }
    assert_eq!(completed, 1);

    // 4. Test Invalid Shape: value <= 0 (unpacked: tag 0x08, value 0)
    let invalid_proto = vec![0x08, 0];
    let invalid_packet = build_proto_packet(&invalid_proto);

    transmit_packet(
        &mut tx_q_dev1,
        &umem_dev1,
        &mut frame_descs_dev1[1],
        &invalid_packet,
    );

    let mut rx_descs_inv = vec![frame_descs_dev0[0]; 16];
    let mut target_desc_inv = None;
    let start_inv = Instant::now();
    while target_desc_inv.is_none() && start_inv.elapsed() < Duration::from_secs(4) {
        let received_inv = unsafe { rx_q_dev0.consume(&mut rx_descs_inv[..]) };
        for desc in rx_descs_inv.iter().take(received_inv) {
            let data = unsafe { umem_dev0.data(desc) };
            let contents = data.contents();
            if contents.len() >= 12 && &contents[6..12] == &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01] {
                target_desc_inv = Some(*desc);
                break;
            } else {
                unsafe {
                    fq_dev0.produce(std::slice::from_ref(desc));
                }
            }
        }
    }
    let desc_inv = target_desc_inv.expect("Failed to receive invalid protobuf packet on dev0");

    {
        let data = unsafe { umem_dev0.data(&desc_inv) };
        let config = ValidationConfig::default();
        let result = validate_grpc_protobuf_packet(data.contents(), &config);
        assert_eq!(
            result.err(),
            Some(ValidationError::Proto(ProtoError::ShapeValueInvalid))
        );
    }
}
