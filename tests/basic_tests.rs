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
        .args(&["link", "add", "veth_t0", "type", "veth", "peer", "name", "veth_t1"])
        .status()
        .expect("Failed to execute ip link add command");
    if !status.success() {
        panic!("Failed to create temporary veth pair veth_t0 <-> veth_t1");
    }

    let _ = Command::new("ip").args(&["link", "set", "veth_t0", "up"]).status();
    let _ = Command::new("ip").args(&["link", "set", "veth_t1", "up"]).status();

    // RAII helper to clean up veth interfaces even if the test panics
    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(&["link", "del", "veth_t0"]).status();
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
    let (mut tx_q_dev0, mut rx_q_dev0, fq_and_cq_dev0) = unsafe {
        Socket::new(
            SocketConfig::default(),
            &umem_dev0,
            &if_dev0,
            0,
        )
    }
    .unwrap();
    let (mut fq_dev0, mut cq_dev0) = fq_and_cq_dev0.unwrap();

    // Populate Fill Queue for Dev0 (giving it all descriptors to receive packets)
    let produced = unsafe { fq_dev0.produce(&frame_descs_dev0) };
    assert_eq!(produced, frame_count as usize, "Failed to load all descriptors into Fill ring");

    // 4. Setup UMEM & Socket for Device 1 (Test Packet Injector / Receiver)
    let (umem_dev1, mut frame_descs_dev1) = Umem::new(
        umem_config,
        NonZeroU32::new(frame_count).unwrap(),
        false,
    )
    .unwrap();

    let if_dev1: Interface = "veth_t1".parse().unwrap();
    let (mut tx_q_dev1, mut rx_q_dev1, fq_and_cq_dev1) = unsafe {
        Socket::new(
            SocketConfig::default(),
            &umem_dev1,
            &if_dev1,
            0,
        )
    }
    .unwrap();
    let (mut fq_dev1, mut cq_dev1) = fq_and_cq_dev1.unwrap();

    // Populate Fill Queue for Dev1 (needed to receive the echoed packet back)
    let produced_dev1 = unsafe { fq_dev1.produce(&frame_descs_dev1) };
    assert_eq!(produced_dev1, frame_count as usize);

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

    // 7. Receive on Dev0, swap MACs, and Echo back
    let mut rx_descs = vec![frame_descs_dev0[0]; 16];
    let mut tx_descs = rx_descs.clone();
    
    let mut received = 0;
    let start = Instant::now();
    while received == 0 && start.elapsed() < Duration::from_secs(4) {
        received = unsafe { rx_q_dev0.consume(&mut rx_descs[..]) };
    }
    assert_eq!(received, 1, "Dev0 failed to receive the injected packet");

    // Verify received frame address maps to expected range and perform swap
    {
        let desc = &mut rx_descs[0];
        let mut data_mut = unsafe { umem_dev0.data_mut(desc) };
        let contents = data_mut.contents_mut();
        assert!(contents.len() >= 12);
        
        let mut mac_dst = [0u8; 6];
        let mut mac_src = [0u8; 6];
        mac_dst.copy_from_slice(&contents[0..6]);
        mac_src.copy_from_slice(&contents[6..12]);
        // Swap Destination & Source MAC in-place
        contents[0..6].copy_from_slice(&mac_src);
        contents[6..12].copy_from_slice(&mac_dst);
        
        tx_descs[0] = *desc;
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
    assert_eq!(completed, 1, "Dev0 failed to reclaim sent descriptor from Completion queue");

    // Return the completed descriptor to the Fill ring (Recycle)
    let recycled = unsafe { fq_dev0.produce(&comp_descs[..1]) };
    assert_eq!(recycled, 1, "Failed to return completed descriptor to Fill ring");

    // 9. Receive the echoed packet on Dev1 and verify MAC Swap & Payload Preservation
    let mut rx_descs_dev1 = vec![frame_descs_dev1[0]; 16];
    let mut echoed = 0;
    let echo_start = Instant::now();
    while echoed == 0 && echo_start.elapsed() < Duration::from_secs(4) {
        echoed = unsafe { rx_q_dev1.consume(&mut rx_descs_dev1[..]) };
    }
    assert_eq!(echoed, 1, "Dev1 failed to receive the echoed packet");

    {
        let desc = &mut rx_descs_dev1[0];
        let data = unsafe { umem_dev1.data(desc) };
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
    
    // Recycle injector frame
    let recycled_dev1 = unsafe { fq_dev1.produce(&comp_descs_dev1[..1]) };
    assert_eq!(recycled_dev1, 1);
}
