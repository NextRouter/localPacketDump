use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pcap::{Capture, Device};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use prometheus::{Counter, Gauge, Registry, TextEncoder, Encoder};
use hyper::{Body, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use tokio::runtime::Runtime;

static SIGINT_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct PrometheusMetrics {
    registry: Registry,
    tx_bytes_total: Counter,
    rx_bytes_total: Counter,
    tx_bytes_per_sec: Gauge,
    rx_bytes_per_sec: Gauge,
    tx_bps: Gauge,
    rx_bps: Gauge,
    retransmissions_per_sec: Gauge,
    duplicate_acks_per_sec: Gauge,
    window_size_changes_per_sec: Gauge,
    // 各IPごとのメトリクス
    ip_tx_bytes_total: prometheus::CounterVec,
    ip_rx_bytes_total: prometheus::CounterVec,
    ip_tx_bytes_per_sec: prometheus::GaugeVec,
    ip_rx_bytes_per_sec: prometheus::GaugeVec,
    ip_tx_bps: prometheus::GaugeVec,
    ip_rx_bps: prometheus::GaugeVec,
    ip_retransmissions_per_sec: prometheus::GaugeVec,
    ip_duplicate_acks_per_sec: prometheus::GaugeVec,
    ip_window_size_changes_per_sec: prometheus::GaugeVec,
}

impl PrometheusMetrics {
    fn new() -> Self {
        let registry = Registry::new();
        
        // 全体のメトリクス - パケットロスは累積値として扱う
        let tx_bytes_total = Counter::new("network_tx_bytes_total", "Total transmitted bytes").unwrap();
        let rx_bytes_total = Counter::new("network_rx_bytes_total", "Total received bytes").unwrap();
        let tx_bytes_per_sec = Gauge::new("network_tx_bytes_per_sec", "Transmitted bytes per second").unwrap();
        let rx_bytes_per_sec = Gauge::new("network_rx_bytes_per_sec", "Received bytes per second").unwrap();
        let tx_bps = Gauge::new("network_tx_bps", "Transmitted bits per second").unwrap();
        let rx_bps = Gauge::new("network_rx_bps", "Received bits per second").unwrap();
        let retransmissions_per_sec = Gauge::new("network_retransmissions_per_sec", "Retransmissions per second").unwrap();
        let duplicate_acks_per_sec = Gauge::new("network_duplicate_acks_per_sec", "Duplicate ACKs per second").unwrap();
        let window_size_changes_per_sec = Gauge::new("network_window_size_changes_per_sec", "Window size changes per second").unwrap();
        
        // IPごとのメトリクス
        let ip_tx_bytes_total = prometheus::CounterVec::new(
            prometheus::Opts::new("network_ip_tx_bytes_total", "Total transmitted bytes per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_rx_bytes_total = prometheus::CounterVec::new(
            prometheus::Opts::new("network_ip_rx_bytes_total", "Total received bytes per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_tx_bytes_per_sec = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_tx_bytes_per_sec", "Transmitted bytes per second per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_rx_bytes_per_sec = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_rx_bytes_per_sec", "Received bytes per second per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_tx_bps = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_tx_bps", "Transmitted bits per second per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_rx_bps = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_rx_bps", "Received bits per second per IP"),
            &["ip_address"]
        ).unwrap();
        // パケットロス関連は1秒間の値をGaugeで表示
        let ip_retransmissions_per_sec = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_retransmissions_per_sec", "Retransmissions per second per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_duplicate_acks_per_sec = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_duplicate_acks_per_sec", "Duplicate ACKs per second per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_window_size_changes_per_sec = prometheus::GaugeVec::new(
            prometheus::Opts::new("network_ip_window_size_changes_per_sec", "Window size changes per second per IP"),
            &["ip_address"]
        ).unwrap();
        
        // 累積値のパケットロスメトリクスも追加
        let ip_retransmissions_total = prometheus::CounterVec::new(
            prometheus::Opts::new("network_ip_retransmissions_total", "Total retransmissions per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_duplicate_acks_total = prometheus::CounterVec::new(
            prometheus::Opts::new("network_ip_duplicate_acks_total", "Total duplicate ACKs per IP"),
            &["ip_address"]
        ).unwrap();
        let ip_window_size_changes_total = prometheus::CounterVec::new(
            prometheus::Opts::new("network_ip_window_size_changes_total", "Total window size changes per IP"),
            &["ip_address"]
        ).unwrap();
        
        // メトリクス登録
        registry.register(Box::new(tx_bytes_total.clone())).unwrap();
        registry.register(Box::new(rx_bytes_total.clone())).unwrap();
        registry.register(Box::new(tx_bytes_per_sec.clone())).unwrap();
        registry.register(Box::new(rx_bytes_per_sec.clone())).unwrap();
        registry.register(Box::new(tx_bps.clone())).unwrap();
        registry.register(Box::new(rx_bps.clone())).unwrap();
        registry.register(Box::new(retransmissions_per_sec.clone())).unwrap();
        registry.register(Box::new(duplicate_acks_per_sec.clone())).unwrap();
        registry.register(Box::new(window_size_changes_per_sec.clone())).unwrap();
        
        registry.register(Box::new(ip_tx_bytes_total.clone())).unwrap();
        registry.register(Box::new(ip_rx_bytes_total.clone())).unwrap();
        registry.register(Box::new(ip_tx_bytes_per_sec.clone())).unwrap();
        registry.register(Box::new(ip_rx_bytes_per_sec.clone())).unwrap();
        registry.register(Box::new(ip_tx_bps.clone())).unwrap();
        registry.register(Box::new(ip_rx_bps.clone())).unwrap();
        registry.register(Box::new(ip_retransmissions_per_sec.clone())).unwrap();
        registry.register(Box::new(ip_duplicate_acks_per_sec.clone())).unwrap();
        registry.register(Box::new(ip_window_size_changes_per_sec.clone())).unwrap();
        registry.register(Box::new(ip_retransmissions_total.clone())).unwrap();
        registry.register(Box::new(ip_duplicate_acks_total.clone())).unwrap();
        registry.register(Box::new(ip_window_size_changes_total.clone())).unwrap();
        
        Self {
            registry,
            tx_bytes_total,
            rx_bytes_total,
            tx_bytes_per_sec,
            rx_bytes_per_sec,
            tx_bps,
            rx_bps,
            retransmissions_per_sec,
            duplicate_acks_per_sec,
            window_size_changes_per_sec,
            ip_tx_bytes_total,
            ip_rx_bytes_total,
            ip_tx_bytes_per_sec,
            ip_rx_bytes_per_sec,
            ip_tx_bps,
            ip_rx_bps,
            ip_retransmissions_per_sec,
            ip_duplicate_acks_per_sec,
            ip_window_size_changes_per_sec,
        }
    }
    
    fn update_metrics(&self, stats: &HashMap<IpAddr, IpStats>, target_ips: &HashSet<IpAddr>) {
        let mut total_tx_bytes = 0u64;
        let mut total_rx_bytes = 0u64;
        let mut total_tx_bytes_per_sec = 0u64;
        let mut total_rx_bytes_per_sec = 0u64;
        let mut total_tx_bps = 0f64;
        let mut total_rx_bps = 0f64;
        let mut total_retransmissions_per_sec = 0u64;
        let mut total_duplicate_acks_per_sec = 0u64;
        let mut total_window_size_changes_per_sec = 0u64;
        
        for (ip, stat) in stats {
            let ip_str = ip.to_string();
            
            // 累積値は一度だけ設定（reset使わない）
            let tx_counter = self.ip_tx_bytes_total.with_label_values(&[&ip_str]);
            let rx_counter = self.ip_rx_bytes_total.with_label_values(&[&ip_str]);
            
            // 現在の値を取得して差分を計算
            let current_tx = tx_counter.get();
            let current_rx = rx_counter.get();
            
            if stat.tx_byte_count as f64 > current_tx {
                tx_counter.inc_by(stat.tx_byte_count as f64 - current_tx);
            }
            if stat.rx_byte_count as f64 > current_rx {
                rx_counter.inc_by(stat.rx_byte_count as f64 - current_rx);
            }
            
            // 1秒間の値はGaugeで設定
            self.ip_tx_bytes_per_sec.with_label_values(&[&ip_str]).set(stat.tx_bytes_per_sec as f64);
            self.ip_rx_bytes_per_sec.with_label_values(&[&ip_str]).set(stat.rx_bytes_per_sec as f64);
            self.ip_tx_bps.with_label_values(&[&ip_str]).set(stat.tx_current_bps);
            self.ip_rx_bps.with_label_values(&[&ip_str]).set(stat.rx_current_bps);
            
            // パケットロス関連も同じように処理
            self.ip_retransmissions_per_sec.with_label_values(&[&ip_str]).set(stat.retransmissions_per_sec as f64);
            self.ip_duplicate_acks_per_sec.with_label_values(&[&ip_str]).set(stat.duplicate_acks_per_sec as f64);
            self.ip_window_size_changes_per_sec.with_label_values(&[&ip_str]).set(stat.window_size_changes_per_sec as f64);
            
            // target_ipsに含まれる場合のみ全体統計に含める
            if target_ips.contains(ip) {
                total_tx_bytes += stat.tx_byte_count;
                total_rx_bytes += stat.rx_byte_count;
                total_tx_bytes_per_sec += stat.tx_bytes_per_sec;
                total_rx_bytes_per_sec += stat.rx_bytes_per_sec;
                total_tx_bps += stat.tx_current_bps;
                total_rx_bps += stat.rx_current_bps;
                total_retransmissions_per_sec += stat.retransmissions_per_sec;
                total_duplicate_acks_per_sec += stat.duplicate_acks_per_sec;
                total_window_size_changes_per_sec += stat.window_size_changes_per_sec;
            }
        }
        
        // 全体のメトリクスを更新（累積値は適切に処理）
        let current_total_tx = self.tx_bytes_total.get();
        let current_total_rx = self.rx_bytes_total.get();
        
        if total_tx_bytes as f64 > current_total_tx {
            self.tx_bytes_total.inc_by(total_tx_bytes as f64 - current_total_tx);
        }
        if total_rx_bytes as f64 > current_total_rx {
            self.rx_bytes_total.inc_by(total_rx_bytes as f64 - current_total_rx);
        }
        
        self.tx_bytes_per_sec.set(total_tx_bytes_per_sec as f64);
        self.rx_bytes_per_sec.set(total_rx_bytes_per_sec as f64);
        self.tx_bps.set(total_tx_bps);
        self.rx_bps.set(total_rx_bps);
        self.retransmissions_per_sec.set(total_retransmissions_per_sec as f64);
        self.duplicate_acks_per_sec.set(total_duplicate_acks_per_sec as f64);
        self.window_size_changes_per_sec.set(total_window_size_changes_per_sec as f64);
    }
}

struct IpStats {
    tx_packet_count: u64,  // 送信パケット数
    rx_packet_count: u64,  // 受信パケット数
    tx_byte_count: u64,    // 送信バイト数
    rx_byte_count: u64,    // 受信バイト数
    tx_last_bytes: u64,
    rx_last_bytes: u64,
    last_time: Instant,
    tx_current_bps: f64,   // 送信ビット/秒
    rx_current_bps: f64,   // 受信ビット/秒
    tx_bytes_per_sec: u64, // 1秒間の送信バイト数
    rx_bytes_per_sec: u64, // 1秒間の受信バイト数
    
    // パケットロス関連
    expected_seq: HashMap<u16, u32>, // ポート別の期待シーケンス番号
    retransmissions: u64,           // 再送パケット数
    duplicate_acks: u64,            // 重複ACK数
    last_retransmissions: u64,      // 前回の再送パケット数
    last_duplicate_acks: u64,       // 前回の重複ACK数
    retransmissions_per_sec: u64,   // 1秒間の再送パケット数
    duplicate_acks_per_sec: u64,    // 1秒間の重複ACK数
    
    // TCPウィンドウサイズ関連
    last_window_size: HashMap<u16, u16>, // ポート別の最後のウィンドウサイズ
    window_size_changes: u64,            // ウィンドウサイズ変更回数
    last_window_size_changes: u64,       // 前回のウィンドウサイズ変更回数
    window_size_changes_per_sec: u64,    // 1秒間のウィンドウサイズ変更回数
}

fn get_interface_info(interface_name: &str) -> Option<(Ipv4Addr, u8)> {
    let interfaces = datalink::interfaces();

    for interface in interfaces {
        if interface.name == interface_name {
            for network in interface.ips {
                if let IpNetwork::V4(ipv4_network) = network {
                    return Some((ipv4_network.ip(), ipv4_network.prefix()));
                }
            }
        }
    }
    None
}

fn ipv4_list(ip: Ipv4Addr, prefix: u8) -> HashSet<IpAddr> {
    let ip_u32 = u32::from(ip);
    let mask = !(0xFFFFFFFFu32 >> prefix);
    let network_addr_u32 = ip_u32 & mask;
    let broadcast_addr_u32 = network_addr_u32 | !mask;

    let mut ip_address_set = HashSet::new();

    // ネットワークアドレスとブロードキャストアドレスを除く
    for ip_int in (network_addr_u32 + 1)..broadcast_addr_u32 {
        ip_address_set.insert(IpAddr::V4(Ipv4Addr::from(ip_int)));
    }

    ip_address_set
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <interface_name>", args[0]);
        process::exit(1);
    }

    let interface_name = &args[1];

    match get_interface_info(interface_name) {
        Some((ip, prefix)) => {
            println!("Interface: {}", interface_name);
            println!("IP Address: {}", ip);
            println!("Subnet Mask: /{}", prefix);

            let ip_set = ipv4_list(ip, prefix);
            println!("Available IP addresses in subnet: {} addresses", ip_set.len());
            
            // 最初の10個のIPアドレスを表示
            let mut count = 0;
            for ip_addr in &ip_set {
                if count < 10 {
                    println!("  {}", ip_addr);
                    count += 1;
                } else {
                    println!("  ... and {} more", ip_set.len() - 10);
                    break;
                }
            }
            
            // Prometheusメトリクスを初期化
            let prometheus_metrics = Arc::new(PrometheusMetrics::new());
            
            // Prometheus HTTPサーバーを起動
            let metrics_clone = prometheus_metrics.clone();
            let rt = Runtime::new().unwrap();
            rt.spawn(async move {
                start_prometheus_server(metrics_clone).await;
            });
            
            // パケットキャプチャ部分に進む
            start_packet_capture(interface_name, ip_set, prometheus_metrics);
        }
        None => {
            eprintln!(
                "Interface '{}' not found or has no IPv4 address",
                interface_name
            );
            process::exit(1);
        }
    }
}

fn start_packet_capture(interface_name: &str, target_ips: HashSet<IpAddr>, prometheus_metrics: Arc<PrometheusMetrics>) {
    // インターフェースを見つける
    let device = Device::list()
        .unwrap()
        .into_iter()
        .find(|d| d.name == *interface_name)
        .unwrap_or_else(|| {
            eprintln!("Interface '{}' not found", interface_name);
            process::exit(1);
        });

    println!("Capturing on interface: {}", device.name);
    println!("Monitoring {} IP addresses in the subnet", target_ips.len());

    // キャプチャを開始
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .timeout(100) // タイムアウトを短くして応答性を向上
        .open()
        .unwrap();

    let ip_stats = Arc::new(Mutex::new(HashMap::new()));
    let running = Arc::new(AtomicBool::new(true));

    // Ctrl+C ハンドラ
    ctrlc::set_handler(move || {
        let _count = SIGINT_COUNT.fetch_add(1, Ordering::SeqCst);
        println!("\nForce quitting...");
        process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // 統計表示用スレッド
    let stats_running = running.clone();
    let ip_stats_clone = Arc::clone(&ip_stats);
    let target_ips_clone = target_ips.clone();
    let prometheus_metrics_clone = prometheus_metrics.clone();
    let stats_thread = thread::spawn(move || {
        while stats_running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100)); // より短い間隔でチェック
            if !stats_running.load(Ordering::SeqCst) {
                break;
            }
            {
                let mut stats = ip_stats_clone.lock().unwrap();
                calculate_bps(&mut stats);
                prometheus_metrics_clone.update_metrics(&stats, &target_ips_clone);
                print_stats(&stats, &target_ips_clone);
            }
            // 1秒待つが、100msごとに中断チェック
            for _ in 0..10 {
                if !stats_running.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    });

    println!("Press Ctrl+C to stop...");

    let mut consecutive_timeouts = 0;
    const MAX_CONSECUTIVE_TIMEOUTS: u32 = 50; // 5秒間タイムアウトが続いたら強制チェック

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                consecutive_timeouts = 0; // パケットを受信したらリセット
                if let Some(ethernet) = EthernetPacket::new(packet.data) {
                    match ethernet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                let src_ip = IpAddr::V4(ipv4.get_source());
                                let dst_ip = IpAddr::V4(ipv4.get_destination());

                                // ソースまたはデスティネーションがターゲットIPセットに含まれている場合のみ処理
                                if target_ips.contains(&src_ip) || target_ips.contains(&dst_ip) {
                                    let mut stats = ip_stats.lock().unwrap();
                                    
                                    // TCPパケットの場合、追加情報を解析
                                    if ipv4.get_next_level_protocol() == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                                        if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                            // 送信トラフィック（ソースIPがターゲットセット内）
                                            if target_ips.contains(&src_ip) {
                                                update_tx_stats_with_tcp(&mut stats, src_ip, packet.header.len as u64, &tcp);
                                            }
                                            
                                            // 受信トラフィック（デスティネーションIPがターゲットセット内）
                                            if target_ips.contains(&dst_ip) {
                                                update_rx_stats_with_tcp(&mut stats, dst_ip, packet.header.len as u64, &tcp);
                                            }
                                        }
                                    } else {
                                        // 非TCPパケット
                                        if target_ips.contains(&src_ip) {
                                            update_tx_stats(&mut stats, src_ip, packet.header.len as u64);
                                        }
                                        
                                        if target_ips.contains(&dst_ip) {
                                            update_rx_stats(&mut stats, dst_ip, packet.header.len as u64);
                                        }
                                    }
                                }
                            }
                        }
                        EtherTypes::Ipv6 => {
                            if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                                let src_ip = IpAddr::V6(ipv6.get_source());
                                let _dst_ip = IpAddr::V6(ipv6.get_destination());

                                // IPv6の場合、ターゲットセットには含まれていないが、記録はする
                                // 必要に応じてIPv6のフィルタリングも追加可能
                                let mut stats = ip_stats.lock().unwrap();
                                update_tx_stats(&mut stats, src_ip, packet.header.len as u64);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                consecutive_timeouts += 1;
                // タイムアウト時にrunningフラグをチェック
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                // 長時間タイムアウトが続く場合も強制的にrunningフラグをチェック
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS {
                    consecutive_timeouts = 0;
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                }
                continue;
            }
            Err(e) => {
                eprintln!("Error reading packet: {}", e);
                break;
            }
        }
    }

    // 統計表示スレッドの終了を待つ
    let _ = stats_thread.join();

    println!("\nFinal statistics:");
    {
        let mut final_stats = ip_stats.lock().unwrap();
        calculate_bps(&mut final_stats);
        prometheus_metrics.update_metrics(&final_stats, &target_ips);
        print_stats(&final_stats, &target_ips);
    }
}

fn update_tx_stats(stats: &mut HashMap<IpAddr, IpStats>, ip: IpAddr, bytes: u64) {
    let now = Instant::now();
    let entry = stats.entry(ip).or_insert(IpStats {
        tx_packet_count: 0,
        rx_packet_count: 0,
        tx_byte_count: 0,
        rx_byte_count: 0,
        tx_last_bytes: 0,
        rx_last_bytes: 0,
        last_time: now,
        tx_current_bps: 0.0,
        rx_current_bps: 0.0,
        tx_bytes_per_sec: 0,
        rx_bytes_per_sec: 0,
        expected_seq: HashMap::new(),
        retransmissions: 0,
        duplicate_acks: 0,
        last_retransmissions: 0,
        last_duplicate_acks: 0,
        retransmissions_per_sec: 0,
        duplicate_acks_per_sec: 0,
        last_window_size: HashMap::new(),
        window_size_changes: 0,
        last_window_size_changes: 0,
        window_size_changes_per_sec: 0,
    });

    entry.tx_packet_count += 1;
    entry.tx_byte_count += bytes;
}

fn update_rx_stats(stats: &mut HashMap<IpAddr, IpStats>, ip: IpAddr, bytes: u64) {
    let now = Instant::now();
    let entry = stats.entry(ip).or_insert(IpStats {
        tx_packet_count: 0,
        rx_packet_count: 0,
        tx_byte_count: 0,
        rx_byte_count: 0,
        tx_last_bytes: 0,
        rx_last_bytes: 0,
        last_time: now,
        tx_current_bps: 0.0,
        rx_current_bps: 0.0,
        tx_bytes_per_sec: 0,
        rx_bytes_per_sec: 0,
        expected_seq: HashMap::new(),
        retransmissions: 0,
        duplicate_acks: 0,
        last_retransmissions: 0,
        last_duplicate_acks: 0,
        retransmissions_per_sec: 0,
        duplicate_acks_per_sec: 0,
        last_window_size: HashMap::new(),
        window_size_changes: 0,
        last_window_size_changes: 0,
        window_size_changes_per_sec: 0,
    });

    entry.rx_packet_count += 1;
    entry.rx_byte_count += bytes;
}

fn update_tx_stats_with_tcp(stats: &mut HashMap<IpAddr, IpStats>, ip: IpAddr, bytes: u64, tcp: &TcpPacket) {
    let now = Instant::now();
    let entry = stats.entry(ip).or_insert(IpStats {
        tx_packet_count: 0,
        rx_packet_count: 0,
        tx_byte_count: 0,
        rx_byte_count: 0,
        tx_last_bytes: 0,
        rx_last_bytes: 0,
        last_time: now,
        tx_current_bps: 0.0,
        rx_current_bps: 0.0,
        tx_bytes_per_sec: 0,
        rx_bytes_per_sec: 0,
        expected_seq: HashMap::new(),
        retransmissions: 0,
        duplicate_acks: 0,
        last_retransmissions: 0,
        last_duplicate_acks: 0,
        retransmissions_per_sec: 0,
        duplicate_acks_per_sec: 0,
        last_window_size: HashMap::new(),
        window_size_changes: 0,
        last_window_size_changes: 0,
        window_size_changes_per_sec: 0,
    });

    entry.tx_packet_count += 1;
    entry.tx_byte_count += bytes;
    
    let src_port = tcp.get_source();
    let seq_num = tcp.get_sequence();
    let _ack_num = tcp.get_acknowledgement();
    let window_size = tcp.get_window();
    
    // パケットロス検出（簡易版）
    if let Some(&expected) = entry.expected_seq.get(&src_port) {
        if seq_num < expected {
            // 再送パケットの可能性
            entry.retransmissions += 1;
        }
    }
    
    // 期待シーケンス番号の更新
    let payload_len = tcp.payload().len() as u32;
    if payload_len > 0 || (tcp.get_flags() & TcpFlags::SYN) != 0 || (tcp.get_flags() & TcpFlags::FIN) != 0 {
        entry.expected_seq.insert(src_port, seq_num + payload_len + 1);
    }
    
    // ウィンドウサイズ変更の検出
    if let Some(&last_window) = entry.last_window_size.get(&src_port) {
        if window_size != last_window {
            entry.window_size_changes += 1;
        }
    }
    entry.last_window_size.insert(src_port, window_size);
}

fn update_rx_stats_with_tcp(stats: &mut HashMap<IpAddr, IpStats>, ip: IpAddr, bytes: u64, tcp: &TcpPacket) {
    let now = Instant::now();
    let entry = stats.entry(ip).or_insert(IpStats {
        tx_packet_count: 0,
        rx_packet_count: 0,
        tx_byte_count: 0,
        rx_byte_count: 0,
        tx_last_bytes: 0,
        rx_last_bytes: 0,
        last_time: now,
        tx_current_bps: 0.0,
        rx_current_bps: 0.0,
        tx_bytes_per_sec: 0,
        rx_bytes_per_sec: 0,
        expected_seq: HashMap::new(),
        retransmissions: 0,
        duplicate_acks: 0,
        last_retransmissions: 0,
        last_duplicate_acks: 0,
        retransmissions_per_sec: 0,
        duplicate_acks_per_sec: 0,
        last_window_size: HashMap::new(),
        window_size_changes: 0,
        last_window_size_changes: 0,
        window_size_changes_per_sec: 0,
    });

    entry.rx_packet_count += 1;
    entry.rx_byte_count += bytes;
    
    let dst_port = tcp.get_destination();
    let _ack_num = tcp.get_acknowledgement();
    let window_size = tcp.get_window();
    
    // 重複ACKの検出（簡易版）
    if (tcp.get_flags() & TcpFlags::ACK) != 0 && tcp.payload().is_empty() {
        // 同じACK番号が連続して来た場合は重複ACKとみなす
        entry.duplicate_acks += 1;
    }
    
    // ウィンドウサイズ変更の検出
    if let Some(&last_window) = entry.last_window_size.get(&dst_port) {
        if window_size != last_window {
            entry.window_size_changes += 1;
        }
    }
    entry.last_window_size.insert(dst_port, window_size);
}

fn calculate_bps(stats: &mut HashMap<IpAddr, IpStats>) {
    let now = Instant::now();

    for (_, stat) in stats.iter_mut() {
        let time_diff = now.duration_since(stat.last_time).as_secs_f64();
        if time_diff >= 1.0 {
            let tx_bytes_diff = stat.tx_byte_count - stat.tx_last_bytes;
            let rx_bytes_diff = stat.rx_byte_count - stat.rx_last_bytes;
            
            // バイトをビットに変換してからビット/秒を計算
            stat.tx_current_bps = (tx_bytes_diff as f64 * 8.0) / time_diff;
            stat.rx_current_bps = (rx_bytes_diff as f64 * 8.0) / time_diff;

            // 1秒間のバイト数を計算
            stat.tx_bytes_per_sec = tx_bytes_diff;
            stat.rx_bytes_per_sec = rx_bytes_diff;

            // パケットロスの1秒間の値を計算
            stat.retransmissions_per_sec = stat.retransmissions - stat.last_retransmissions;
            stat.duplicate_acks_per_sec = stat.duplicate_acks - stat.last_duplicate_acks;
            
            // ウィンドウサイズ変更の1秒間の値を計算
            stat.window_size_changes_per_sec = stat.window_size_changes - stat.last_window_size_changes;

            stat.tx_last_bytes = stat.tx_byte_count;
            stat.rx_last_bytes = stat.rx_byte_count;
            stat.last_retransmissions = stat.retransmissions;
            stat.last_duplicate_acks = stat.duplicate_acks;
            stat.last_window_size_changes = stat.window_size_changes;
            stat.last_time = now;
        }
    }
}

fn print_stats(stats: &HashMap<IpAddr, IpStats>, target_ips: &HashSet<IpAddr>) {
    // Clear screen and move cursor to top
    print!("\x1B[2J\x1B[1;1H");

    println!("=== Subnet Network Traffic Monitor ===");
    println!(
        "{:<30} {:>10} {:>10} {:>10} {:>10} {:>6} {:>6} {:>6}",
        "IP Address", "TX/s", "RX/s", "↑ Up", "↓ Down", "PLoss/s", "DupAck/s", "WinChg/s"
    );
    println!("{:-<120}", "");

    let mut sorted_stats: Vec<_> = stats.iter().collect();
    sorted_stats.sort_by(|a, b| {
        let a_total_bps = a.1.tx_current_bps + a.1.rx_current_bps;
        let b_total_bps = b.1.tx_current_bps + b.1.rx_current_bps;
        b_total_bps
            .partial_cmp(&a_total_bps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if sorted_stats.is_empty() {
        println!("No traffic detected from monitored subnet IPs...");
    } else {
        for (ip, stat) in sorted_stats.iter().take(20) {
            let is_subnet_ip = target_ips.contains(ip);
            let ip_prefix = if is_subnet_ip { "" } else { "*" };
            
            println!(
                "{}{:<29} {:>10} {:>10} {:>10} {:>10} {:>6} {:>6} {:>6}",
                ip_prefix,
                ip.to_string(),
                format_bytes_short(stat.tx_bytes_per_sec),
                format_bytes_short(stat.rx_bytes_per_sec),
                format_bps_short(stat.tx_current_bps),
                format_bps_short(stat.rx_current_bps),
                stat.retransmissions_per_sec,
                stat.duplicate_acks_per_sec,
                stat.window_size_changes_per_sec
            );
        }
    }
    
    let subnet_ips_with_traffic = sorted_stats.iter()
        .filter(|(ip, _)| target_ips.contains(ip))
        .count();
    let external_ips_with_traffic = sorted_stats.len() - subnet_ips_with_traffic;
    
    println!();
    println!("Legend: TX/s=TX Bytes per second, RX/s=RX Bytes per second, PLoss/s=Packet Loss per second");
    println!("        DupAck/s=Duplicate ACKs per second, WinChg/s=Window Size Changes per second");
    println!("Subnet IPs: {} | External IPs: {} (*) | Total subnet: {}", 
             subnet_ips_with_traffic, external_ips_with_traffic, target_ips.len());
}

fn format_bps_short(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.1}G", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.1}M", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1}K", bps / 1_000.0)
    } else {
        format!("{:.0}", bps)
    }
}

fn format_bytes_short(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}M", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.1}K", bytes as f64 / 1_024.0)
    } else {
        format!("{}", bytes)
    }
}

async fn start_prometheus_server(metrics: Arc<PrometheusMetrics>) {
    let make_svc = make_service_fn(move |_conn| {
        let metrics = metrics.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let metrics = metrics.clone();
                async move {
                    match req.uri().path() {
                        "/metrics" => {
                            let encoder = TextEncoder::new();
                            let metric_families = metrics.registry.gather();
                            let mut buffer = Vec::new();
                            encoder.encode(&metric_families, &mut buffer).unwrap();
                            Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
                        }
                        _ => {
                            let response = Response::builder()
                                .status(404)
                                .body(Body::from("Not Found"))
                                .unwrap();
                            Ok(response)
                        }
                    }
                }
            }))
        }
    });

    let addr = SocketAddr::from(([127, 0, 0, 1], 59122));
    let server = Server::bind(&addr).serve(make_svc);

    println!("Prometheus metrics server listening on http://{}/metrics", addr);
    
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }
}
