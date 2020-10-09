#[macro_use]
extern crate log;

use std::env;

mod bpf;
mod datalink;
mod packet;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Please specify target interface name");
        std::process::exit(1);
    }

    let (_tx, mut rx) = match datalink::channel(&args[1], Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Err(e) => panic!("Failed to create datalink channel {}", e),
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = packet::EthernetPacket::new(frame).unwrap();
                println!("ether_header----------------------------");
                println!("ether_dhost={}", frame.get_destination());
                println!("ether_shost={}", frame.get_source());
                match frame.get_ethertype() {
                    packet::EtherType(0x0800) => {
                        println!("ether_type=800(IP)");
                    }
                    packet::EtherType(0x86DD) => {
                        println!("ether_type=86DD(IPv6)");
                    }
                    packet::EtherType(0x0806) => {
                        println!("ether_type=806(ARP)");
                    }
                    _ => {
                        info!("Not an IPv4 or IPv6 or Arp");
                    }
                }
            }
            Err(e) => {
                error!("Failed to read: {}", e);
            }
        }
    }
}
