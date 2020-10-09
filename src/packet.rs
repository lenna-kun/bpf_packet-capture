#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

/// Represents the Ethernet ethertype field.
#[derive(Hash, Ord, PartialOrd, Eq, PartialEq, Debug, Clone, Copy)]
pub struct EtherType(pub u16);
impl EtherType {
    /// Construct a new EtherType
    pub fn new(val: u16) -> EtherType { EtherType(val) }
}

/// A structure enabling manipulation of on the wire packets
#[derive(PartialEq)]
pub struct EthernetPacket<'p> {
    packet: &'p [u8],
}

impl <'a> EthernetPacket<'a> {
    /// Constructs a new EthernetPacket. If the provided buffer is less than the minimum required
    /// packet size, this will return None.
    #[inline]
    pub fn new<'p>(packet: &'p [u8]) -> Option<EthernetPacket<'p>> {
        if packet.len() >= EthernetPacket::minimum_packet_size() {
            Some(EthernetPacket{packet: packet,})
        } else { None }
    }

    /// The minimum size (in bytes) a packet of this type can be. It's based on the total size
    /// of the fixed-size fields.
    #[inline]
    pub fn minimum_packet_size() -> usize { 14 }

    /// Get the value of the destination field
    #[inline]
    pub fn get_destination(&self) -> MacAddr {
        MacAddr::new(self.packet[0], self.packet[1], self.packet[2],
                     self.packet[3], self.packet[4], self.packet[5])
    }

    /// Get the value of the source field
    #[inline]
    pub fn get_source(&self) -> MacAddr {
        MacAddr::new(self.packet[6], self.packet[7], self.packet[8],
                     self.packet[9], self.packet[10], self.packet[11])
    }
    /// Get the value of the ethertype field
    #[inline]
    pub fn get_ethertype(&self) -> EtherType {
        EtherType::new(((self.packet[12] as u16) << 8) | (self.packet[13] as u16))
    }
}