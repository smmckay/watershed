use byteorder::ByteOrder;
use crate::tcp::TcpError;

#[derive(Debug)]
pub struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    seqnum: u32,
    acknum: u32,
    pub(crate) doff: u8,
    flags: u8,
    win: u16,
    cksum: u16,
    urgptr: u16,
}

pub enum TcpFlags {
    CWR = 0x80,
    ECE = 0x40,
    URG = 0x20,
    ACK = 0x10,
    PSH = 0x08,
    RST = 0x04,
    SYN = 0x02,
    FIN = 0x01,
}

impl TcpHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, TcpError> {
        if raw.len() < 20 {
            return Err(TcpError::HeaderTooShort);
        }

        let header = Self {
            source_port: byteorder::BigEndian::read_u16(raw),
            destination_port: byteorder::BigEndian::read_u16(&raw[2..4]),
            seqnum: byteorder::BigEndian::read_u32(&raw[4..8]),
            acknum: byteorder::BigEndian::read_u32(&raw[8..12]),
            doff: raw[12] >> 4,
            flags: raw[13],
            win: byteorder::BigEndian::read_u16(&raw[14..16]),
            cksum: byteorder::BigEndian::read_u16(&raw[16..18]),
            urgptr: byteorder::BigEndian::read_u16(&raw[18..20]),
        };

        // FIXME: validate

        Ok(header)
    }

    pub fn has_flag(&self, flag: TcpFlags) -> bool {
        self.flags & flag as u8 != 0
    }
}
