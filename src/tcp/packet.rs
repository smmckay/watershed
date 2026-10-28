use crate::tcp::TcpError;
use crate::tcp::header::TcpHeader;
use crate::tcp::option::{TcpOption, TcpOptionIterator};

#[derive(Debug)]
pub struct TcpPacket<'a> {
    raw: &'a [u8],
    tcp_hdr: TcpHeader,
    payload: &'a [u8],
}

impl <'a> TcpPacket<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, TcpError> {
        // FIXME: validate packet
        let header = TcpHeader::parse(raw)?;
        let payload = &raw[(header.doff as usize * 4)..];
        let packet = Self { raw, tcp_hdr: header, payload };
        for r in packet.iter_options() {
            if let Err(e) = r {
                return Err(e);
            }
        }
        Ok(packet)
    }

    pub fn has_options(&self) -> bool {
        self.tcp_hdr.doff > 5
    }

    pub fn iter_options(&self) -> impl Iterator<Item = Result<TcpOption, TcpError>> {
        TcpOptionIterator::new(&self.raw[20..(self.tcp_hdr.doff as usize * 4)])
    }
}