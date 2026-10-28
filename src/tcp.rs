pub mod option;
pub mod header;
pub mod packet;

#[derive(Debug, Eq, PartialEq)]
pub enum TcpError {
    HeaderTooShort,
    InvalidOption,
}

pub fn process_packet(input: &[u8], output: &mut Vec<u8>)