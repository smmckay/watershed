use crate::tcp::TcpError;

#[derive(Debug, Eq, PartialEq)]
pub enum TcpOption {
    EndOfOptions,
    Noop,
    MSS(u16),

    Unknown,
}

pub struct TcpOptionIterator<'a> {
    options: &'a [u8],
}

impl<'a> TcpOptionIterator<'a> {
    pub fn new(options: &'a [u8]) -> Self {
        Self { options }
    }
}

impl <'a> Iterator for TcpOptionIterator<'a> {
    type Item = Result<TcpOption, TcpError>;

    fn next(&mut self) -> Option<Self::Item> {
        match next_option(self.options) {
            Ok((TcpOption::EndOfOptions, _)) => {
                None
            }
            Ok((option, remaining)) => {
                self.options = remaining;
                Some(Ok(option))
            }
            Err(err) => Some(Err(err)),
        }
    }
}

fn next_option(options: &[u8]) -> Result<(TcpOption, &[u8]), TcpError> {
    if options.is_empty() {
        return Ok((TcpOption::EndOfOptions, options));
    }

    match options[0] {
        0 => Ok((TcpOption::EndOfOptions, &options[1..])),
        1 => Ok((TcpOption::Noop, &options[1..])),
        2 => {
            if options.len() < 4 || options[1] != 4 {
                return Err(TcpError::InvalidOption);
            }
            let mss = u16::from_be_bytes([options[2], options[3]]);
            Ok((TcpOption::MSS(mss), &options[4..]))
        }
        _ => {
            if options.len() < 2 || options.len() < options[1] as usize || options[1] < 2 {
                return Err(TcpError::InvalidOption);
            }
            Ok((TcpOption::Unknown, &options[options[1] as usize..]))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_end_of_options() {
        let options: &[u8] = &[];
        let (opt, rest) = next_option(options).unwrap();
        assert!(matches!(opt, TcpOption::EndOfOptions));
        assert_eq!(rest, options);
    }

    #[test]
    fn end_of_options() {
        let options = [0x00, 0x01];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::EndOfOptions));
        assert_eq!(rest, &[0x01]);
    }

    #[test]
    fn noop() {
        let options = [0x01, 0x02];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::Noop));
        assert_eq!(rest, &[0x02]);
    }

    #[test]
    fn mss_valid() {
        let mss: u16 = 0x05B4; // 1460
        let options = [0x02, 0x04, (mss >> 8) as u8, mss as u8, 0x01];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::MSS(v) if v == mss));
        assert_eq!(rest, &[0x01]);
    }

    #[test]
    fn mss_wrong_length_byte() {
        // Length must be exactly 4
        for len in [1, 2, 3, 5, 6] {
            let options = [0x02, len, 0x05, 0xB4, 0x00, 0x00];
            let err = next_option(&options).unwrap_err();
            assert!(matches!(err, TcpError::InvalidOption), "len={len}");
        }
    }

    #[test]
    fn mss_truncated() {
        // Fewer than 4 total bytes
        let options = [0x02, 0x04, 0x05];
        let err = next_option(&options).unwrap_err();
        assert!(matches!(err, TcpError::InvalidOption));
    }

    #[test]
    fn unknown_skips_payload() {
        // Kind 0xFF (sack-permitted), len 2, no payload
        let options = [0xFF, 0x02, 0x01, 0x00];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::Unknown));
        assert_eq!(rest, &[0x01, 0x00]);
    }

    #[test]
    fn unknown_exactly_consumes_all_bytes() {
        // Length extends exactly to the end of the slice
        let options = [0x03, 0x05, 0xAA, 0xBB, 0xCC];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::Unknown));
        assert!(rest.is_empty());
    }

    #[test]
    fn unknown_missing_length_byte() {
        let options = [0xFF];
        let err = next_option(&options).unwrap_err();
        assert!(matches!(err, TcpError::InvalidOption));
    }

    #[test]
    fn unknown_length_exceeds_available_bytes() {
        let options = [0xFF, 0x06, 0xAA, 0xBB];
        let err = next_option(&options).unwrap_err();
        assert!(matches!(err, TcpError::InvalidOption));
    }

    #[test]
    fn sequence_of_options_walks_to_end() {
        let mut options: &[u8] = &[0x02, 0x04, 0x05, 0xB4, 0xFF, 0x02, 0x01, 0x00];
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::MSS(1460)));
        options = rest;

        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::Unknown));
        options = rest;

        // Remaining bytes: a Noop and an end-of-options marker
        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::Noop));
        options = rest;

        let (opt, rest) = next_option(&options).unwrap();
        assert!(matches!(opt, TcpOption::EndOfOptions));
        assert!(rest.is_empty());
    }

    #[test]
    fn options_iterator_walks_to_end() {
        let options: &[u8] = &[0x02, 0x04, 0x05, 0xB4, 0xFF, 0x02, 0x01, 0x00];
        let mut iter = TcpOptionIterator::new(options);
        assert_eq!(iter.next().unwrap(), Ok(TcpOption::MSS(1460)));
        assert_eq!(iter.next().unwrap(), Ok(TcpOption::Unknown));
        assert_eq!(iter.next().unwrap(), Ok(TcpOption::Noop));
        assert!(iter.next().is_none());
    }
}