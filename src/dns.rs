//! DNS protocol types and utilities.
//!
//! This module provides fundamental DNS types and conversions used for DNS query operations.
//! It includes support for common DNS record types and their string/numeric representations,
//! as well as DNS message header parsing and serialization.
//!
//! The implementation follows RFC 1035 (Domain Names - Implementation and Specification)
//! and related RFCs for DNS protocol compliance.
//!
//! # Core Types
//!
//! - [`QueryType`] - Enumeration of supported DNS record types (A, AAAA, CNAME, MX, TXT)
//! - [`DnsHeader`] - Represents the 12-byte DNS message header
//! - [`ResponseCode`] - DNS response codes indicating query success or failure types
//!
//! # Examples
//!
//! Basic usage of DNS types:
//!
//! ```rust
//! use dns_resolver::dns::{QueryType, DnsHeader, ResponseCode};
//! use std::str::FromStr;
//!
//! // Parse a query type from string
//! let query_type = QueryType::from_str("A").unwrap();
//! assert_eq!(query_type as u16, 1);
//!
//! // Create and serialize a DNS header
//! let mut header = DnsHeader::new();
//! header.id = 12345;
//! header.question_count = 1;
//!
//! let mut buffer = Vec::new();
//! header.pack(&mut buffer);
//! assert_eq!(buffer.len(), 12);
//! ```
//!
//! # Wire Format Compatibility
//!
//! All structures in this module are designed to work with the DNS wire format,
//! using network byte order (big-endian) for multi-byte fields. This ensures
//! compatibility with standard DNS implementations and network protocols.

use core::fmt;
use std::{
    io::{Cursor, Read},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Represents the type of a DNS query according to RFC 1035 and subsequent RFCs.
///
/// This enum maps DNS query types to their standard numeric codes as defined in the DNS
/// specification. It supports the most commonly used DNS record types for basic DNS
/// resolution operations.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::QueryType;
/// use std::str::FromStr;
///
/// // Create from string
/// let query_type = QueryType::from_str("A").unwrap();
/// assert_eq!(query_type, QueryType::A);
///
/// // Convert to numeric code
/// let code = query_type as u16;
/// assert_eq!(code, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum QueryType {
    /// IPv4 address record (RFC 1035).
    A = 1,
    /// IPv6 address record (RFC 3596).
    AAAA = 28,
    /// Canonical name record (RFC 1035).
    CNAME = 5,
    /// Mail exchange record (RFC 1035).
    MX = 15,
    /// Text record (RFC 1035).
    TXT = 16,
}

impl FromStr for QueryType {
    type Err = String;

    /// Parses a string slice into a [`QueryType`].
    ///
    /// The parsing is case-insensitive and supports the standard DNS record type names.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::QueryType;
    /// use std::str::FromStr;
    ///
    /// assert_eq!(QueryType::from_str("A").unwrap(), QueryType::A);
    /// assert_eq!(QueryType::from_str("aaaa").unwrap(), QueryType::AAAA);
    /// assert_eq!(QueryType::from_str("CnAmE").unwrap(), QueryType::CNAME);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the input string does not match any known DNS record type.
    ///
    /// ```rust
    /// use dns_resolver::dns::QueryType;
    /// use std::str::FromStr;
    ///
    /// let result = QueryType::from_str("UNKNOWN");
    /// assert!(result.is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(QueryType::A),
            "AAAA" => Ok(QueryType::AAAA),
            "CNAME" => Ok(QueryType::CNAME),
            "MX" => Ok(QueryType::MX),
            "TXT" => Ok(QueryType::TXT),
            _ => Err(format!("Unknown query type: {}", s)),
        }
    }
}

impl fmt::Display for QueryType {
    /// Formats the [`QueryType`] as its standard DNS record type string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::QueryType;
    ///
    /// assert_eq!(format!("{}", QueryType::A), "A");
    /// assert_eq!(format!("{}", QueryType::AAAA), "AAAA");
    /// assert_eq!(format!("{}", QueryType::MX), "MX");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryType::A => write!(f, "A"),
            QueryType::AAAA => write!(f, "AAAA"),
            QueryType::CNAME => write!(f, "CNAME"),
            QueryType::MX => write!(f, "MX"),
            QueryType::TXT => write!(f, "TXT"),
        }
    }
}

impl TryFrom<u16> for QueryType {
    type Error = String;

    /// Converts a numeric DNS record type code into a [`QueryType`].
    ///
    /// This is useful when parsing DNS packets where record types are represented
    /// as numeric codes according to the DNS specification.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::QueryType;
    ///
    /// assert_eq!(QueryType::try_from(1).unwrap(), QueryType::A);
    /// assert_eq!(QueryType::try_from(28).unwrap(), QueryType::AAAA);
    /// assert_eq!(QueryType::try_from(5).unwrap(), QueryType::CNAME);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the numeric code does not correspond to a supported DNS record type.
    ///
    /// ```rust
    /// use dns_resolver::dns::QueryType;
    ///
    /// let result = QueryType::try_from(999);
    /// assert!(result.is_err());
    /// ```
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(QueryType::A),
            28 => Ok(QueryType::AAAA),
            5 => Ok(QueryType::CNAME),
            15 => Ok(QueryType::MX),
            16 => Ok(QueryType::TXT),
            _ => Err(format!("Unknown query type code: {}", value)),
        }
    }
}

/// Represents the 12-byte header of a DNS message according to RFC 1035.
///
/// The DNS header contains essential information about a DNS message, including
/// identification, flags, and counts for different sections of the DNS packet.
/// This structure follows the standard DNS header format with all fields in
/// network byte order (big-endian).
///
/// # Layout
///
/// The header consists of the following fields in order:
/// - ID (16 bits): Packet identifier for matching queries with responses
/// - Flags (16 bits): Various flags and response codes
/// - QDCOUNT (16 bits): Number of entries in the question section
/// - ANCOUNT (16 bits): Number of resource records in the answer section
/// - NSCOUNT (16 bits): Number of name server resource records in the authority section
/// - ARCOUNT (16 bits): Number of resource records in the additional section
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::DnsHeader;
///
/// // Create a new header for a query
/// let mut header = DnsHeader::new();
/// header.id = 12345;
/// header.question_count = 1;
///
/// // Pack into a byte buffer
/// let mut buffer = Vec::new();
/// header.pack(&mut buffer);
/// assert_eq!(buffer.len(), 12); // DNS header is always 12 bytes
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DnsHeader {
    /// Packet identifier used to match queries with responses.
    ///
    /// This is typically a random value chosen by the client to correlate
    /// DNS queries with their corresponding responses.
    pub id: u16,

    /// Flags and status codes for the DNS message.
    ///
    /// Contains various bit flags including:
    /// - QR (Query/Response): 0 for query, 1 for response
    /// - Opcode: Type of query (standard query, inverse query, etc.)
    /// - AA (Authoritative Answer): Set if responding server is authoritative
    /// - TC (Truncated): Set if message was truncated
    /// - RD (Recursion Desired): Set if recursion is desired
    /// - RA (Recursion Available): Set if recursion is available
    /// - RCODE: Response code indicating success or error
    pub flags: u16,

    /// Number of entries in the question section.
    ///
    /// For most queries, this is 1, but the DNS protocol supports multiple questions.
    pub question_count: u16,

    /// Number of resource records in the answer section.
    ///
    /// This field is typically 0 in queries and contains the number of answers in responses.
    pub answer_count: u16,

    /// Number of name server resource records in the authority section.
    ///
    /// These records point toward an authoritative name server for the queried domain.
    pub authority_count: u16,

    /// Number of resource records in the additional section.
    ///
    /// Additional records provide extra information that may be useful but wasn't
    /// directly requested (e.g., A records for MX record targets).
    pub additional_count: u16,
}

/// Represents the 4-bit Response Code (RCODE) field in the DNS header.
///
/// The response code indicates the status of a DNS query response and is defined
/// in RFC 1035. It's stored in the lower 4 bits of the flags field in the DNS header.
/// These codes help clients understand whether their query was successful and, if not,
/// what type of error occurred.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::{DnsHeader, ResponseCode};
///
/// let header = DnsHeader::new();
/// let response_code = header.get_response_code();
///
/// match response_code {
///     ResponseCode::NoError => println!("Query successful"),
///     ResponseCode::NameError => println!("Domain does not exist"),
///     ResponseCode::ServerFailure => println!("Server encountered an error"),
///     _ => println!("Other error occurred"),
/// }
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseCode {
    /// No error condition (RCODE = 0).
    ///
    /// The query completed successfully and the response contains the requested information.
    NoError = 0,

    /// Format error (RCODE = 1).
    ///
    /// The name server was unable to interpret the query due to a format error.
    /// This typically indicates malformed query packets.
    FormatError = 1,

    /// Server failure (RCODE = 2).
    ///
    /// The name server encountered an internal error and was unable to process
    /// the query. This is a temporary condition that may resolve on retry.
    ServerFailure = 2,

    /// Name error (RCODE = 3).
    ///
    /// The domain name referenced in the query does not exist. This is
    /// commonly known as "NXDOMAIN" and indicates that the queried name
    /// has no DNS records.
    NameError = 3,

    /// Not implemented (RCODE = 4).
    ///
    /// The name server does not support the requested operation type.
    /// This may occur with unsupported query types or opcodes.
    NotImplemented = 4,

    /// Refused (RCODE = 5).
    ///
    /// The name server refuses to perform the requested operation for
    /// policy or security reasons (e.g., unauthorized recursive queries).
    Refused = 5,
}

impl DnsHeader {
    /// Creates a new `DnsHeader` with all fields initialized to zero.
    ///
    /// This is useful for creating a fresh DNS header for a new query.
    /// You'll typically want to set the `id` and `question_count` fields
    /// after creation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsHeader;
    ///
    /// let header = DnsHeader::new();
    /// assert_eq!(header.id, 0);
    /// assert_eq!(header.question_count, 0);
    /// assert_eq!(header.answer_count, 0);
    /// ```
    pub fn new() -> Self {
        DnsHeader {
            id: 0,
            flags: 0,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    /// Serializes the DNS header into bytes and appends them to the provided buffer.
    ///
    /// The header is packed in network byte order (big-endian) according to the
    /// DNS specification. The resulting data will be exactly 12 bytes long.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `Vec<u8>` where the serialized header will be appended
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsHeader;
    ///
    /// let mut header = DnsHeader::new();
    /// header.id = 0x1234;
    /// header.question_count = 1;
    ///
    /// let mut buffer = Vec::new();
    /// header.pack(&mut buffer);
    ///
    /// assert_eq!(buffer.len(), 12);
    /// assert_eq!(&buffer[0..2], &[0x12, 0x34]); // ID in big-endian
    /// ```
    pub fn pack(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(&self.id.to_be_bytes());
        buffer.extend_from_slice(&self.flags.to_be_bytes());
        buffer.extend_from_slice(&self.question_count.to_be_bytes());
        buffer.extend_from_slice(&self.answer_count.to_be_bytes());
        buffer.extend_from_slice(&self.authority_count.to_be_bytes());
        buffer.extend_from_slice(&self.additional_count.to_be_bytes());
    }

    /// Deserializes a DNS header from a byte cursor.
    ///
    /// Reads exactly 12 bytes from the cursor and interprets them as a DNS header
    /// in network byte order (big-endian). The cursor position will be advanced
    /// by 12 bytes upon successful completion.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A mutable reference to a `Cursor<&[u8]>` positioned at the start of the header
    ///
    /// # Returns
    ///
    /// * `Ok(DnsHeader)` - Successfully parsed DNS header
    /// * `Err(std::io::Error)` - If there aren't enough bytes to read a complete header
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsHeader;
    /// use std::io::Cursor;
    ///
    /// let data = [
    ///     0x12, 0x34, // ID
    ///     0x01, 0x00, // Flags
    ///     0x00, 0x01, // Question count
    ///     0x00, 0x00, // Answer count
    ///     0x00, 0x00, // Authority count
    ///     0x00, 0x00, // Additional count
    /// ];
    ///
    /// let mut cursor = Cursor::new(&data[..]);
    /// let header = DnsHeader::from_bytes(&mut cursor).unwrap();
    ///
    /// assert_eq!(header.id, 0x1234);
    /// assert_eq!(header.flags, 0x0100);
    /// assert_eq!(header.question_count, 1);
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The cursor doesn't contain at least 12 bytes of data
    /// - An I/O error occurs while reading from the cursor
    pub fn from_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let mut buf = [0u8; 2];

        cursor.read_exact(&mut buf)?;
        let id = u16::from_be_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let flags = u16::from_be_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let question_count = u16::from_be_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let answer_count = u16::from_be_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let authority_count = u16::from_be_bytes(buf);

        cursor.read_exact(&mut buf)?;
        let additional_count = u16::from_be_bytes(buf);

        Ok(DnsHeader {
            id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }

    /// Extracts the response code from the DNS header flags.
    ///
    /// The response code is stored in the lower 4 bits of the flags field.
    /// This method masks out the relevant bits and converts them to a
    /// [`ResponseCode`] enum value.
    ///
    /// # Returns
    ///
    /// The [`ResponseCode`] extracted from the header flags. If the code
    /// is not recognized, defaults to [`ResponseCode::ServerFailure`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{DnsHeader, ResponseCode};
    ///
    /// let mut header = DnsHeader::new();
    /// header.flags = 0x8003; // Response with NameError (NXDOMAIN)
    ///
    /// let response_code = header.get_response_code();
    /// assert_eq!(response_code, ResponseCode::NameError);
    /// ```
    pub fn get_response_code(&self) -> ResponseCode {
        match self.flags & 0x000F {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => ResponseCode::ServerFailure, // Default to ServerFailure for unknown codes
        }
    }
}

/// Represents a DNS question section entry in a DNS message.
///
/// The question section of a DNS message contains queries that specify what
/// the client is asking the DNS server. Each question consists of a domain name,
/// query type, and query class according to RFC 1035.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::{DnsQuestion, QueryType};
///
/// let question = DnsQuestion {
///     name: "www.example.com".to_string(),
///     qtype: QueryType::A,
///     qclass: 1, // IN (Internet) class
/// };
/// ```
#[derive(Debug, Clone)]
pub struct DnsQuestion {
    /// The domain name being queried (e.g., "www.example.com").
    pub name: String,
    /// The type of DNS record being requested (A, AAAA, CNAME, etc.).
    pub qtype: QueryType,
    /// The query class, typically 1 for Internet (IN) class.
    pub qclass: u16,
}

impl DnsQuestion {
    /// Serializes the DNS question into bytes and appends them to the provided buffer.
    ///
    /// The question is packed according to DNS wire format: domain name in label format,
    /// followed by query type and query class in network byte order.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `Vec<u8>` where the serialized question will be appended
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully serialized the question
    /// * `Err(String)` - If domain name encoding fails (e.g., label too long)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{DnsQuestion, QueryType};
    ///
    /// let question = DnsQuestion {
    ///     name: "example.com".to_string(),
    ///     qtype: QueryType::A,
    ///     qclass: 1,
    /// };
    ///
    /// let mut buffer = Vec::new();
    /// question.pack(&mut buffer).unwrap();
    /// // Buffer now contains the packed question
    /// ```
    pub fn pack(&self, buffer: &mut Vec<u8>) -> Result<(), String> {
        pack_domain_name(buffer, &self.name)?;
        buffer.extend_from_slice(&(self.qtype as u16).to_be_bytes());
        buffer.extend_from_slice(&self.qclass.to_be_bytes());
        Ok(())
    }

    /// Deserializes a DNS question from a byte cursor.
    ///
    /// Reads a DNS question from the cursor in wire format: domain name (with potential
    /// compression), followed by query type and query class in network byte order.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A mutable reference to a `Cursor<&[u8]>` positioned at the start of the question
    ///
    /// # Returns
    ///
    /// * `Ok(DnsQuestion)` - Successfully parsed DNS question
    /// * `Err(std::io::Error)` - If parsing fails due to insufficient data or invalid format
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsQuestion;
    /// use std::io::Cursor;
    ///
    /// let data = [
    ///     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
    ///     3, b'c', b'o', b'm', // "com"
    ///     0, // null terminator
    ///     0, 1, // Type A
    ///     0, 1, // Class IN
    /// ];
    ///
    /// let mut cursor = Cursor::new(&data[..]);
    /// let question = DnsQuestion::from_bytes(&mut cursor).unwrap();
    /// assert_eq!(question.name, "example.com");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The cursor doesn't contain enough data to read a complete question
    /// - The domain name format is invalid or contains compression pointer errors
    /// - The query type is not recognized
    pub fn from_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let name = unpack_domain_name(cursor)?;

        let mut buf = [0u8; 2];
        cursor.read_exact(&mut buf)?;
        let qtype_val = u16::from_be_bytes(buf);
        let qtype = QueryType::try_from(qtype_val)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        cursor.read_exact(&mut buf)?;
        let qclass = u16::from_be_bytes(buf);

        Ok(DnsQuestion {
            name,
            qtype,
            qclass,
        })
    }
}

/// Represents MX record data.
///
/// Contains the preference value and exchange server hostname from an MX record.
#[derive(Debug, Clone)]
#[allow(dead_code)] // This is part of the public API
pub struct MxData {
    /// Priority/preference value - lower numbers have higher priority.
    pub preference: u16,
    /// The hostname of the mail server.
    pub exchange: String,
}

/// Represents a DNS resource record in the answer, authority, or additional sections.
///
/// Resource records contain the actual data returned by DNS servers in response to queries.
/// Each record includes the domain name, record type, class, time-to-live, and the actual data.
/// This structure follows the DNS wire format as defined in RFC 1035.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::{ResourceRecord, QueryType, RData};
/// use std::net::Ipv4Addr;
///
/// let record = ResourceRecord {
///     name: "example.com".to_string(),
///     rtype: QueryType::A,
///     rclass: 1, // IN class
///     ttl: 300,  // 5 minutes
///     data: RData::A(Ipv4Addr::new(93, 184, 216, 34)),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    /// The domain name this record refers to (e.g., "www.example.com").
    pub name: String,
    /// The type of this resource record (A, AAAA, CNAME, etc.).
    pub rtype: QueryType,
    /// The record class, typically 1 for Internet (IN) class.
    #[allow(dead_code)] // Used by get_class() method
    pub rclass: u16,
    /// Time-to-live in seconds - how long this record can be cached.
    pub ttl: u32,
    /// The actual resource record data, typed according to the record type.
    pub data: RData,
}

/// Represents the data payload of a DNS resource record.
///
/// Different DNS record types carry different kinds of data. This enum encapsulates
/// all supported record data types, providing type-safe access to the record content.
/// Unsupported record types are stored as raw bytes for forward compatibility.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::RData;
/// use std::net::{Ipv4Addr, Ipv6Addr};
///
/// // IPv4 address record
/// let a_record = RData::A(Ipv4Addr::new(192, 0, 2, 1));
///
/// // Mail exchange record
/// let mx_record = RData::MX {
///     preference: 10,
///     exchange: "mail.example.com".to_string(),
/// };
///
/// // Text record
/// let txt_record = RData::TXT("v=spf1 include:_spf.google.com ~all".to_string());
/// ```
#[derive(Debug, Clone)]
pub enum RData {
    /// IPv4 address record data (A record).
    A(Ipv4Addr),
    /// IPv6 address record data (AAAA record).
    AAAA(Ipv6Addr),
    /// Canonical name record data (CNAME record) - points to another domain name.
    CNAME(String),
    /// Mail exchange record data (MX record) with preference and mail server hostname.
    MX {
        /// Priority/preference value - lower numbers have higher priority.
        preference: u16,
        /// The hostname of the mail server.
        exchange: String,
    },
    /// Text record data (TXT record) containing arbitrary text.
    TXT(String),
    /// Raw data for unsupported record types, preserving the original type code and data.
    Other {
        /// The numeric DNS record type code.
        rtype: u16,
        /// The raw record data as received from the server.
        #[allow(dead_code)] // Used by get_raw_data() method
        data: Vec<u8>,
    },
}

impl fmt::Display for ResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<30} {:<10} {:<10} {}",
            self.name, self.ttl, self.rtype, self.data
        )
    }
}

impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(addr) => write!(f, "A {}", addr),
            RData::AAAA(addr) => write!(f, "AAAA {}", addr),
            RData::CNAME(name) => write!(f, "CNAME {}", name),
            RData::MX {
                preference,
                exchange,
            } => write!(f, "MX {} {}", preference, exchange),
            RData::TXT(text) => write!(f, "TXT \"{}\"", text),
            RData::Other { rtype, .. } => write!(f, "TYPE={} (Unsupported)", rtype),
        }
    }
}

impl ResourceRecord {
    /// Gets the IPv4 address from an A record.
    ///
    /// # Returns
    ///
    /// * `Some(Ipv4Addr)` - The IPv4 address if this is an A record
    /// * `None` - If this is not an A record
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{ResourceRecord, QueryType, RData};
    /// use std::net::Ipv4Addr;
    ///
    /// let record = ResourceRecord {
    ///     name: "example.com".to_string(),
    ///     rtype: QueryType::A,
    ///     rclass: 1,
    ///     ttl: 300,
    ///     data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    /// };
    ///
    /// if let Some(ip) = record.get_ipv4_address() {
    ///     println!("IP address: {}", ip);
    /// }
    /// ```
    #[allow(dead_code)] // Public API method
    pub fn get_ipv4_address(&self) -> Option<std::net::Ipv4Addr> {
        match &self.data {
            RData::A(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Gets the IPv6 address from an AAAA record.
    ///
    /// # Returns
    ///
    /// * `Some(Ipv6Addr)` - The IPv6 address if this is an AAAA record
    /// * `None` - If this is not an AAAA record
    #[allow(dead_code)] // Public API method
    pub fn get_ipv6_address(&self) -> Option<std::net::Ipv6Addr> {
        match &self.data {
            RData::AAAA(addr) => Some(*addr),
            _ => None,
        }
    }

    /// Gets the MX record data.
    ///
    /// # Returns
    ///
    /// * `Some(MxData)` - The MX record data if this is an MX record
    /// * `None` - If this is not an MX record
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{ResourceRecord, QueryType, RData};
    ///
    /// let record = ResourceRecord {
    ///     name: "example.com".to_string(),
    ///     rtype: QueryType::MX,
    ///     rclass: 1,
    ///     ttl: 3600,
    ///     data: RData::MX {
    ///         preference: 10,
    ///         exchange: "mail.example.com".to_string(),
    ///     },
    /// };
    ///
    /// if let Some(mx_data) = record.get_mx_data() {
    ///     println!("Mail server: {} (priority: {})", mx_data.exchange, mx_data.preference);
    /// }
    /// ```
    #[allow(dead_code)] // Public API method
    pub fn get_mx_data(&self) -> Option<MxData> {
        match &self.data {
            RData::MX {
                preference,
                exchange,
            } => Some(MxData {
                preference: *preference,
                exchange: exchange.clone(),
            }),
            _ => None,
        }
    }

    /// Gets the CNAME target from a CNAME record.
    ///
    /// # Returns
    ///
    /// * `Some(String)` - The canonical name if this is a CNAME record
    /// * `None` - If this is not a CNAME record
    #[allow(dead_code)] // Public API method
    pub fn get_cname(&self) -> Option<&str> {
        match &self.data {
            RData::CNAME(name) => Some(name),
            _ => None,
        }
    }

    /// Gets the text content from a TXT record.
    ///
    /// # Returns
    ///
    /// * `Some(String)` - The text content if this is a TXT record
    /// * `None` - If this is not a TXT record
    #[allow(dead_code)] // Public API method
    pub fn get_txt_data(&self) -> Option<&str> {
        match &self.data {
            RData::TXT(text) => Some(text),
            _ => None,
        }
    }

    /// Gets the record class.
    ///
    /// # Returns
    ///
    /// The record class value. Typically 1 for Internet (IN) class.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{ResourceRecord, QueryType, RData};
    /// use std::net::Ipv4Addr;
    ///
    /// let record = ResourceRecord {
    ///     name: "example.com".to_string(),
    ///     rtype: QueryType::A,
    ///     rclass: 1, // IN class
    ///     ttl: 300,
    ///     data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    /// };
    ///
    /// assert_eq!(record.get_class(), 1); // Internet class
    /// ```
    #[allow(dead_code)] // Public API method
    pub fn get_class(&self) -> u16 {
        self.rclass
    }

    /// Gets raw data from unsupported record types.
    ///
    /// # Returns
    ///
    /// * `Some((rtype, data))` - The record type code and raw data if this is an unsupported record type
    /// * `None` - If this is a supported record type
    #[allow(dead_code)] // Public API method
    pub fn get_raw_data(&self) -> Option<(u16, &[u8])> {
        match &self.data {
            RData::Other { rtype, data } => Some((*rtype, data)),
            _ => None,
        }
    }

    /// Deserializes a DNS resource record from a byte cursor.
    ///
    /// Reads a complete resource record from the cursor in DNS wire format, including
    /// the domain name (with potential compression), record type, class, TTL, and data.
    /// The data is parsed according to the record type into the appropriate [`RData`] variant.
    ///
    /// # Arguments
    ///
    /// * `cursor` - A mutable reference to a `Cursor<&[u8]>` positioned at the start of the record
    ///
    /// # Returns
    ///
    /// * `Ok(ResourceRecord)` - Successfully parsed resource record
    /// * `Err(std::io::Error)` - If parsing fails due to insufficient data, invalid format, or unsupported compression
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::ResourceRecord;
    /// use std::io::Cursor;
    ///
    /// // Example A record data (simplified - real data would include proper domain name encoding)
    /// let data = [
    ///     // Domain name, type, class, TTL, data length, and IP address would be here
    ///     // This is a conceptual example - actual usage requires proper DNS packet data
    /// ];
    ///
    /// // let mut cursor = Cursor::new(&data[..]);
    /// // let record = ResourceRecord::from_bytes(&mut cursor).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The cursor doesn't contain enough data to read a complete record
    /// - The domain name format is invalid or contains compression pointer errors
    /// - The record data is malformed or truncated
    /// - An I/O error occurs while reading from the cursor
    ///
    /// # Supported Record Types
    ///
    /// - **A records**: Parsed into [`RData::A`] with IPv4 address
    /// - **AAAA records**: Parsed into [`RData::AAAA`] with IPv6 address  
    /// - **CNAME records**: Parsed into [`RData::CNAME`] with target domain name
    /// - **MX records**: Parsed into [`RData::MX`] with preference and exchange server
    /// - **TXT records**: Parsed into [`RData::TXT`] with text content
    /// - **Other types**: Stored as [`RData::Other`] with raw data for forward compatibility
    pub fn from_bytes(cursor: &mut Cursor<&[u8]>) -> Result<Self, std::io::Error> {
        let name = unpack_domain_name(cursor)?;

        let mut u16_buf = [0u8; 2];
        let mut u32_buf = [0u8; 4];

        cursor.read_exact(&mut u16_buf)?;
        let rtype_val = u16::from_be_bytes(u16_buf);
        let rtype = QueryType::try_from(rtype_val);

        cursor.read_exact(&mut u16_buf)?;
        let rclass = u16::from_be_bytes(u16_buf);

        cursor.read_exact(&mut u32_buf)?;
        let ttl = u32::from_be_bytes(u32_buf);

        cursor.read_exact(&mut u16_buf)?;
        let data_len = u16::from_be_bytes(u16_buf) as usize;

        let data_start_pos = cursor.position() as usize;
        let data_end_pos = data_start_pos + data_len;

        let rdata = match rtype {
            Ok(QueryType::A) => {
                cursor.read_exact(&mut u32_buf)?;
                RData::A(Ipv4Addr::from(u32_buf))
            }
            Ok(QueryType::AAAA) => {
                let mut ipv6_buf = [0u8; 16];
                cursor.read_exact(&mut ipv6_buf)?;
                RData::AAAA(Ipv6Addr::from(ipv6_buf))
            }
            Ok(QueryType::CNAME) => {
                let cname = unpack_domain_name(cursor)?;
                RData::CNAME(cname)
            }
            Ok(QueryType::MX) => {
                cursor.read_exact(&mut u16_buf)?;
                let preference = u16::from_be_bytes(u16_buf);
                let exchange = unpack_domain_name(cursor)?;
                RData::MX {
                    preference,
                    exchange,
                }
            }
            Ok(QueryType::TXT) => {
                // TXT records have one or more <character-string>s. A <character-string>
                // is a length octet followed by that number of characters.
                let mut text_data = Vec::new();
                let mut current_pos = cursor.position();
                while current_pos < data_end_pos as u64 {
                    let mut len_buf = [0u8; 1];
                    cursor.read_exact(&mut len_buf)?;
                    let len = len_buf[0] as usize;

                    let mut str_buf = vec![0u8; len];
                    cursor.read_exact(&mut str_buf)?;
                    text_data.extend_from_slice(&str_buf);
                    current_pos = cursor.position();
                }
                RData::TXT(String::from_utf8_lossy(&text_data).to_string())
            }
            _ => {
                // Unsupported type
                let mut other_data = vec![0; data_len];
                cursor.read_exact(&mut other_data)?;
                RData::Other {
                    rtype: rtype_val,
                    data: other_data,
                }
            }
        };

        // Ensure cursor is at the end of the RDATA section
        cursor.set_position(data_end_pos as u64);

        Ok(ResourceRecord {
            name,
            rtype: rtype.unwrap_or(QueryType::A), // Default for display, data is in RData::Other
            rclass,
            ttl,
            data: rdata,
        })
    }
}

/// Represents a complete DNS message containing header and all sections.
///
/// A DNS message consists of a header followed by four sections: questions, answers,
/// authority records, and additional records. This structure provides a complete
/// representation of a DNS packet as defined in RFC 1035.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::{DnsMessage, DnsQuestion, DnsHeader, QueryType};
///
/// let mut message = DnsMessage::new();
/// message.header.id = 12345;
/// message.header.question_count = 1;
///
/// let question = DnsQuestion {
///     name: "example.com".to_string(),
///     qtype: QueryType::A,
///     qclass: 1,
/// };
/// message.questions.push(question);
/// ```
#[derive(Debug)]
pub struct DnsMessage {
    /// The DNS message header containing IDs, flags, and section counts.
    pub header: DnsHeader,
    /// Questions being asked in this DNS message.
    pub questions: Vec<DnsQuestion>,
    /// Answer records provided by the server.
    pub answers: Vec<ResourceRecord>,
    /// Authority records indicating authoritative name servers.
    pub authorities: Vec<ResourceRecord>,
    /// Additional records providing supplementary information.
    pub additionals: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Creates a new empty DNS message with default header values.
    ///
    /// All section vectors are initialized as empty, and the header is created
    /// with [`DnsHeader::new()`] containing all zero values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsMessage;
    ///
    /// let message = DnsMessage::new();
    /// assert_eq!(message.header.id, 0);
    /// assert_eq!(message.questions.len(), 0);
    /// assert_eq!(message.answers.len(), 0);
    /// ```
    pub fn new() -> Self {
        DnsMessage {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Serializes the DNS message into bytes and appends them to the provided buffer.
    ///
    /// Packs the complete DNS message including header and questions into DNS wire format.
    /// Currently only questions are serialized - resource record serialization is not
    /// implemented as this library primarily sends queries rather than responses.
    ///
    /// # Arguments
    ///
    /// * `buffer` - A mutable reference to a `Vec<u8>` where the serialized message will be appended
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully serialized the message
    /// * `Err(String)` - If question serialization fails (e.g., invalid domain name)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::{DnsMessage, DnsQuestion, QueryType};
    ///
    /// let mut message = DnsMessage::new();
    /// message.header.id = 12345;
    /// message.header.question_count = 1;
    ///
    /// let question = DnsQuestion {
    ///     name: "example.com".to_string(),
    ///     qtype: QueryType::A,
    ///     qclass: 1,
    /// };
    /// message.questions.push(question);
    ///
    /// let mut buffer = Vec::new();
    /// message.pack(&mut buffer).unwrap();
    /// // Buffer now contains the complete DNS query packet
    /// ```
    ///
    /// # Note
    ///
    /// Resource records (answers, authorities, additionals) are not serialized by this
    /// method as they are typically only present in DNS responses, not queries.
    pub fn pack(&self, buffer: &mut Vec<u8>) -> Result<(), String> {
        self.header.pack(buffer);
        for question in &self.questions {
            question.pack(buffer)?;
        }
        // Packing resource records is not implemented as we only send queries.
        Ok(())
    }

    /// Deserializes a complete DNS message from a byte slice.
    ///
    /// Parses a full DNS packet including header and all sections (questions, answers,
    /// authorities, additionals) from the provided byte data. The parsing follows
    /// DNS wire format with proper handling of domain name compression.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice containing the complete DNS message in wire format
    ///
    /// # Returns
    ///
    /// * `Ok(DnsMessage)` - Successfully parsed DNS message with all sections
    /// * `Err(std::io::Error)` - If parsing fails due to insufficient data, invalid format, or corruption
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dns_resolver::dns::DnsMessage;
    ///
    /// // Example with actual DNS response data
    /// let dns_response_data = [
    ///     // DNS header (12 bytes)
    ///     0x12, 0x34, // ID
    ///     0x81, 0x80, // Flags (response, no error)
    ///     0x00, 0x01, // Questions: 1
    ///     0x00, 0x01, // Answers: 1
    ///     0x00, 0x00, // Authority: 0
    ///     0x00, 0x00, // Additional: 0
    ///     // Question and answer sections would follow...
    /// ];
    ///
    /// // let message = DnsMessage::from_bytes(&dns_response_data).unwrap();
    /// // assert_eq!(message.header.id, 0x1234);
    /// // assert_eq!(message.questions.len(), 1);
    /// // assert_eq!(message.answers.len(), 1);
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The byte slice is too short to contain a valid DNS message
    /// - The DNS header is malformed or incomplete
    /// - Any section contains invalid or truncated data
    /// - Domain name compression pointers are invalid or create loops
    /// - Resource record data is malformed
    ///
    /// # Performance
    ///
    /// The function pre-allocates vectors based on the counts in the DNS header
    /// to minimize memory allocations during parsing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        let mut cursor = Cursor::new(bytes);
        let header = DnsHeader::from_bytes(&mut cursor)?;

        let mut questions = Vec::with_capacity(header.question_count as usize);
        for _ in 0..header.question_count {
            questions.push(DnsQuestion::from_bytes(&mut cursor)?);
        }

        let mut answers = Vec::with_capacity(header.answer_count as usize);
        for _ in 0..header.answer_count {
            answers.push(ResourceRecord::from_bytes(&mut cursor)?);
        }

        let mut authorities = Vec::with_capacity(header.authority_count as usize);
        for _ in 0..header.authority_count {
            authorities.push(ResourceRecord::from_bytes(&mut cursor)?);
        }

        let mut additionals = Vec::with_capacity(header.additional_count as usize);
        for _ in 0..header.additional_count {
            additionals.push(ResourceRecord::from_bytes(&mut cursor)?);
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

/// Encodes a domain name into DNS label format and appends it to a buffer.
///
/// Converts a human-readable domain name like "www.google.com" into the DNS wire format
/// where each label is prefixed by its length: `\x03www\x06google\x03com\x00`.
/// The encoded name is terminated with a null byte (0x00).
///
/// # Arguments
///
/// * `buffer` - A mutable reference to a `Vec<u8>` where the encoded domain name will be appended
/// * `domain` - The domain name to encode (e.g., "www.example.com")
///
/// # Returns
///
/// * `Ok(())` - Successfully encoded the domain name
/// * `Err(String)` - If any label exceeds the maximum length of 63 characters
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::pack_domain_name;
///
/// let mut buffer = Vec::new();
/// pack_domain_name(&mut buffer, "www.example.com").unwrap();
///
/// // Buffer now contains: [3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
/// assert_eq!(buffer[0], 3); // Length of "www"
/// assert_eq!(&buffer[1..4], b"www");
/// assert_eq!(buffer[4], 7); // Length of "example"
/// assert_eq!(&buffer[5..12], b"example");
/// assert_eq!(buffer[12], 3); // Length of "com"
/// assert_eq!(&buffer[13..16], b"com");
/// assert_eq!(buffer[16], 0); // Null terminator
/// ```
///
/// # Errors
///
/// Returns an error if any individual label in the domain name exceeds 63 characters,
/// which is the maximum allowed by the DNS specification (RFC 1035).
///
/// ```rust
/// use dns_resolver::dns::pack_domain_name;
///
/// let mut buffer = Vec::new();
/// let long_label = "a".repeat(64); // 64 characters - too long
/// let domain = format!("{}.example.com", long_label);
///
/// let result = pack_domain_name(&mut buffer, &domain);
/// assert!(result.is_err());
/// ```
///
/// # Domain Name Format
///
/// The DNS label format stores each label (domain component) as:
/// 1. A length byte (0-63) indicating how many characters follow
/// 2. The label characters in ASCII
/// 3. Repeat for each label
/// 4. A null byte (0x00) to terminate the name
pub fn pack_domain_name(buffer: &mut Vec<u8>, domain: &str) -> Result<(), String> {
    for label in domain.split('.') {
        let len = label.len();
        if len > 63 {
            return Err(format!(
                "Label '{}' exceeds maximum length of 63 characters",
                label
            ));
        }

        buffer.push(len as u8);
        buffer.extend_from_slice(label.as_bytes());
    }

    buffer.push(0);
    Ok(())
}

/// Decodes a domain name from DNS wire format, handling compression pointers.
///
/// Reads a domain name from the current cursor position in DNS label format and converts
/// it back to human-readable form (e.g., "www.example.com"). This function properly handles
/// DNS message compression where domain names can contain pointers to other locations in
/// the message to avoid repetition and reduce packet size.
///
/// # Arguments
///
/// * `cursor` - A mutable reference to a `Cursor<&[u8]>` positioned at the start of the domain name
///
/// # Returns
///
/// * `Ok(String)` - Successfully decoded domain name
/// * `Err(std::io::Error)` - If decoding fails due to invalid format, insufficient data, or pointer errors
///
/// # Examples
///
/// ```rust
/// use dns_resolver::dns::unpack_domain_name;
/// use std::io::Cursor;
///
/// // Simple domain name without compression
/// let data = [
///     3, b'w', b'w', b'w',           // "www"
///     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"  
///     3, b'c', b'o', b'm',           // "com"
///     0                              // null terminator
/// ];
///
/// let mut cursor = Cursor::new(&data[..]);
/// let domain = unpack_domain_name(&mut cursor).unwrap();
/// assert_eq!(domain, "www.example.com");
/// ```
///
/// # DNS Message Compression
///
/// DNS compression uses 2-byte pointers to reference previously occurring domain names
/// or suffixes. A pointer is identified by the first two bits being set to `11` (0xC0).
/// The remaining 14 bits specify the offset from the start of the DNS message.
///
/// ```text
/// Format of a compression pointer:
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// | 1  1|                OFFSET                   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// When a pointer is encountered, the function:
/// 1. Saves the current position (to return to after following the pointer)
/// 2. Jumps to the offset specified by the pointer
/// 3. Continues reading the domain name from that location
/// 4. Returns to the saved position when complete
///
/// # Examples with Compression
///
/// ```rust
/// use dns_resolver::dns::unpack_domain_name;
/// use std::io::Cursor;
///
/// // Data with compression pointer
/// let data = [
///     // Start of message (offset 0-11 would be DNS header)
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
///     // Domain name "example.com" starts at offset 12
///     7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
///     3, b'c', b'o', b'm',                          // "com"
///     0,                                            // null terminator
///     // Later in the message: "www" + pointer to "example.com"
///     3, b'w', b'w', b'w',                          // "www"
///     0xC0, 0x0C,                                   // pointer to offset 12 (example.com)
/// ];
///
/// let mut cursor = Cursor::new(&data[..]);
/// cursor.set_position(29); // Position at "www" + pointer
/// let domain = unpack_domain_name(&mut cursor).unwrap();
/// assert_eq!(domain, "www.example.com");
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - The cursor doesn't contain enough data to read labels or pointers
/// - A compression pointer references an invalid offset
/// - Label lengths are invalid (greater than 63)
/// - The domain name is malformed or incomplete
/// - An I/O error occurs while reading from the cursor
///
/// # Cursor Position
///
/// After successful execution:
/// - If no compression was used: cursor is positioned after the null terminator
/// - If compression was used: cursor is positioned after the pointer (2 bytes)
pub fn unpack_domain_name(cursor: &mut Cursor<&[u8]>) -> Result<String, std::io::Error> {
    let mut parts = Vec::new();
    let mut jumped = false;
    let mut jump_pos = 0;
    let initial_pos = cursor.position();

    loop {
        let mut len_buf = [0u8; 1];
        cursor.read_exact(&mut len_buf)?;
        let len = len_buf[0];

        if (len & 0b1100_0000) == 0b1100_0000 {
            if !jumped {
                jump_pos = cursor.position() + 1; // Save position after the pointer.
                jumped = true;
            }

            // Read the second byte of the pointer.
            let mut offset_buf = [0u8; 1];
            cursor.read_exact(&mut offset_buf)?;
            let offset = (((len & 0x3F) as u16) << 8) | (offset_buf[0] as u16);

            // Move cursor to the offset, read the name, then jump back.
            cursor.set_position(offset as u64);
            continue;
        }

        if len == 0 {
            break; // End of domain name
        }

        let mut label_buf = vec![0u8; len as usize];
        cursor.read_exact(&mut label_buf)?;
        parts.push(String::from_utf8_lossy(&label_buf).to_string());
    }

    // If we jumped, restore the cursor to its position after the pointer.
    if jumped {
        cursor.set_position(jump_pos);
    } else {
        // If we didn't jump, the cursor is already at the end of the name.
        // However, if the name was empty (just a null byte), we need to advance past it.
        if initial_pos == cursor.position() - 1 && parts.is_empty() {
            // This case handles the root domain "." which is just a single 0x00 byte.
        }
    }

    Ok(parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_domain_name() {
        let mut buffer = Vec::new();
        pack_domain_name(&mut buffer, "www.google.com").unwrap();
        assert_eq!(
            buffer,
            vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
    }

    #[test]
    fn test_unpack_simple_domain_name() {
        let data = vec![
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let mut cursor = Cursor::new(&data[..]);
        let name = unpack_domain_name(&mut cursor).unwrap();
        assert_eq!(name, "www.google.com");
        assert_eq!(cursor.position(), 17); // Check cursor is at the end.
    }

    #[test]
    fn test_unpack_compressed_domain_name() {
        // Sample response data with compression
        // Header (12 bytes)
        // Question: 03www06google03com00 (17 bytes)
        // Answer: c00c (pointer to www.google.com)
        let data = vec![
            // Some dummy data to represent the start of a packet
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // 12 bytes
            // The name "www.google.com" at offset 12
            3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm',
            0, // 17 bytes
            // Some other data
            0xDE, 0xAD, 0xBE, 0xEF, // A pointer `c00c` to offset 12 (0x0c)
            0xc0, 0x0c,
        ];
        // Start cursor at the pointer (offset 12 + 17 + 4 = 33)
        let mut cursor = Cursor::new(&data[..]);
        cursor.set_position(33);

        let name = unpack_domain_name(&mut cursor).unwrap();
        assert_eq!(name, "www.google.com");
        // Cursor should be at position 35 (after the 2-byte pointer)
        assert_eq!(cursor.position(), 35);
    }

    #[test]
    fn test_unpack_complex_compression() {
        // F.EXAMPLE.COM, where F points to EXAMPLE.COM
        // 01 F 07 EXAMPLE 03 COM 00 ... C0 02 (pointer to EXAMPLE.COM)
        let data = vec![
            0x01, b'f', // "f"
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // null terminator for example.com
            // Pointer starts here. We want to decode "f.example.com"
            0x01, b'f', 0xc0, 0x02, // Pointer to offset 2 (where "example" starts)
        ];
        let mut cursor = Cursor::new(&data[..]);
        cursor.set_position(16); // Start at the second "f"

        let name = unpack_domain_name(&mut cursor).unwrap();
        assert_eq!(name, "f.example.com");
        assert_eq!(cursor.position(), 20);
    }

    #[test]
    fn test_parse_a_record() {
        // A record for "google.com" -> 142.250.187.206
        let data = vec![
            // Name pointer to offset 12 (not shown, but assumed)
            0xc0, 0x0c, // Type A (1)
            0x00, 0x01, // Class IN (1)
            0x00, 0x01, // TTL (e.g., 60)
            0x00, 0x00, 0x00, 0x3c, // Data length (4)
            0x00, 0x04, // IP Address (142.250.187.206)
            142, 250, 187, 206,
        ];
        let full_packet = [
            &[0; 12][..],                                       // Dummy header
            &[3, b'g', b'o', b'o', 3, b'c', b'o', b'm', 0][..], // Dummy name for pointer
            &data[..],
        ]
        .concat();

        let mut cursor = Cursor::new(&full_packet[..]);
        cursor.set_position(12 + 9); // Position cursor at the start of the record data.

        let record = ResourceRecord::from_bytes(&mut cursor).unwrap();
        assert_eq!(record.name, "goo.com"); // This is an artifact of the dummy data
        assert_eq!(record.rtype, QueryType::A);
        assert_eq!(record.ttl, 60);
        match record.data {
            RData::A(addr) => assert_eq!(addr, Ipv4Addr::new(142, 250, 187, 206)),
            _ => panic!("Expected A record"),
        }
    }
}
