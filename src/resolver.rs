//! DNS resolver implementation.
//!
//! This module provides a complete DNS resolver client that can query DNS servers
//! and parse responses according to RFC 1035. It handles the full DNS query lifecycle:
//! building queries, sending them over UDP, receiving responses, and parsing the
//! returned DNS messages.
//!
//! The resolver supports standard DNS query types (A, AAAA, CNAME, MX, TXT) and
//! provides comprehensive error handling for network issues, timeouts, and DNS
//! protocol errors.
//!
//! # Examples
//!
//! Basic DNS resolution:
//!
//! ```rust
//! use dns_resolver::resolver::resolve;
//! use dns_resolver::dns::QueryType;
//! use std::net::Ipv4Addr;
//!
//! // Resolve A record for google.com using Google's DNS server
//! let result = resolve("google.com", QueryType::A, Ipv4Addr::new(8, 8, 8, 8));
//! match result {
//!     Ok(response) => {
//!         println!("Resolved successfully: {} answers", response.answers.len());
//!         for answer in &response.answers {
//!             println!("Answer: {:?}", answer);
//!         }
//!     }
//!     Err(e) => eprintln!("Resolution failed: {}", e),
//! }
//! ```
//!
//! # Network Configuration
//!
//! The resolver uses UDP on port 53 (the standard DNS port) and sets a 5-second
//! timeout for queries. It binds to a random local port chosen by the operating system.
//!
//! # Error Handling
//!
//! The resolver provides detailed error information through the [`DnsError`] enum,
//! which covers I/O errors, timeouts, malformed responses, and DNS server errors.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use crate::dns::{DnsMessage, DnsQuestion, QueryType, ResponseCode};

/// Errors that can occur during DNS resolution.
///
/// This enum represents all possible error conditions that may arise during
/// the DNS resolution process, from network issues to protocol violations.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::resolver::DnsError;
/// use std::io;
///
/// // Converting from std::io::Error
/// let io_error = io::Error::new(io::ErrorKind::ConnectionRefused, "Connection refused");
/// let dns_error = DnsError::from(io_error);
/// println!("DNS error: {}", dns_error);
/// ```
#[derive(Debug)]
pub enum DnsError {
    /// An I/O error occurred during network communication.
    ///
    /// This wraps standard I/O errors such as connection failures,
    /// permission denied, or other socket-related issues.
    Io(std::io::Error),

    /// The DNS query timed out.
    ///
    /// This occurs when no response is received within the configured
    /// timeout period (currently 5 seconds).
    Timeout,

    /// The DNS response was malformed or could not be parsed.
    ///
    /// This indicates a protocol violation or corrupted data in the
    /// DNS response message. The string contains details about what
    /// went wrong during parsing.
    InvalidResponse(String),

    /// The DNS server returned an error response code.
    ///
    /// This occurs when the DNS server successfully processed the query
    /// but returned an error condition such as NXDOMAIN (domain not found),
    /// SERVFAIL (server failure), or other DNS error codes.
    ServerReturnedError(ResponseCode),
}

/// Enables `DnsError` to be used with the standard error handling infrastructure.
///
/// This implementation allows `DnsError` to be used with the `?` operator and
/// other error handling mechanisms provided by the standard library.
impl std::error::Error for DnsError {}

/// Provides human-readable error messages for `DnsError`.
///
/// This implementation ensures that DNS errors can be displayed in a user-friendly
/// manner, with appropriate context for each error type.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::resolver::DnsError;
/// use dns_resolver::dns::ResponseCode;
///
/// let error = DnsError::Timeout;
/// println!("Error occurred: {}", error);
/// // Output: "Error occurred: Request timed out"
///
/// let server_error = DnsError::ServerReturnedError(ResponseCode::NameError);
/// println!("Server error: {}", server_error);
/// // Output: "Server error: DNS server returned an error: NameError"
/// ```
impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::Io(e) => write!(f, "I/O error: {}", e),
            DnsError::Timeout => write!(f, "Request timed out"),
            DnsError::InvalidResponse(msg) => write!(f, "Invalid DNS response: {}", msg),
            DnsError::ServerReturnedError(code) => {
                write!(f, "DNS server returned an error: {:?}", code)
            }
        }
    }
}

/// Enables automatic conversion from standard I/O errors to `DnsError`.
///
/// This conversion allows the `?` operator to be used with functions that
/// return `std::io::Error`, automatically wrapping them in `DnsError::Io`.
///
/// # Examples
///
/// ```rust
/// use dns_resolver::resolver::DnsError;
/// use std::io;
///
/// fn network_operation() -> Result<(), DnsError> {
///     // This I/O error will be automatically converted to DnsError::Io
///     std::fs::File::open("/nonexistent/file")?;
///     Ok(())
/// }
/// ```
impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Io(e)
    }
}

/// Performs a DNS query for the specified domain and record type.
///
/// This function implements a complete DNS resolution process by:
/// 1. Creating a UDP socket and connecting to the specified DNS server
/// 2. Building a properly formatted DNS query message
/// 3. Sending the query over the network
/// 4. Receiving and parsing the DNS response
/// 5. Validating the response and extracting the results
///
/// The function uses a 5-second timeout to prevent indefinite blocking and
/// provides detailed error information for troubleshooting failed queries.
///
/// # Arguments
///
/// * `domain_name` - The fully qualified domain name to resolve (e.g., "www.example.com").
///   Should not include a trailing dot, as this will be handled internally.
/// * `query_type` - The type of DNS record to request. Common types include:
///   - [`QueryType::A`] for IPv4 addresses
///   - [`QueryType::AAAA`] for IPv6 addresses  
///   - [`QueryType::CNAME`] for canonical name records
///   - [`QueryType::MX`] for mail exchange records
///   - [`QueryType::TXT`] for text records
/// * `dns_server_addr` - The IPv4 address of the DNS server to query.
///   Common public DNS servers include:
///   - `8.8.8.8` (Google)
///   - `1.1.1.1` (Cloudflare)
///   - `208.67.222.222` (OpenDNS)
///
/// # Returns
///
/// Returns a `Result` containing:
/// - `Ok(DnsMessage)` - A successfully parsed DNS response message containing
///   the query results in the `answers`, `authority`, and `additional` sections
/// - `Err(DnsError)` - An error describing what went wrong during resolution
///
/// # Errors
///
/// This function can return several types of errors:
///
/// - [`DnsError::Io`] - Network connectivity issues, permission problems, or
///   other socket-related errors
/// - [`DnsError::Timeout`] - No response received within 5 seconds
/// - [`DnsError::InvalidResponse`] - Malformed or unparseable DNS response
/// - [`DnsError::ServerReturnedError`] - DNS server returned an error code such as:
///   - `NXDOMAIN` - Domain name does not exist
///   - `SERVFAIL` - Server failure or temporary error
///   - `REFUSED` - Server refused to process the query
///
/// # Examples
///
/// ## Basic A record lookup
///
/// ```rust
/// use dns_resolver::resolver::resolve;
/// use dns_resolver::dns::QueryType;
/// use std::net::Ipv4Addr;
///
/// let response = resolve(
///     "google.com",
///     QueryType::A,
///     Ipv4Addr::new(8, 8, 8, 8)
/// )?;
///
/// println!("Resolved {} A records", response.answers.len());
/// for answer in &response.answers {
///     if let Some(ip) = answer.get_ipv4_address() {
///         println!("IP address: {}", ip);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## MX record lookup
///
/// ```rust
/// use dns_resolver::resolver::resolve;
/// use dns_resolver::dns::QueryType;
/// use std::net::Ipv4Addr;
///
/// let response = resolve(
///     "example.com",
///     QueryType::MX,
///     Ipv4Addr::new(1, 1, 1, 1)
/// )?;
///
/// for answer in &response.answers {
///     if let Some(mx_data) = answer.get_mx_data() {
///         println!("Mail server: {} (priority: {})", mx_data.exchange, mx_data.preference);
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Error handling
///
/// ```rust
/// use dns_resolver::resolver::{resolve, DnsError};
/// use dns_resolver::dns::QueryType;
/// use std::net::Ipv4Addr;
///
/// match resolve("nonexistent.invalid", QueryType::A, Ipv4Addr::new(8, 8, 8, 8)) {
///     Ok(response) => println!("Unexpected success: {} answers", response.answers.len()),
///     Err(DnsError::ServerReturnedError(code)) => {
///         println!("DNS server error: {:?}", code);
///     }
///     Err(DnsError::Timeout) => {
///         println!("Query timed out - server may be unreachable");
///     }
///     Err(e) => {
///         println!("Other error: {}", e);
///     }
/// }
/// ```
///
/// # Network Requirements
///
/// This function requires:
/// - UDP network connectivity to the specified DNS server on port 53
/// - Ability to bind to a local UDP socket (ephemeral port)
/// - No firewall restrictions blocking DNS queries
///
/// # Protocol Compliance
///
/// The implementation follows RFC 1035 standards for DNS message format and
/// query processing. It sets the Recursion Desired (RD) flag to request
/// recursive resolution from the target DNS server.
pub fn resolve(
    domain_name: &str,
    query_type: QueryType,
    dns_server_addr: Ipv4Addr,
) -> Result<DnsMessage, DnsError> {
    // The DNS server port is standardized to 53 per RFC 1035.
    let server_address = (dns_server_addr, 53);

    // Bind a UDP socket to an available local port.
    // Using "0.0.0.0:0" allows the OS to choose an appropriate interface and ephemeral port.
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // Set a read timeout to prevent indefinite blocking on unresponsive servers.
    // 5 seconds provides a reasonable balance between responsiveness and reliability.
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // --- Build the DNS Query Message ---
    let mut message = DnsMessage::new();

    // Configure the header for a standard recursive query:
    // - Use a fixed ID for request/response matching (production code should use random IDs)
    // - Set flags to 0x0100 (standard query with Recursion Desired bit set)
    // - Set question count to 1 since we're asking one question
    message.header.id = 1234; // TODO: Use a random ID for production security
    message.header.flags = 0x0100; // Standard query (RD=1, recursion desired)
    message.header.question_count = 1;

    // Create the question section of the DNS message.
    // This specifies what we're asking for: domain name, record type, and class (Internet).
    message.questions.push(DnsQuestion {
        name: domain_name.to_string(),
        qtype: query_type,
        qclass: 1, // IN (Internet) class - the most common DNS class
    });

    // Serialize the DNS message into the wire format (binary representation).
    // This converts our structured data into the byte format expected by DNS servers.
    let mut query_buffer = Vec::new();
    message
        .pack(&mut query_buffer)
        .map_err(|e| DnsError::InvalidResponse(e.to_string()))?;

    // --- Send the Query Over UDP ---
    // --- Send the Query Over UDP ---
    // Transmit the serialized DNS query to the target server.
    socket.send_to(&query_buffer, server_address)?;

    // --- Receive the DNS Response ---
    // DNS messages are typically limited to 512 bytes over UDP (RFC 1035).
    // Larger responses use TCP or DNS extensions, but 512 bytes covers most use cases.
    let mut response_buffer = [0; 512];

    // Wait for the server's response, handling timeout and other I/O errors appropriately.
    let (size, _) = socket.recv_from(&mut response_buffer).map_err(|e| {
        // Convert specific I/O error types to more descriptive DNS errors.
        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut {
            DnsError::Timeout
        } else {
            DnsError::Io(e)
        }
    })?;

    // --- Parse the DNS Response Message ---
    // Deserialize the binary response back into a structured DnsMessage.
    // Only parse the actual response data (not the full buffer).
    let response_message = DnsMessage::from_bytes(&response_buffer[..size])
        .map_err(|e| DnsError::InvalidResponse(e.to_string()))?;

    // --- Validate the Response ---
    // Check if the DNS server encountered an error processing our query.
    // Even if we receive a response, it might contain an error code like NXDOMAIN.
    if response_message.header.get_response_code() != ResponseCode::NoError {
        return Err(DnsError::ServerReturnedError(
            response_message.header.get_response_code(),
        ));
    }

    // Return the successfully parsed and validated DNS response.
    // The caller can now examine the answers, authority, and additional sections.
    Ok(response_message)
}
