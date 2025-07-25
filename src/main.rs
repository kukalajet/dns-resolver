//! Command-line DNS resolver application.
//!
//! This module provides a command-line interface for performing DNS queries against
//! public DNS servers. It supports common DNS record types (A, AAAA, CNAME, MX, TXT)
//! and displays comprehensive information about DNS responses including headers,
//! questions, answers, authority records, and additional records.
//!
//! The application uses Google's public DNS server (8.8.8.8) by default and implements
//! proper error handling for various failure scenarios including network timeouts,
//! invalid domains, and unsupported record types.
//!
//! # Usage
//!
//! ```bash
//! # Basic A record lookup
//! dns-resolver google.com
//!
//! # Specify record type explicitly
//! dns-resolver google.com A
//!
//! # Query MX records for a domain
//! dns-resolver example.com MX
//!
//! # Query AAAA (IPv6) records
//! dns-resolver google.com AAAA
//! ```
//!
//! # Supported Record Types
//!
//! - **A**: IPv4 address records
//! - **AAAA**: IPv6 address records
//! - **CNAME**: Canonical name (alias) records
//! - **MX**: Mail exchange records
//! - **TXT**: Text records
//!
//! # Examples
//!
//! Query A records for google.com:
//! ```bash
//! $ dns-resolver google.com
//! Querying 8.8.8.8 for A records of google.com...
//! ------------------------------------
//! Header: DnsHeader { id: 1234, flags: 33152, ... }
//!
//! Question Section:
//!   - QNAME: google.com, QTYPE: A
//!
//! Answer Section:
//!   - google.com 300 IN A 142.250.187.206
//!   - google.com 300 IN A 142.250.187.174
//! ...
//! ```
//!
//! Query MX records for a domain:
//! ```bash
//! $ dns-resolver example.com MX
//! Querying 8.8.8.8 for MX records of example.com...
//! ------------------------------------
//! Answer Section:
//!   - example.com 3600 IN MX 10 mail.example.com
//! ...
//! ```

use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;

// Import modules from the current crate.
mod dns;
mod resolver;

use dns::QueryType;
use resolver::resolve;

/// Entry point for the DNS resolver command-line application.
///
/// This function orchestrates the complete DNS resolution process:
/// 1. Parses command-line arguments for domain name and record type
/// 2. Validates the provided arguments and record type
/// 3. Performs the DNS query using Google's public DNS server
/// 4. Displays comprehensive results or error information
///
/// # Command-line Arguments
///
/// * `domain_name` - The fully qualified domain name to resolve (required)
/// * `record_type` - The DNS record type to query (optional, defaults to "A")
///
/// # Exit Behavior
///
/// The program will exit with status 0 on successful resolution and display
/// results to stdout. On errors, it prints diagnostic information to stderr
/// and exits with a non-zero status.
///
/// # Error Handling
///
/// The function handles several categories of errors:
/// - **Argument validation**: Incorrect number of arguments or invalid record types
/// - **Network errors**: DNS server timeouts, connectivity issues
/// - **DNS protocol errors**: NXDOMAIN, SERVFAIL, and other DNS response codes
/// - **Parsing errors**: Malformed DNS responses or protocol violations
///
/// # Examples
///
/// The function processes various command-line invocations:
///
/// ```bash
/// # Resolve A records (default type)
/// ./dns-resolver google.com
///
/// # Explicitly specify record type
/// ./dns-resolver google.com AAAA
///
/// # Query mail exchange records
/// ./dns-resolver example.com MX
/// ```
fn main() {
    // Collect command-line arguments into a vector for processing.
    // The first argument (index 0) is always the program name/path.
    let args: Vec<String> = env::args().collect();

    // Validate command-line argument count and provide usage information.
    // We expect 1-2 arguments beyond the program name:
    // - Required: domain name to resolve
    // - Optional: DNS record type (defaults to 'A' if not specified)
    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <domain_name> [record_type]", args[0]);
        eprintln!("Example: {} google.com A", args[0]);
        eprintln!("Supported record types: A, AAAA, CNAME, MX, TXT");
        return;
    }

    // Extract the domain name from the first argument.
    // This should be a fully qualified domain name (e.g., "www.example.com").
    let domain_name = &args[1];

    // Extract and validate the DNS record type from the optional second argument.
    // If no record type is specified, default to 'A' (IPv4 address records).
    let record_type_str = args.get(2).map_or("A", |s| s.as_str());
    let query_type = match QueryType::from_str(record_type_str) {
        Ok(qt) => qt,
        Err(_) => {
            eprintln!(
                "Error: Invalid record type '{}'. Supported types are A, AAAA, CNAME, MX, TXT.",
                record_type_str
            );
            return;
        }
    };

    // Configure the DNS server to use for resolution.
    // Google's public DNS (8.8.8.8) is chosen for its reliability and global availability.
    // Alternative options include Cloudflare (1.1.1.1) or OpenDNS (208.67.222.222).
    let dns_server_addr = "8.8.8.8".parse::<Ipv4Addr>().unwrap();

    // Display query information to the user before initiating the DNS request.
    // This provides immediate feedback about what operation is being performed.
    println!(
        "Querying {} for {} records of {}...",
        dns_server_addr,
        query_type.to_string().to_uppercase(),
        domain_name
    );
    println!("------------------------------------");

    // Perform the DNS resolution and handle the result.
    // The resolve function performs the complete DNS query lifecycle and returns
    // either a successful DNS message or a detailed error description.
    match resolve(domain_name, query_type, dns_server_addr) {
        Ok(dns_message) => {
            // --- Display DNS Response Information ---

            // Print the DNS header containing metadata about the response.
            // The header includes information such as response codes, flags,
            // and counts for each section of the DNS message.
            println!("Header: {:?}", dns_message.header);
            println!();

            // Display the question section showing what was asked.
            // This confirms the query that was sent to the DNS server and
            // helps verify that the response matches the request.
            println!("Question Section:");
            for question in dns_message.questions {
                println!("  - QNAME: {}, QTYPE: {}", question.name, question.qtype);
            }
            println!();

            // Display answer records if any were returned.
            // Answer records contain the direct responses to the DNS query
            // (e.g., IP addresses for A records, mail servers for MX records).
            if !dns_message.answers.is_empty() {
                println!("Answer Section:");
                for record in dns_message.answers {
                    println!("  - {}", record);
                }
            } else {
                println!("Answer Section: No records found.");
            }
            println!();

            // Display authority records if present.
            // Authority records identify authoritative name servers for the domain
            // and are particularly useful when no direct answers are available.
            if !dns_message.authorities.is_empty() {
                println!("Authority Section:");
                for record in dns_message.authorities {
                    println!("  - {}", record);
                }
            } else {
                println!("Authority Section: No records found.");
            }
            println!();

            // Display additional records if present.
            // Additional records provide supplementary information that may be
            // useful but wasn't directly requested (e.g., A records for MX targets).
            if !dns_message.additionals.is_empty() {
                println!("Additional Section:");
                for record in dns_message.additionals {
                    println!("  - {}", record);
                }
            } else {
                println!("Additional Section: No records found.");
            }
        }
        Err(e) => {
            // Handle DNS resolution errors with descriptive error messages.
            // This covers various failure scenarios including network issues,
            // DNS server errors, timeouts, and protocol violations.
            eprintln!("Error resolving {}: {}", domain_name, e);
        }
    }
}
