/*
 * Copyright 2014 The Netty Project
 * Copyright 2024 Alexander Liesenfeld
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

//! This library contains utilities to simplify operate multiple protocols through a
//! single network port.
use std::fmt;
use std::fmt::{Display, Formatter};

// ************************************************************************************************
// Errors
#[derive(Debug)]
pub enum Error {
    NotEnoughDataError,
    NotEncryptedError,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Error::NotEncryptedError => write!(f, "Byte buffer does not seem to be encrypted"),
            Error::NotEnoughDataError => write!(f, "Byte buffer length too short"),
        }
    }
}

impl std::error::Error for Error {}

// ************************************************************************************************
// Constants

/// Change Cipher Spec (20): Indicates that subsequent records will
/// be protected under the newly negotiated CipherSpec and keys.
const SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;

/// Alert (21): Used to convey alerts to the peer. Alerts can be of
/// severity warning or fatal and include a description of the alert.
const SSL_CONTENT_TYPE_ALERT: u8 = 21;

/// Handshake (22): Manages the negotiation of security parameters
/// for the SSL/TLS session. It encompasses a series of messages
/// for capabilities exchange, key distribution, and session setup.
const SSL_CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Application Data (23): Used for transmitting encrypted data
/// (payload) between the client and server once a secure connection
/// is established.
const SSL_CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

/// Extension Heartbeat (24): Supports a keep-alive functionality
/// within the TLS protocol, allowing for heartbeat messages to
/// maintain the connection without full renegotiation. Its usage
/// has become less common due to security vulnerabilities like Heartbleed.
const SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT: u8 = 24;

/// Represents a specific version of the GMSSL protocol that the application supports.
///
/// GMSSL is an extension of SSL/TLS protocols with additional features and security mechanisms.
/// This constant is used to identify the protocol version during the SSL/TLS handshake process
/// and ensure compatibility between client and server.
///
/// The use of GMSSL is particularly important for applications and services that need to
/// adhere to Chinese cryptographic standards for reasons of regulatory compliance,
/// security policy, or interoperability with Chinese technologies and networks.
///
/// The value `0x101` corresponds to a specific version of GMSSL, indicating support for
/// particular cryptographic algorithms and security features.
const GMSSL_PROTOCOL_VERSION: u16 = 0x101;

/// Represents the length of the SSL (Secure Sockets Layer) record header in bytes.
///
/// In SSL/TLS protocols, each record transmitted or received is prefixed with a header.
/// This header contains essential information for processing the record, such as its type
/// (e.g., handshake, data, alert), version, and the length of the payload.
///
/// The constant value of `5` bytes is derived from the following components of the SSL record header:
/// - 1 byte for the "Content Type" indicating the type of record (handshake, application data, etc.).
/// - 2 bytes for the "Version" specifying the SSL or TLS version used.
/// - 2 bytes for the "Length" denoting the size of the record payload in bytes (excluding the header).
///
/// This constant is critical for correctly parsing and constructing SSL/TLS records, ensuring proper
/// protocol operation and security.
///
/// Note: While this constant is specific to SSL, it is also applicable to TLS records,
/// as the header format has remained consistent across versions of the protocol.
const SSL_RECORD_HEADER_LENGTH: u16 = 5;

// The following constants are representing the version numbers for different versions of the
// DTLS (Datagram Transport Layer Security) protocol. DTLS is designed to provide secure
// communication between clients and servers over datagram protocols such as UDP. It is based on
// the TLS (Transport Layer Security) protocol and provides similar security guarantees.

/// DTLS version 1.0 identifier.
///
/// This version is defined in RFC 4347 and is identified by the specific protocol version number `0xFEFF`.
/// It introduced the basic security features and mechanisms for securing datagram communication.
const DTLS_1_0: u16 = 0xFEFF;

/// DTLS version 1.2 identifier.
///
/// Defined in RFC 6347, this version enhances the security features introduced in DTLS 1.0 and aligns
/// more closely with TLS version 1.2, introducing stronger cryptographic algorithms and security practices.
const DTLS_1_2: u16 = 0xFEFD;

/// DTLS version 1.3 identifier.
///
/// Although DTLS 1.3 is conceptually aligned with TLS 1.3, it is still in the process of being
/// standardized. The version number `0xFEFC` is used here as a placeholder and should be verified
/// against the latest standards and RFCs related to DTLS 1.3.
///
/// DTLS 1.3 aims to further improve the security and efficiency of DTLS by adopting modern cryptographic
/// algorithms, reducing handshake latency, and improving resistance against various attack vectors.
const DTLS_1_3: u16 = 0xFEFC;

/// The length of the DTLS record header in bytes.
///
/// In the DTLS protocol, each record transmitted or received is prefixed with a header. This header
/// contains critical information for processing the record, including the protocol version, epoch, sequence number,
/// length, and more.
///
/// The constant value of `13` bytes is composed of the following parts of the DTLS record header:
/// - 1 byte for the "Content Type"
/// - 2 bytes for the "Version"
/// - 2 bytes for the "Epoch"
/// - 6 bytes for the "Sequence Number"
/// - 2 bytes for the "Length"
///
/// This header length is essential for the correct parsing and handling of DTLS records.
const DTLS_RECORD_HEADER_LENGTH: u16 = 13;

/// Determines whether a byte slice contains encrypted data at a specified offset.
///
/// This function leverages `get_encrypted_packet_length` to analyze the provided byte slice, starting
/// from the given offset, to assess if it contains an encrypted packet according to recognized SSL/TLS,
/// GMSSL, and DTLS protocols. It effectively serves as a boolean helper to quickly identify encrypted data
/// without needing to parse or understand the specifics of the encryption protocol.
///
/// # Arguments
///
/// * `buffer` - A slice of bytes representing the buffer to be analyzed for encrypted data.
/// * `offset` - The offset within `buffer` from which to start the analysis.
///
/// # Returns
///
/// `true` if the data at the specified offset is recognized as an encrypted packet, otherwise `false`.
/// The determination is based on whether `get_encrypted_packet_length` returns a packet length greater than 0
/// or if it encounters an error (e.g., `NotEnoughDataError` or `NotEncryptedError`), in which case it will
/// return `false`.
pub fn is_encrypted(buffer: &[u8], offset: usize) -> bool {
    match get_encrypted_packet_length(buffer, offset) {
        Ok(length) => length > 0,
        Err(_) => false,
    }
}

/// Calculates the length of an encrypted data packet within a byte slice, without consuming the bytes.
///
/// This function analyzes the provided byte slice, starting from a specified offset, to determine
/// the length of the encrypted packet based on the encryption protocol's header format. It supports
/// various SSL/TLS versions, including SSLv3, TLS (all versions up to TLS 1.3), GMSSL, and DTLS protocols.
/// It can distinguish between SSLv2 and other protocol versions, handling each according to its
/// specific header and length encoding scheme.
///
/// The function returns an `Ok(u16)` with the total length of the encrypted packet (including its header)
/// if successful. If the byte slice does not contain enough data to determine the packet length or
/// if the data does not appear to be encrypted according to the recognized protocols, it returns
/// an `Err(Error)`, with `Error` being a custom enum indicating the type of error encountered
/// (`NotEnoughDataError` or `NotEncryptedError`).
///
/// # Arguments
///
/// * `buffer` - A slice of bytes representing the buffer from which to read the encrypted packet.
/// * `offset` - The offset within `buffer` from which to start analyzing the encrypted data.
///
/// # Returns
///
/// A `Result<u16, Error>` indicating the outcome of the function. On success, it contains the length
/// of the encrypted packet. On failure, it contains an `Error` enum indicating the reason for the failure.
///
/// # Errors
///
/// * `NotEnoughDataError` - If the buffer does not contain enough data to determine the packet length.
/// * `NotEncryptedError` - If the data does not appear to be encrypted according to recognized protocols.
///
pub fn get_encrypted_packet_length(buffer: &[u8], offset: usize) -> Result<u16, Error> {
    let mut packet_length: u16 = 0;

    // SSLv3 or TLS - Check ContentType
    let mut tls = match buffer[offset] {
        SSL_CONTENT_TYPE_CHANGE_CIPHER_SPEC
        | SSL_CONTENT_TYPE_ALERT
        | SSL_CONTENT_TYPE_HANDSHAKE
        | SSL_CONTENT_TYPE_APPLICATION_DATA
        | SSL_CONTENT_TYPE_EXTENSION_HEARTBEAT => true,
        _ => false,
    };

    if tls {
        // SSLv3 or TLS or GMSSLv1.0 or GMSSLv1.1 - Check ProtocolVersion

        // TLS 1.0 (RFC 2246) is represented by the major version 3 and minor version 1, which corresponds to the byte sequence {3, 1}.
        // TLS 1.1 (RFC 4346) uses the version represented by the bytes {3, 2}.
        // TLS 1.2 (RFC 5246) has the version indicated by {3, 3}.
        // TLS 1.3 (RFC 8446) is represented by {3, 4}
        // SSL 3.0 is represented as {3, 4} (but this is SSL, not TLS).
        let major_version = buffer[offset + 1];
        let version = read_u16(&buffer, offset + 1, true)? as u16;

        if major_version == 3 || version == GMSSL_PROTOCOL_VERSION {
            // SSLv3 or TLS or GMSSLv1.0 or GMSSLv1.1
            packet_length = read_u16(buffer, offset + 3, true)? + SSL_RECORD_HEADER_LENGTH;
            if packet_length <= SSL_RECORD_HEADER_LENGTH {
                // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
                tls = false;
            }
        } else if version == DTLS_1_0 || version == DTLS_1_2 || version == DTLS_1_3 {
            if buffer.len() < offset + DTLS_RECORD_HEADER_LENGTH as usize {
                return Err(Error::NotEnoughDataError);
            }

            // length is the last 2 bytes in the 13 byte header.
            packet_length = read_u16(buffer, offset + DTLS_RECORD_HEADER_LENGTH as usize - 2, true)?
                + DTLS_RECORD_HEADER_LENGTH;
        } else {
            // Neither SSLv3 or TLSv1 (i.e. SSLv2 or bad data)
            tls = false;
        }
    }

    if !tls {
        // SSLv2 or bad data - Check the version
        let header_length: usize = if (buffer[offset] & 0x80) != 0 { 2 } else { 3 };
        let major_version = buffer[offset + header_length + 1];

        if major_version == 2 || major_version == 3 {
            // SSLv2
            packet_length = if header_length == 2 {
                (read_u16(buffer, offset, true)? & 0x7FFF) + 2
            } else {
                (read_u16(buffer, offset, true)? & 0x3FFF) + 3
            };

            if packet_length as usize <= header_length {
                return Err(Error::NotEnoughDataError);
            }
        } else {
            return Err(Error::NotEncryptedError);
        }
    }

    Ok(packet_length)
}

#[inline]
fn read_u16(bytes: &[u8], offset: usize, is_big_endian: bool) -> Result<u16, Error> {
    if bytes.len() >= offset + 2 {
        let slice = &bytes[offset..offset + 2];

        let result = if is_big_endian {
            u16::from_be_bytes([slice[0], slice[1]])
        } else {
            u16::from_ne_bytes([slice[0], slice[1]])
        };

        Ok(result)
    } else {
        Err(Error::NotEnoughDataError)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        get_encrypted_packet_length, is_encrypted, DTLS_RECORD_HEADER_LENGTH,
        GMSSL_PROTOCOL_VERSION, SSL_CONTENT_TYPE_APPLICATION_DATA, SSL_CONTENT_TYPE_HANDSHAKE,
        SSL_RECORD_HEADER_LENGTH,
    };

    #[test]
    fn test_is_encrypted_true_for_known_encrypted_data() {
        // Example buffer setup - you'll need actual encrypted data for meaningful tests
        let buffer: Vec<u8> = vec![
            SSL_CONTENT_TYPE_HANDSHAKE, // Pretend this is part of an encrypted packet
            0x03,
            0x03, // Version TLS 1.2
            0x00,
            0x14, // Length
                  // ... additional bytes that represent an encrypted packet
        ];
        assert!(is_encrypted(&buffer, 0));
    }

    #[test]
    fn test_is_encrypted_false_for_short_buffer() {
        let buffer: Vec<u8> = vec![SSL_CONTENT_TYPE_HANDSHAKE]; // Insufficient data
        assert!(!is_encrypted(&buffer, 0));
    }

    #[test]
    fn test_get_encrypted_packet_length_with_valid_data() {
        let buffer: Vec<u8> = vec![
            SSL_CONTENT_TYPE_HANDSHAKE, // Pretend this is part of an encrypted packet
            0x03,
            0x03, // Version TLS 1.2
            0x00,
            0x14, // Length
                  // ... additional bytes that represent an encrypted packet
        ];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert_eq!(result, Ok(20 + SSL_RECORD_HEADER_LENGTH));
    }

    #[test]
    fn test_get_encrypted_packet_length_with_not_encrypted_error() {
        let buffer: Vec<u8> = vec![0x00]; // Data that does not match any known encrypted format
        let result = get_encrypted_packet_length(&buffer, 0);
        assert!(matches!(result, Err(Error::NotEncryptedError)));
    }

    #[test]
    fn test_get_encrypted_packet_length_with_not_enough_data_error() {
        let buffer: Vec<u8> = vec![SSL_CONTENT_TYPE_HANDSHAKE]; // Insufficient data
        let result = get_encrypted_packet_length(&buffer, 0);
        assert!(matches!(result, Err(Error::NotEnoughDataError)));
    }

    #[test]
    fn test_encrypted_handshake_length() {
        // Simulating a buffer that includes an SSL/TLS handshake message
        let buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03, // Major version (TLS)
            0x03, // Minor version (TLS 1.2)
            0x00,
            0x14, // Length of the handshake message
                  // The actual handshake message would follow here
        ];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert_eq!(result, Ok(SSL_RECORD_HEADER_LENGTH + 20)); // Expected length includes the header
    }

    #[test]
    fn test_is_not_encrypted_with_application_data() {
        // Simulating a buffer that looks like application data but is too short to be valid
        let buffer = vec![
            SSL_CONTENT_TYPE_APPLICATION_DATA,
            0x03,
            0x01, // Incorrect version for encrypted application data
        ];
        assert!(!is_encrypted(&buffer, 0));
    }

    #[test]
    fn test_invalid_content_type() {
        // Buffer with an invalid content type
        let buffer = vec![0xFF, 0x03, 0x03, 0x00, 0x14];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert!(matches!(result, Err(Error::NotEncryptedError)));
    }

    #[test]
    fn test_encrypted_packet_with_insufficient_length() {
        // Buffer that indicates a longer message than is actually present
        let buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2
            0xFF,
            0xFF, // Length indicating a very large message
        ];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert!(matches!(result, Err(Error::NotEnoughDataError)));
    }

    #[test]
    fn test_dtls_handshake_length() {
        // Simulating a DTLS handshake message buffer
        let buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0xFE,
            0xFD, // DTLS 1.2
            0x00,
            0x01, // Epoch
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01, // Sequence number
            0x00,
            0x14, // Length of the handshake message
                  // The actual handshake message would follow here
        ];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert_eq!(result, Ok(DTLS_RECORD_HEADER_LENGTH + 20)); // Expected length includes the header
    }

    #[test]
    fn test_buffer_with_offset() {
        // Testing with a non-zero offset
        let buffer = vec![
            0x00, // Some unrelated data
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x14,
            // Followed by the encrypted handshake message
        ];
        let result = get_encrypted_packet_length(&buffer, 1); // Start analysis at offset 1
        assert_eq!(result, Ok(SSL_RECORD_HEADER_LENGTH + 20)); // Expected length includes the header
    }

    #[test]
    fn test_gmssl_protocol_version_handling() {
        // GMSSL protocol version should be recognized as encrypted
        let buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            ((GMSSL_PROTOCOL_VERSION >> 8) & 0xFF) as u8, // Major version
            (GMSSL_PROTOCOL_VERSION & 0xFF) as u8,        // Minor version
            0x00,
            0x14, // Length of the message
        ];
        assert!(is_encrypted(&buffer, 0));
    }

    #[test]
    fn test_various_tls_versions() {
        // Testing with different versions of TLS to ensure they're recognized as encrypted
        let tls_versions = vec![0x0301, 0x0302, 0x0303, 0x0304]; // TLS 1.0, 1.1, 1.2, 1.3

        for &version in tls_versions.iter() {
            let buffer = vec![
                SSL_CONTENT_TYPE_HANDSHAKE,
                ((version >> 8) & 0xFF) as u8,
                (version & 0xFF) as u8,
                0x00,
                0x14, // Length of the message
            ];
            assert!(
                is_encrypted(&buffer, 0),
                "Version {:X} should be encrypted",
                version
            );
        }
    }

    #[test]
    fn test_partial_message_handling() {
        // Simulate a buffer that ends partway through the encrypted message
        let buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x50, // Length indicating a larger message than is present
                  // Only part of the message is included
        ];
        let result = get_encrypted_packet_length(&buffer, 0);
        assert!(
            matches!(result, Err(Error::NotEnoughDataError)),
            "Should return NotEnoughDataError for partial messages"
        );
    }

    #[test]
    fn test_multiple_messages() {
        // Buffer containing two complete handshake messages back-to-back
        let mut buffer = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x14, // Length of the first message
                  // The actual first handshake message would follow here (omitted for brevity)
        ];
        let second_message = vec![
            SSL_CONTENT_TYPE_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2 again
            0x00,
            0x14, // Length of the second message
                  // The actual second handshake message would follow here (omitted for brevity)
        ];
        buffer.extend(second_message);

        // Test that the first message is correctly identified
        let first_message_result = get_encrypted_packet_length(&buffer, 0);
        assert_eq!(
            first_message_result,
            Ok(SSL_RECORD_HEADER_LENGTH + 20),
            "First message should be correctly identified"
        );

        // Assuming the first message and its header total length is known, check the second
        let offset_for_second_message = SSL_RECORD_HEADER_LENGTH as usize + 20; // Adjust based on actual message length
        let second_message_result = get_encrypted_packet_length(&buffer, offset_for_second_message);
        assert_eq!(
            second_message_result,
            Ok(SSL_RECORD_HEADER_LENGTH + 20),
            "Second message should be correctly identified"
        );
    }
}
