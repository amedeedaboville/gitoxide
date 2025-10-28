//! A simple Git-compatible URL parser that doesn't require heavy dependencies like the `url` crate.
//!
//! This parser aims to match Git's native URL parsing behavior as closely as possible,
//! without international domain name (IDN) support.

use bstr::{BStr, ByteSlice};
use percent_encoding::percent_decode_str;

use crate::{parse::Error, parse::UrlKind, Scheme};

/// Parse a URL scheme following Git's behavior.
///
/// Git's approach from connect.c:
/// - Look for "://" to detect URL format
/// - Otherwise look for ":" to detect SCP format
/// - Otherwise it's a local path
pub(crate) fn find_scheme(input: &BStr) -> crate::parse::InputScheme {
    // Look for "://" first
    if let Some(protocol_end) = input.find("://") {
        return crate::parse::InputScheme::Url { protocol_end };
    }

    // Look for ":" which indicates SCP-like syntax
    if let Some(colon) = input.find_byte(b':') {
        // Allow user to select files containing a `:` by passing them as absolute or relative path
        // This is behavior explicitly mentioned by the scp and git manuals
        let explicitly_local = input[..colon].contains(&b'/');
        let dos_driver_letter = cfg!(windows) && input[..colon].len() == 1;

        if !explicitly_local && !dos_driver_letter {
            return crate::parse::InputScheme::Scp { colon };
        }
    }

    crate::parse::InputScheme::Local
}

/// Parse a URL with "://" scheme (git://, ssh://, http://, https://, file://)
pub(crate) fn url(input: &BStr, protocol_end: usize) -> Result<crate::Url, Error> {
    const MAX_LEN: usize = 1024;

    // Safety check for DoS
    let bytes_to_path = input[protocol_end + "://".len()..]
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .skip_while(|b| **b == b'/' || **b == b'\\')
        .position(|b| *b == b'/')
        .unwrap_or(input.len() - protocol_end);
    if bytes_to_path > MAX_LEN || protocol_end > MAX_LEN {
        return Err(Error::TooLong {
            truncated_url: input[..(protocol_end + "://".len() + MAX_LEN).min(input.len())].into(),
            len: input.len(),
        });
    }

    let input = std::str::from_utf8(input).map_err(|source| Error::Utf8 {
        url: input.to_owned(),
        kind: UrlKind::Url,
        source,
    })?;

    // Extract scheme
    let scheme_str = &input[..protocol_end];

    // Validate scheme: must contain only alphanumeric, +, -, or .
    // This matches URL spec and rejects things like "invalid:" (with colon) or double colons
    if !scheme_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
        return Err(Error::RelativeUrl {
            url: input.to_owned(),
        });
    }

    let scheme = Scheme::from(scheme_str);

    // Parse the rest: [user[:password]@]host[:port][/path]
    let after_scheme = &input[protocol_end + 3..]; // Skip "://"

    let (user, password, host, port, path) = parse_authority_and_path(after_scheme, &scheme)?;

    // Validate required fields
    if matches!(scheme, Scheme::Git | Scheme::Ssh) && path.is_empty() {
        return Err(Error::MissingRepositoryPath {
            url: input.into(),
            kind: UrlKind::Url,
        });
    }

    Ok(crate::Url {
        serialize_alternative_form: false,
        scheme,
        user,
        password,
        host,
        port,
        path: path.into(),
    })
}

/// Decode percent-encoded strings
fn percent_decode(s: &str) -> Result<String, Error> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|err| Error::Utf8 {
            url: s.into(),
            kind: UrlKind::Url,
            source: err,
        })
}

/// Parse authority (user, password, host, port) and path from a URL.
///
/// Format: [user[:password]@]host[:port][/path]
fn parse_authority_and_path(
    input: &str,
    scheme: &Scheme,
) -> Result<(Option<String>, Option<String>, Option<String>, Option<u16>, String), Error> {
    // Find the path separator
    let path_start = input.find('/').unwrap_or(input.len());
    let authority = &input[..path_start];
    let path = &input[path_start..];

    // Parse authority: [user[:password]@]host[:port]
    let (user, password, host, port) = if authority.is_empty() {
        (None, None, None, None)
    } else {
        parse_authority(authority)?
    };

    // Git's behavior: paths starting with /~ should become ~
    // This is for tilde expansion on the remote side
    let path = if path.starts_with("/~") && matches!(scheme, Scheme::Ssh | Scheme::Git) {
        &path[1..] // Remove leading /
    } else {
        path
    };

    // HTTP URLs must have at least "/" as path
    let path = if path.is_empty() && matches!(scheme, Scheme::Http | Scheme::Https) {
        "/"
    } else {
        path
    };

    Ok((user, password, host, port, path.to_string()))
}

/// Parse the authority part: [user[:password]@]host[:port]
fn parse_authority(
    authority: &str,
) -> Result<(Option<String>, Option<String>, Option<String>, Option<u16>), Error> {
    // Split on @ to separate user info from host
    let (user_info, host_port) = if let Some(at_pos) = authority.rfind('@') {
        let user_info = &authority[..at_pos];
        let host_port = &authority[at_pos + 1..];
        (Some(user_info), host_port)
    } else {
        (None, authority)
    };

    // Parse user info: user[:password]
    // User and password are percent-encoded in URLs
    let (user, password) = if let Some(user_info) = user_info {
        if let Some(colon_pos) = user_info.find(':') {
            let user = &user_info[..colon_pos];
            let password = &user_info[colon_pos + 1..];
            let user_decoded = percent_decode(user)?;
            let password_decoded = percent_decode(password)?;
            // When there's a colon, keep empty user as Some("") to distinguish from no user
            // This handles URLs like http://:password@host
            (
                Some(user_decoded),
                if password_decoded.is_empty() { None } else { Some(password_decoded) },
            )
        } else {
            let user_decoded = percent_decode(user_info)?;
            // When there's no colon, empty user becomes None
            (if user_decoded.is_empty() { None } else { Some(user_decoded) }, None)
        }
    } else {
        (None, None)
    };

    // Parse host and port
    let (host, port) = parse_host_port(host_port)?;

    Ok((user, password, host, port))
}

/// Parse host and port, handling IPv6 addresses correctly.
///
/// Git's behavior with IPv6:
/// - In URLs: ssh://user@[::1]/repo -> host is "::1" (brackets stripped)
/// - The brackets are just delimiters in the URL syntax
/// - Trailing colons without ports should be removed: host: -> host
fn parse_host_port(host_port: &str) -> Result<(Option<String>, Option<u16>), Error> {
    if host_port.is_empty() {
        return Ok((None, None));
    }

    // Handle IPv6 addresses in brackets: [::1]:port or [::1]
    if host_port.starts_with('[') {
        if let Some(close_bracket) = host_port.find(']') {
            let host = &host_port[1..close_bracket]; // Strip brackets
            let after_bracket = &host_port[close_bracket + 1..];

            let port = if after_bracket.starts_with(':') && after_bracket.len() > 1 {
                Some(after_bracket[1..].parse().map_err(|_| Error::Url {
                    url: host_port.to_string(),
                    kind: UrlKind::Url,
                    source: url::ParseError::InvalidPort,
                })?)
            } else {
                None
            };

            return Ok((Some(host.to_string()), port));
        }
    }

    // Check if this looks like an IPv6 address without brackets
    // IPv6 addresses contain multiple colons (::1, 2001:db8::1, etc.)
    let colon_count = host_port.chars().filter(|&c| c == ':').count();

    // If there are 2 or more colons, treat as IPv6 without brackets
    if colon_count >= 2 {
        // For IPv6 without brackets in URLs, return the whole thing as host
        return Ok((Some(host_port.to_string()), None));
    }

    // Handle regular host:port or just host
    // For non-IPv6, split on last : to get port
    if let Some(colon_pos) = host_port.rfind(':') {
        let host = &host_port[..colon_pos];
        let port_str = &host_port[colon_pos + 1..];

        // Git's behavior: trailing colon without port number -> no port
        if port_str.is_empty() {
            return Ok((Some(host.to_string()), None));
        }

        // Only parse as port if it's actually numeric
        if port_str.chars().all(|c| c.is_ascii_digit()) {
            let port = port_str.parse().map_err(|_| Error::Url {
                url: host_port.to_string(),
                kind: UrlKind::Url,
                source: url::ParseError::InvalidPort,
            })?;
            Ok((Some(host.to_string()), Some(port)))
        } else {
            // Colon but non-numeric port, keep the whole thing as host
            Ok((Some(host_port.to_string()), None))
        }
    } else {
        Ok((Some(host_port.to_string()), None))
    }
}

/// Parse SCP-like syntax: [user@]host:path or [user@][ipv6]:path
pub(crate) fn scp(input: &BStr, colon: usize) -> Result<crate::Url, Error> {
    let input = std::str::from_utf8(input).map_err(|source| Error::Utf8 {
        url: input.to_owned(),
        kind: UrlKind::Scp,
        source,
    })?;

    // Special handling for IPv6 addresses in brackets: [::1]:path
    // Find the closing bracket if it starts with [
    let (host_part, path_start) = if input.starts_with('[') {
        if let Some(close_bracket) = input.find(']') {
            // Check if there's a colon after the bracket
            if input[close_bracket + 1..].starts_with(':') {
                let host_part = &input[..close_bracket + 1]; // Include brackets
                let path_start = close_bracket + 2; // Skip ]:
                (host_part, path_start)
            } else {
                // No colon after bracket, use original logic
                (input.split_at(colon).0, colon + 1)
            }
        } else {
            // Unclosed bracket, use original logic
            (input.split_at(colon).0, colon + 1)
        }
    } else {
        (input.split_at(colon).0, colon + 1)
    };

    let path = &input[path_start..];

    if path.is_empty() {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned().into(),
            kind: UrlKind::Scp,
        });
    }

    // Parse user@host or user@[ipv6] or just host or just [ipv6]
    let (user, host) = if let Some(at_pos) = host_part.rfind('@') {
        let user = &host_part[..at_pos];
        let host_with_brackets = &host_part[at_pos + 1..];

        // Strip brackets from IPv6 if present
        let host = if host_with_brackets.starts_with('[') && host_with_brackets.ends_with(']') {
            &host_with_brackets[1..host_with_brackets.len() - 1]
        } else {
            host_with_brackets
        };

        (Some(user.to_string()), Some(host.to_string()))
    } else {
        // Strip brackets from IPv6 if present
        let host = if host_part.starts_with('[') && host_part.ends_with(']') {
            &host_part[1..host_part.len() - 1]
        } else {
            host_part
        };

        (None, Some(host.to_string()))
    };

    // Git's behavior: paths starting with /~ should become ~
    let path = if path.starts_with("/~") {
        &path[1..] // Remove leading /
    } else {
        path
    };

    Ok(crate::Url {
        serialize_alternative_form: true,
        scheme: Scheme::Ssh,
        user,
        password: None,
        host,
        port: None,
        path: path.into(),
    })
}

/// Parse file:// URLs
pub(crate) fn file_url(input: &BStr, protocol_end: usize) -> Result<crate::Url, Error> {
    let input = std::str::from_utf8(input).map_err(|source| Error::Utf8 {
        url: input.to_owned(),
        kind: UrlKind::Url,
        source,
    })?;

    let input_after_protocol = &input[protocol_end + "://".len()..];

    let first_slash = input_after_protocol
        .find('/')
        .or_else(|| cfg!(windows).then(|| input_after_protocol.find('\\')).flatten());

    let Some(first_slash) = first_slash else {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned().into(),
            kind: UrlKind::Url,
        });
    };

    // Windows special path handling
    let windows_special_path = if cfg!(windows) {
        let input_after_protocol = if first_slash == 0 {
            &input_after_protocol[1..]
        } else {
            input_after_protocol
        };

        if input_after_protocol.chars().nth(1) == Some(':') {
            Some(input_after_protocol)
        } else {
            None
        }
    } else {
        None
    };

    let host = if windows_special_path.is_some() || first_slash == 0 {
        None
    } else {
        Some(&input_after_protocol[..first_slash])
    };

    let path = windows_special_path.unwrap_or(&input_after_protocol[first_slash..]);

    Ok(crate::Url {
        serialize_alternative_form: false,
        scheme: Scheme::File,
        password: None,
        user: None,
        host: host.map(Into::into),
        port: None,
        path: path.into(),
    })
}

/// Parse local file paths
pub(crate) fn local(input: &BStr) -> Result<crate::Url, Error> {
    if input.is_empty() {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned(),
            kind: UrlKind::Local,
        });
    }

    Ok(crate::Url {
        serialize_alternative_form: true,
        scheme: Scheme::File,
        password: None,
        user: None,
        host: None,
        port: None,
        path: input.to_owned(),
    })
}
