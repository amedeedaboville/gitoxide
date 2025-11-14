use std::convert::Infallible;

use bstr::{BStr, BString, ByteSlice};
use percent_encoding::percent_decode_str;

use crate::Scheme;

// Characters considered unsafe per RFC 3986 and Git's implementation.
const URL_UNSAFE_CHARS: &str = " <>\"#%{}|\\^`";
// RFC 3986 reserved characters (gen-delims + sub-delims).
const URL_RESERVED: &str = ":/?#[]@!$&'()*+,;=";

/// The error returned by [parse()](crate::parse()).
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("{} \"{url}\" is not valid UTF-8", kind.as_str())]
    Utf8 {
        url: BString,
        kind: UrlKind,
        source: std::str::Utf8Error,
    },

    #[error("{} {url:?} can not be parsed as valid URL", kind.as_str())]
    Url {
        url: String,
        kind: UrlKind,
        #[cfg(feature = "idn")]
        source: url::ParseError,
        #[cfg(not(feature = "idn"))]
        reason: String,
    },

    #[error("The host portion of the following URL is too long ({} bytes, {len} bytes total): {truncated_url:?}", truncated_url.len())]
    TooLong { truncated_url: BString, len: usize },
    #[error("{} \"{url}\" does not specify a path to a repository", kind.as_str())]
    MissingRepositoryPath { url: BString, kind: UrlKind },
    #[error("URL {url:?} is relative which is not allowed in this context")]
    RelativeUrl { url: String },
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        unreachable!("Cannot actually happen, but it seems there can't be a blanket impl for this")
    }
}

///
#[derive(Debug, Clone, Copy)]
pub enum UrlKind {
    ///
    Url,
    ///
    Scp,
    ///
    Local,
}

impl UrlKind {
    fn as_str(&self) -> &'static str {
        match self {
            UrlKind::Url => "URL",
            UrlKind::Scp => "SCP-like target",
            UrlKind::Local => "local path",
        }
    }
}

pub(crate) enum InputScheme {
    Url { protocol_end: usize },
    Scp { colon: usize },
    Local,
}

pub(crate) fn find_scheme(input: &BStr) -> InputScheme {
    // TODO: url's may only contain `:/`, we should additionally check if the characters used for
    //       protocol are all valid
    if let Some(protocol_end) = input.find("://") {
        return InputScheme::Url { protocol_end };
    }

    if let Some(colon) = input.find_byte(b':') {
        // allow user to select files containing a `:` by passing them as absolute or relative path
        // this is behavior explicitly mentioned by the scp and git manuals
        let explicitly_local = &input[..colon].contains(&b'/');
        let dos_driver_letter = cfg!(windows) && input[..colon].len() == 1;

        if !explicitly_local && !dos_driver_letter {
            return InputScheme::Scp { colon };
        }
    }

    InputScheme::Local
}

fn is_allowed_scheme_char(chr: char) -> bool {
    matches!(chr, 'a'..='z' | 'A'..='Z' | '0'..='9' | '+' | '-' | '.')
}

pub(crate) fn url(input: &BStr, protocol_end: usize) -> Result<crate::Url, Error> {
    const MAX_LEN: usize = 1024;
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
    #[cfg(feature = "idn")]
    {
        let (input, url) = input_to_utf8_and_url(input, UrlKind::Url)?;
        let scheme = url.scheme().into();

        if matches!(scheme, Scheme::Git | Scheme::Ssh) && url.path().is_empty() {
            return Err(Error::MissingRepositoryPath {
                url: input.into(),
                kind: UrlKind::Url,
            });
        }

        if url.cannot_be_a_base() {
            return Err(Error::RelativeUrl { url: input.to_owned() });
        }

        Ok(crate::Url {
            serialize_alternative_form: false,
            scheme,
            user: url_user(&url, UrlKind::Url)?,
            password: url
                .password()
                .map(|s| percent_decoded_utf8(s, UrlKind::Url))
                .transpose()?,
            host: url.host_str().map(Into::into),
            port: url.port(),
            path: url.path().into(),
        })
    }
    #[cfg(not(feature = "idn"))]
    {
        let input = input_to_utf8(input, UrlKind::Url)?;
        let scheme_str = &input[..protocol_end];
        if !scheme_str.chars().all(is_allowed_scheme_char) {
            return Err(Error::Url {
                url: input.to_string(),
                kind: UrlKind::Url,
                reason: "Scheme contains invalid characters".into(),
            });
        }
        let scheme = Scheme::from(scheme_str);

        // Parse `userinfo` (username[:password]) if present and before the path/query/fragment.
        let authority_start = protocol_end + "://".len();
        let authority_end = input[authority_start..]
            .find(|c: char| matches!(c, '/' | '?' | '#'))
            .map(|offset| authority_start + offset)
            .unwrap_or(input.len());
        let authority = &input[authority_start..authority_end];
        /*
         * Match one of:
         *   (1) proto://<host>/...
         *   (2) proto://<user>@<host>/...
         *   (3) proto://<user>:<pass>@<host>/...
         */
        let (raw_host_port, raw_user, raw_password) = if let Some((userinfo, host)) = authority.split_once('@') {
            if let Some((user, pass)) = userinfo.split_once(':') {
                let user = Some(user); // keep empty user if password is present
                let pass = (!pass.is_empty()).then_some(pass);
                (host, user, pass)
            } else {
                let user = (!userinfo.is_empty()).then_some(userinfo);
                (host, user, None)
            }
        } else {
            (authority, None, None)
        };

        // Parse host[:port] portion
        let (parsed_host, port) = parse_host_port(raw_host_port, scheme == Scheme::Git);
        let (host, user, password) = (
            parsed_host.and_then(|h| escape_url_chars(&h).ok()),
            raw_user.map(|s| percent_decoded_utf8(s, UrlKind::Url)).transpose()?,
            raw_password
                .filter(|s| !s.is_empty())
                .map(|s| percent_decoded_utf8(s, UrlKind::Url))
                .transpose()?,
        );

        let raw_path = &input[authority_end..];
        let path = match (raw_path.is_empty(), &scheme) {
            (false, _) => escape_url_chars(raw_path).expect("percent decode error for path"),
            (true, Scheme::Http | Scheme::Https) => "/".to_string(),
            // Path is required for ssh and git URLs
            (true, Scheme::Ssh | Scheme::Git) => {
                return Err(Error::MissingRepositoryPath {
                    url: input.into(),
                    kind: UrlKind::Url,
                });
            }
            (true, _) => "".to_string(),
        };

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
}

fn parse_host_port(host_port: &str, is_protocol_git: bool) -> (Option<&str>, Option<u16>) {
    if host_port.is_empty() {
        return (None, None);
    }
    // Bracketed IPv6: [addr]:port?
    if !is_protocol_git {
        if let Some(rest) = host_port.strip_prefix('[') {
            if let Some((host, after)) = rest.split_once(']') {
                let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
                return (Some(host), port);
            }
        }
    }
    // Unbracketed IPv6 (contains multiple colons) - treat entire segment as host, no port.
    if host_port.bytes().filter(|b| *b == b':').count() > 1 {
        return (Some(host_port), None);
    }
    // Regular host[:port]
    if let Some(colon) = host_port.find(':') {
        let after = &host_port[colon + 1..];
        if after.is_empty() {
            return match is_protocol_git {
                // Git URLs without an explicit port keep their trailing colon
                true => (Some(&host_port[..=colon]), None),
                false => (Some(&host_port[..colon]), None),
            };
        }
        if let Ok(port) = after.parse::<u16>() {
            return (Some(&host_port[..colon]), Some(port));
        }
    }
    // Has no leading [, no ipv6 ::, and no colon, treat it as regular host
    (Some(host_port), None)
}
fn percent_decoded_utf8(s: &str, kind: UrlKind) -> Result<String, Error> {
    Ok(percent_decode_str(s)
        .decode_utf8()
        .map_err(|err| Error::Utf8 {
            url: s.into(),
            kind,
            source: err,
        })?
        .into_owned())
}

/*
 * Convert two consecutive hexadecimal digits into a char.  Return a
 * negative value on error.  Don't run over the end of short strings.
 */
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + (b - b'a')),
        b'A'..=b'F' => Some(10 + (b - b'A')),
        _ => None,
    }
}

fn hex_to_char(hi: u8, lo: u8) -> Option<u8> {
    let Some(hi_v) = hex_val(hi) else { return None };
    let Some(lo_v) = hex_val(lo) else {
        return None;
    };
    Some((hi_v << 4) | lo_v)
}

fn escape_url_chars(from: &str) -> Result<String, ()> {
    append_normalized_escapes(from, "", URL_RESERVED)
}
fn append_normalized_escapes(from: &str, esc_extra: &str, esc_ok: &str) -> Result<String, ()> {
    let bytes = from.as_bytes();
    let mut i = 0usize;
    let mut out = String::with_capacity(from.len());

    while i < bytes.len() {
        let mut ch = bytes[i];
        let mut was_esc = false;
        i += 1;

        if ch == b'%' {
            if i + 1 >= bytes.len() {
                return Err(());
            }
            was_esc = true;
            let Some(converted_ch) = hex_to_char(bytes[i], bytes[i + 1]) else {
                return Err(());
            };
            ch = converted_ch;
            i += 2;
        }

        let should_escape = ch <= 0x1F
            || ch >= 0x7F
            || URL_UNSAFE_CHARS.as_bytes().contains(&ch)
            || (!esc_extra.is_empty() && esc_extra.as_bytes().contains(&ch))
            || (was_esc && !esc_ok.is_empty() && esc_ok.as_bytes().contains(&ch));

        if should_escape {
            out.push('%');
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push(HEX[(ch >> 4) as usize] as char);
            out.push(HEX[(ch & 0x0F) as usize] as char);
        } else {
            out.push(ch as char);
        }
    }

    Ok(out)
}

pub(crate) fn scp(input: &BStr, _colon: usize) -> Result<crate::Url, Error> {
    let input = input_to_utf8(input, UrlKind::Scp)?;

    // Find the delimiter colon for scp-like syntax, but ignore colons inside IPv6 brackets.
    // Split at the FIRST ':' that appears AFTER the first '@' (if any), matching scp semantics.
    let mut bracket_depth = 0usize;
    let mut split_at: Option<usize> = None;
    let first_at = input.as_bytes().iter().position(|b| *b == b'@');
    for (idx, byte) in input.as_bytes().iter().enumerate() {
        match *byte {
            b'[' => bracket_depth = bracket_depth.saturating_add(1),
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b':' if bracket_depth == 0 && first_at.map(|a| idx > a).unwrap_or(true) => {
                split_at = Some(idx);
                break;
            }
            _ => {}
        }
    }
    let Some(split_at) = split_at else {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned().into(),
            kind: UrlKind::Scp,
        });
    };

    let (host, path) = input.split_at(split_at);
    debug_assert_eq!(path.get(..1), Some(":"), "{path} should start with :");
    let path = &path[1..];

    if path.is_empty() {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned().into(),
            kind: UrlKind::Scp,
        });
    }

    // Match git's behavior: paths starting with /~ become ~ (tilde-expansion on remote)
    let path = if path.starts_with("/~") { &path[1..] } else { path };

    #[cfg(feature = "idn")]
    {
        // The path returned by the parsed url often has the wrong number of leading `/` characters but
        // should never differ in any other way (ssh URLs should not contain a query or fragment part).
        // To avoid the various off-by-one errors caused by the `/` characters, we keep using the path
        // determined above and can therefore skip parsing it here as well.
        let url = url::Url::parse(&format!("ssh://{host}")).map_err(|source| Error::Url {
            url: input.to_owned(),
            kind: UrlKind::Scp,
            source,
        })?;

        Ok(crate::Url {
            serialize_alternative_form: true,
            scheme: url.scheme().into(),
            user: url_user(&url, UrlKind::Scp)?,
            password: url
                .password()
                .map(|s| percent_decoded_utf8(s, UrlKind::Scp))
                .transpose()?,
            host: url.host_str().map(Into::into),
            port: url.port(),
            path: path.into(),
        })
    }
    let (user, host_port) = if let Some((user, host_port)) = host.rsplit_once('@') {
        (Some(user.to_string()), host_port)
    } else {
        (None, host)
    };
    let (host_parsed, _port) = parse_host_port(host_port, false);
    let host = host_parsed.unwrap_or(host_port);
    Ok(crate::Url {
        serialize_alternative_form: true,
        scheme: Scheme::Ssh,
        user,
        password: None,
        host: Some(host.into()),
        port: None,
        path: path.into(),
    })
}

#[cfg(feature = "idn")]
fn url_user(url: &url::Url, kind: UrlKind) -> Result<Option<String>, Error> {
    if url.username().is_empty() && url.password().is_none() {
        Ok(None)
    } else {
        Ok(Some(percent_decoded_utf8(url.username(), kind)?))
    }
}

pub(crate) fn file_url(input: &BStr, protocol_colon: usize) -> Result<crate::Url, Error> {
    let input = input_to_utf8(input, UrlKind::Url)?;
    let input_after_protocol = &input[protocol_colon + "://".len()..];

    let Some(first_slash) = input_after_protocol
        .find('/')
        .or_else(|| cfg!(windows).then(|| input_after_protocol.find('\\')).flatten())
    else {
        return Err(Error::MissingRepositoryPath {
            url: input.to_owned().into(),
            kind: UrlKind::Url,
        });
    };

    // We cannot use the url crate to parse host and path because it special cases Windows
    // driver letters. With the url crate an input of `file://x:/path/to/git` is parsed as empty
    // host and with `x:/path/to/git` as path. This behavior is wrong for Git which only follows
    // that rule on Windows and parses `x:` as host on Unix platforms. Additionally, the url crate
    // does not account for Windows special UNC path support.

    // TODO: implement UNC path special case
    let windows_special_path = if cfg!(windows) {
        // Inputs created via url::Url::from_file_path contain an additional `/` between the
        // protocol and the absolute path. Make sure we ignore that first slash character to avoid
        // producing invalid paths.
        let input_after_protocol = if first_slash == 0 {
            &input_after_protocol[1..]
        } else {
            input_after_protocol
        };
        // parse `file://x:/path/to/git` as explained above
        if input_after_protocol.chars().nth(1) == Some(':') {
            Some(input_after_protocol)
        } else {
            None
        }
    } else {
        None
    };

    let host = if windows_special_path.is_some() || first_slash == 0 {
        // `file:///path/to/git` or a windows special case was triggered
        None
    } else {
        // `file://host/path/to/git`
        Some(&input_after_protocol[..first_slash])
    };

    // default behavior on Unix platforms and if no Windows special case was triggered
    let path = windows_special_path.unwrap_or(&input_after_protocol[first_slash..]);

    Ok(crate::Url {
        serialize_alternative_form: false,
        host: host.map(Into::into),
        ..local(path.into())?
    })
}

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

fn input_to_utf8(input: &BStr, kind: UrlKind) -> Result<&str, Error> {
    std::str::from_utf8(input).map_err(|source| Error::Utf8 {
        url: input.to_owned(),
        kind,
        source,
    })
}

#[cfg(feature = "idn")]
fn input_to_utf8_and_url(input: &BStr, kind: UrlKind) -> Result<(&str, url::Url), Error> {
    let input = input_to_utf8(input, kind)?;
    url::Url::parse(input)
        .map(|url| (input, url))
        .map_err(|source| Error::Url {
            url: input.to_owned(),
            kind,
            source,
        })
}
