use std::convert::Infallible;

use bstr::{BStr, BString, ByteSlice};
use percent_encoding::percent_decode_str;

use crate::Scheme;

// Characters considered unsafe per RFC 3986 and Git's implementation.
const URL_UNSAFE_CHARS: &[u8] = b" <>\"#%{}|\\^`";
// RFC 3986 reserved characters (gen-delims + sub-delims).
const URL_RESERVED: &[u8] = b":/?#[]@!$&'()*+,;=";

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

fn check_length(input: &BStr, protocol_end: usize) -> Result<(), Error> {
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
    Ok(())
}
#[cfg(feature = "idn")]
pub(crate) fn url(input: &BStr, protocol_end: usize) -> Result<crate::Url, Error> {
    check_length(input, protocol_end)?;
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
pub(crate) fn url(input: &BStr, protocol_end: usize) -> Result<crate::Url, Error> {
    check_length(input, protocol_end)?;
    let input = input_to_utf8(input, UrlKind::Url)?;

    let scheme_str = &input[..protocol_end];
    if !scheme_str.chars().all(is_allowed_scheme_char) {
        return Err(Error::RelativeUrl { url: input.to_owned() });
    }
    let scheme: Scheme = Scheme::from(scheme_str.to_ascii_lowercase().as_str());

    // The "authority" is the part of the URL between the scheme and the path.
    let authority_start = protocol_end + "://".len();
    let authority_end = input[authority_start..]
        .find(|c: char| matches!(c, '/' | '?' | '#'))
        .map(|offset| authority_start + offset)
        .unwrap_or(input.len());
    let authority = &input[authority_start..authority_end];

    // Match one of:
    //   (1) scheme://<host>/...
    //   (2) scheme://<user>@<host>/...
    //   (3) scheme://<user>:<pass>@<host>/...
    let (raw_host_port, raw_user, raw_password) = if let Some((userinfo, host)) = authority.split_once('@') {
        if let Some((user, pass)) = userinfo.split_once(':') {
            let user = Some(user);
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
    // Remove default ports for the scheme (eg http:80 or https:443). This matches the url
    // crate's behavior but we may want to split this into a separate normalization step.
    let port = if port == scheme.default_port() { None } else { port };
    let (host, user, password) = (
        // Hosts are case-insensitive only for HTTP(S).
        parsed_host
            .map(|h| {
                if matches!(scheme, Scheme::Http | Scheme::Https) {
                    h.to_ascii_lowercase()
                } else {
                    h.to_string()
                }
            })
            .and_then(|h| escape_url_chars(&h).ok()),
        raw_user.map(|s| percent_decoded_utf8(s, UrlKind::Url)).transpose()?,
        raw_password
            .filter(|s| !s.is_empty())
            .map(|s| percent_decoded_utf8(s, UrlKind::Url))
            .transpose()?,
    );

    // A host is required for HTTP(S)
    if host.is_none() && matches!(scheme, Scheme::Http | Scheme::Https) {
        return Err(Error::MissingRepositoryPath {
            url: input.into(),
            kind: UrlKind::Url,
        });
    }

    let raw_path = &input[authority_end..];
    let path = match (raw_path.is_empty(), &scheme) {
        (false, _) => escape_url_chars(raw_path).expect("percent decode error for path"),
        (true, Scheme::Http | Scheme::Https) => "/".to_string(),
        // Path is required for SSH and git URLs
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

fn parse_host_port(host_port: &str, is_protocol_git: bool) -> (Option<&str>, Option<u16>) {
    if host_port.is_empty() {
        return (None, None);
    }
    // Bracketed IPv6: [addr]:port?
    if host_port.starts_with('[') {
        if let Some(end_pos) = host_port.find(']') {
            let host = &host_port[..=end_pos];
            let port = host_port[end_pos + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (Some(host), port);
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

// A port of git's append_normalized_escapes() from urlmatch.c.
// Escapes the set of characters from the RFC 3986 unsafe characters
// and unescapes everything but the characters in URL_RESERVED.
// If a %-escape sequence is encountered that is not followed by 2
// hexadecimal digits, the sequence is invalid and an Err is returned.
//
// All %-escape sequences are normalized to UPPERCASE as indicated in RFC 3986.
// Alphanumerics and "-._~" are always unescaped as per RFC 3986.
fn escape_url_chars(from: &str) -> Result<String, ()> {
    let mut out = String::with_capacity(from.len());
    let mut it = from.as_bytes().iter();

    while let Some(&b) = it.next() {
        let mut ch = b;
        let mut was_esc = false;

        if ch == b'%' {
            let hi = it.next().copied().ok_or(())?;
            let lo = it.next().copied().ok_or(())?;
            if !(hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()) {
                return Err(());
            }
            let hi = char::from(hi).to_digit(16).ok_or(())? as u8;
            let lo = char::from(lo).to_digit(16).ok_or(())? as u8;
            ch = (hi << 4) | lo;
            was_esc = true;
        }

        let should_escape = !ch.is_ascii()
            || ch.is_ascii_control()
            || URL_UNSAFE_CHARS.contains(&ch)
            || (was_esc && URL_RESERVED.contains(&ch));

        if should_escape {
            out.push_str(percent_encoding::percent_encode_byte(ch));
        } else {
            out.push(ch as char);
        }
    }

    Ok(out)
}

pub(crate) fn scp(input: &BStr, colon: usize) -> Result<crate::Url, Error> {
    let input = input_to_utf8(input, UrlKind::Scp)?;

    // TODO: this incorrectly splits at IPv6 addresses, check for `[]` before splitting
    let (host, path) = input.split_at(colon);
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
    let (user, host) = {
        // The path returned by the parsed url often has the wrong number of leading `/` characters but
        // should never differ in any other way (ssh URLs should not contain a query or fragment part).
        // To avoid the various off-by-one errors caused by the `/` characters, we keep using the path
        // determined above and can therefore skip parsing it here as well.
        let url = url::Url::parse(&format!("ssh://{host}")).map_err(|source| Error::Url {
            url: input.to_owned(),
            kind: UrlKind::Scp,
            source,
        })?;
        (url_user(&url, UrlKind::Scp)?, url.host_str())
    };
    #[cfg(not(feature = "idn"))]
    let (user, host) = {
        let (user, host_port) = if let Some((user, host_port)) = host.rsplit_once('@') {
            (Some(user.to_string()), host_port)
        } else {
            (None, host)
        };
        let host = parse_host_port(host_port, false).0.or(Some(host_port));
        (user, host)
    };

    Ok(crate::Url {
        serialize_alternative_form: true,
        scheme: Scheme::Ssh,
        user,
        password: None,
        host: host.map(Into::into),
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
