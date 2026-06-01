//! A minimal HTTP/1.1 server using only the standard library.
//!
//! This is intentionally small: a local single-user tool, one thread per
//! connection, no keep-alive. It parses the request line, headers, and an
//! optional body bounded by Content-Length, and hands a [`Request`] to a
//! handler that returns a [`Response`].

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

/// A parsed HTTP request.
pub struct Request {
    pub method: String,
    pub path: String,
    /// Decoded query-string parameters.
    pub query: HashMap<String, String>,
    /// Decoded form parameters from a urlencoded body (POST).
    pub form: HashMap<String, String>,
}

/// A response to send back.
pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json(body: String) -> Response {
        Response {
            status: 200,
            content_type: "application/json; charset=utf-8".into(),
            body: body.into_bytes(),
        }
    }

    pub fn html(body: &str) -> Response {
        Response {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn download(name: &str, body: Vec<u8>) -> Response {
        Response {
            status: 200,
            content_type: format!("application/octet-stream; filename=\"{name}\""),
            body,
        }
    }
}

/// Run the server, dispatching each request through `handler` until the process
/// is killed.
pub fn serve<F>(bind: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(bind)?;
    let handler = std::sync::Arc::new(handler);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let h = handler.clone();
                std::thread::spawn(move || {
                    if let Err(e) = handle_conn(stream, &*h) {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_conn<F>(stream: TcpStream, handler: &F) -> std::io::Result<()>
where
    F: Fn(&Request) -> Response,
{
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    // Read headers.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    // Read body.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let (path, query_str) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let request = Request {
        method,
        path,
        query: parse_urlencoded(&query_str),
        form: parse_urlencoded(&String::from_utf8_lossy(&body)),
    };

    let response = handler(&request);
    write_response(stream, &response)
}

fn write_response(mut stream: TcpStream, r: &Response) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        r.status,
        reason,
        r.content_type,
        r.body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&r.body)?;
    stream.flush()
}

/// Parse `a=1&b=hello%20world` into a map, percent-decoding keys and values.
pub fn parse_urlencoded(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
