// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This port is based on the original Coraza, created by Juan Pablo Tosso and
// the OWASP Coraza contributors.
//
// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//! IP address matching against CIDR blocks and ranges.

use std::{net::IpAddr, path::Path, str::FromStr as _};

use ipnet::{IpNet, Ipv4Net};

use crate::{
    operators::{Datasets, Operator, Outputs},
    rule_data::{FileSystem, RuleData, read_to_string},
    transaction::Transaction,
};

/// Parse an input address the way Go's `net.IPNet.Contains` sees it.
///
/// Go applies `net.IP.To4` to the address it tests, so an IPv4-mapped IPv6 address is an
/// IPv4 address and never fits an IPv6 network.
fn parse_input(input: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(input).ok()?;
    let ip = text.parse::<IpAddr>().ok()?;
    Some(ip.to_canonical())
}

/// Rewrite a parsed network the way Go's `net.IPNet.Contains` sees it.
///
/// Go's `networkNumberAndMask` applies `To4` to the network address and, for a mapped one,
/// keeps only the last 32 bits of the mask. `::ffff:192.0.2.128/124` is therefore
/// `192.0.2.128/28`, and a mapped network shorter than /96 is an IPv4 `/0`.
fn canonical_net(net: IpNet) -> IpNet {
    let IpNet::V6(inner) = net.trunc() else {
        return net;
    };
    let Some(addr) = inner.addr().to_ipv4_mapped() else {
        return net;
    };
    let prefix = inner.prefix_len().saturating_sub(96);
    let Ok(canonical) = Ipv4Net::new(addr, prefix) else {
        return net;
    };
    IpNet::V4(canonical)
}

/// IP address matching operator.
///
/// Performs fast IPv4 or IPv6 address matching with support for CIDR notation.
/// Can match individual IPs or IP ranges. Automatically adds appropriate subnet masks
/// (/32 for IPv4, /128 for IPv6) when not specified. Unparsable entries are ignored, as Go's
/// `newIPMatch` ignores them, so an argument with no valid entry matches nothing.
///
/// # Arguments
///
/// Comma-separated list of IP addresses with optional CIDR blocks (e.g., "192.168.1.0/24, 10.0.0.1").
///
/// # Returns
///
/// `true` if the input IP address matches any of the provided IPs or ranges, `false` otherwise.
#[derive(Debug, Clone)]
pub struct IpMatch {
    /// List of IP networks (CIDR blocks) to match against
    subnets: Vec<IpNet>,
}

impl IpMatch {
    /// Creates a new `IpMatch` operator from a comma-separated list of IPs/CIDRs.
    ///
    /// `10.0.0.0/100` alone yields an operator that matches nothing rather than an error, which
    /// is what Go's `newIPMatch` does when `net.ParseCIDR` rejects an entry.
    ///
    /// # Arguments
    ///
    /// * `ips` - Comma-separated list of IP addresses with optional CIDR notation
    pub fn new(ips: &str) -> Self {
        let mut subnets = Vec::new();

        for ip_str in ips.split(',') {
            let ip_str = ip_str.trim();
            if ip_str.is_empty() {
                continue;
            }

            // Auto-add CIDR suffix if not present
            let ip_with_cidr = if ip_str.contains(':') && !ip_str.contains('/') {
                // IPv6 without CIDR - add /128
                format!("{ip_str}/128")
            } else if ip_str.contains('.') && !ip_str.contains('/') {
                // IPv4 without CIDR - add /32
                format!("{ip_str}/32")
            } else {
                ip_str.to_owned()
            };

            if let Ok(net) = IpNet::from_str(&ip_with_cidr) {
                subnets.push(canonical_net(net));
            }
        }

        IpMatch { subnets }
    }
}

impl Operator for IpMatch {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        let Some(ip) = parse_input(input) else {
            return false;
        };

        // Check if the IP is contained in any of the configured subnets
        for subnet in &self.subnets {
            if subnet.contains(&ip) {
                return true;
            }
        }

        false
    }
}

/// Creates a new `ipMatch` operator.
///
/// # Arguments
///
/// * `ips` - Comma-separated list of IP addresses with optional CIDR blocks
pub fn ip_match(ips: &str) -> IpMatch {
    IpMatch::new(ips)
}

/// IP address matching operator (from a `SecDataset`).
///
/// Matches the IPs and CIDR blocks of a dataset as `@ipMatch` matches its own.
#[derive(Debug, Clone)]
pub struct IpMatchFromDataset {
    /// Parsed networks from the named dataset.
    ips: IpMatch,
}

impl Operator for IpMatchFromDataset {
    fn evaluate(&self, tx: &Transaction, input: &[u8], out: &mut Outputs) -> bool {
        self.ips.evaluate(tx, input, out)
    }
}

/// Creates a new `@ipMatchFromDataset` operator from the dataset `name` of `datasets`.
///
/// # Errors
///
/// If `datasets` has no dataset `name`, or an empty one.
pub fn ip_match_from_dataset(name: &str, datasets: &Datasets) -> Result<IpMatchFromDataset, String> {
    let items = datasets
        .get(name)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| format!("dataset \"{name}\" not found"))?;
    Ok(IpMatchFromDataset {
        ips: IpMatch::new(&items.join(",")),
    })
}

/// IP address matching operator (from file).
///
/// Loads IP addresses and CIDR blocks from a file, then performs matching
/// identical to `@ipMatch`. Each line in the file should contain one IP
/// address or CIDR block. Empty lines and lines starting with `#` are ignored.
///
/// # File Format
///
/// ```text
/// # Internal networks
/// 10.0.0.0/8
/// 172.16.0.0/12
/// 192.168.0.0/16
///
/// # Specific IPs
/// 203.0.113.42
/// ```
///
/// # Arguments
///
/// File path to load IP addresses from.
#[derive(Debug, Clone)]
pub struct IpMatchFromFile {
    /// List of IP networks (CIDR blocks) loaded from file
    subnets: Vec<IpNet>,
}

impl IpMatchFromFile {
    /// Creates a new `IpMatchFromFile` operator by loading IPs from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to file containing IP addresses (one per line); a relative path is relative to the working
    ///   directory
    ///
    /// # Returns
    ///
    /// `Ok(IpMatchFromFile)` if the file was read, even when it holds no valid entry (which
    /// matches nothing, as in Go), `Err` if the file could not be read.
    ///
    /// # File Format
    ///
    /// - One IP address or CIDR block per line
    /// - Empty lines are ignored
    /// - Lines starting with `#` are treated as comments and ignored
    /// - Invalid IP addresses are silently skipped
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read.
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        Self::with_rule_data(file_path, &FileSystem)
    }

    /// Creates a new `IpMatchFromFile` operator from `file_path` through `rule_data`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read.
    pub(crate) fn with_rule_data(file_path: impl AsRef<Path>, rule_data: &dyn RuleData) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = read_to_string(rule_data, file_path)
            .map_err(|error| format!("failed to read file {}: {error}", file_path.display()))?;

        let mut subnets = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Auto-add CIDR suffix if not present
            let ip_with_cidr = if line.contains(':') && !line.contains('/') {
                // IPv6 without CIDR - add /128
                format!("{line}/128")
            } else if line.contains('.') && !line.contains('/') {
                // IPv4 without CIDR - add /32
                format!("{line}/32")
            } else {
                line.to_owned()
            };

            if let Ok(net) = IpNet::from_str(&ip_with_cidr) {
                subnets.push(canonical_net(net));
            }
        }

        Ok(Self { subnets })
    }
}

impl Operator for IpMatchFromFile {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // Parse input IP address
        let Some(ip) = parse_input(input) else {
            return false;
        };

        // Check if IP is in any of the subnets
        self.subnets.iter().any(|subnet| subnet.contains(&ip))
    }
}

/// Creates a new `@ipMatchFromFile` operator.
///
/// # Arguments
///
/// * `file_path` - Path to file containing IP addresses (one per line); a relative path is relative to the working
///   directory
///
/// # Errors
///
/// Returns an error when the file cannot be read or contains no valid addresses.
pub fn ip_match_from_file(file_path: impl AsRef<Path>) -> Result<IpMatchFromFile, String> {
    IpMatchFromFile::new(file_path)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "operator tests use fixed valid inputs")]
mod tests {
    use super::{Datasets, Operator as _, Outputs, ip_match, ip_match_from_dataset, ip_match_from_file};
    use crate::transaction::Transaction;

    #[test]
    fn matches_ipv4_and_ipv6_networks() {
        let tx = Transaction::new("operator-test");
        let operator = ip_match("192.168.1.0/24, ::1");
        assert!(operator.evaluate(&tx, b"192.168.1.10", &mut Outputs::default()));
        assert!(operator.evaluate(&tx, b"::1", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"192.168.2.10", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"\xff", &mut Outputs::default()));
    }

    #[test]
    fn skips_unparsable_entries_like_go() {
        let tx = Transaction::new("operator-test");
        // Go's newIPMatch drops an entry net.ParseCIDR rejects; an IPv4 /100 is one.
        let invalid = ip_match("10.0.0.0/100");
        assert!(!invalid.evaluate(&tx, b"10.10.10.11", &mut Outputs::default()));
        assert!(!ip_match("").evaluate(&tx, b"10.10.10.11", &mut Outputs::default()));

        // A valid entry next to unparsable ones keeps matching.
        let mixed = ip_match("192.168.1.0/24, 10.0.0.0/100, not-an-ip");
        assert!(mixed.evaluate(&tx, b"192.168.1.10", &mut Outputs::default()));
        assert!(!mixed.evaluate(&tx, b"10.10.10.11", &mut Outputs::default()));
        assert!(!mixed.evaluate(&tx, b"203.0.113.1", &mut Outputs::default()));
    }

    #[test]
    fn skips_unparsable_file_entries_like_go() {
        let tx = Transaction::new("operator-test");
        let dir = tempfile::tempdir().unwrap();

        let mixed = dir.path().join("mixed.dat");
        std::fs::write(&mixed, "192.168.1.0/24\n10.0.0.0/100\nnot-an-ip\n").unwrap();
        let operator = ip_match_from_file(&mixed).unwrap();
        assert!(operator.evaluate(&tx, b"192.168.1.10", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"10.10.10.11", &mut Outputs::default()));

        let invalid = dir.path().join("invalid.dat");
        std::fs::write(&invalid, "10.0.0.0/100\n").unwrap();
        assert!(
            !ip_match_from_file(&invalid)
                .unwrap()
                .evaluate(&tx, b"10.10.10.11", &mut Outputs::default())
        );

        assert!(ip_match_from_file(dir.path().join("missing.dat")).is_err());
    }

    #[test]
    fn canonicalizes_ipv4_mapped_ipv6_like_go() {
        let tx = Transaction::new("operator-test");
        // Go's Contains applies To4 to the tested address, so a mapped address is an IPv4
        // address and does not fit an IPv6 network.
        let v6 = ip_match("0:0::/80");
        assert!(!v6.evaluate(&tx, b"0000:0000:0000:0000:0000:ffff:ffff:ffff", &mut Outputs::default()));
        assert!(v6.evaluate(&tx, b"0000:0000:0000:0000:0000:0000:0000:0009", &mut Outputs::default()));

        // A mapped network is the IPv4 network of its last 32 bits: /124 is /28.
        let mapped = ip_match("::ffff:192.0.2.128/124");
        assert!(mapped.evaluate(&tx, b"::ffff:192.0.2.143", &mut Outputs::default()));
        assert!(mapped.evaluate(&tx, b"192.0.2.143", &mut Outputs::default()));
        assert!(!mapped.evaluate(&tx, b"192.0.2.127", &mut Outputs::default()));
        assert!(!mapped.evaluate(&tx, b"::1", &mut Outputs::default()));

        // An IPv4 network contains the mapped form of its members.
        let v4 = ip_match("192.0.2.0/24");
        assert!(v4.evaluate(&tx, b"::ffff:192.0.2.1", &mut Outputs::default()));
        assert!(!v4.evaluate(&tx, b"::ffff:192.0.3.1", &mut Outputs::default()));
    }

    #[test]
    fn matches_ip_dataset_entries() {
        let tx = Transaction::new("operator-test");
        let mut datasets = Datasets::new();
        datasets.insert("private".to_owned(), vec!["10.0.0.0/8".to_owned()]);
        let operator = ip_match_from_dataset("private", &datasets).unwrap();
        assert!(operator.evaluate(&tx, b"10.1.2.3", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"192.0.2.1", &mut Outputs::default()));
        datasets.insert("invalid".to_owned(), vec!["10.0.0.0/100".to_owned()]);
        let operator = ip_match_from_dataset("invalid", &datasets).unwrap();
        assert!(!operator.evaluate(&tx, b"10.1.2.3", &mut Outputs::default()));
        assert!(ip_match_from_dataset("missing", &datasets).is_err());
    }
}
