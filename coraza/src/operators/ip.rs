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

use ipnet::IpNet;

use crate::{
    operators::{Datasets, Operator, Outputs},
    transaction::Transaction,
};

/// IP address matching operator.
///
/// Performs fast IPv4 or IPv6 address matching with support for CIDR notation.
/// Can match individual IPs or IP ranges. Automatically adds appropriate subnet masks
/// (/32 for IPv4, /128 for IPv6) when not specified.
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
    /// # Arguments
    ///
    /// * `ips` - Comma-separated list of IP addresses with optional CIDR notation
    ///
    /// # Returns
    ///
    /// `Ok(IpMatch)` if at least one valid IP/CIDR was parsed, `Err` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error when no valid IP address or CIDR block is provided.
    pub fn new(ips: &str) -> Result<Self, String> {
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
                subnets.push(net);
            }
        }

        if subnets.is_empty() {
            return Err("no valid IP addresses or CIDR blocks provided".to_owned());
        }

        Ok(IpMatch { subnets })
    }
}

impl Operator for IpMatch {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // Parse the input IP address
        let Ok(Ok(ip)) = std::str::from_utf8(input).map(IpAddr::from_str) else {
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
///
/// # Errors
///
/// Returns an error when no valid IP address or CIDR block is provided.
pub fn ip_match(ips: &str) -> Result<IpMatch, String> {
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
/// If `datasets` has no dataset `name`, or an empty one, or it holds no valid IP.
pub fn ip_match_from_dataset(name: &str, datasets: &Datasets) -> Result<IpMatchFromDataset, String> {
    let items = datasets
        .get(name)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| format!("dataset \"{name}\" not found"))?;
    Ok(IpMatchFromDataset {
        ips: IpMatch::new(&items.join(","))?,
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
    /// `Ok(IpMatchFromFile)` if file was read and at least one valid IP was parsed,
    /// `Err` if file couldn't be read or no valid IPs were found.
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
    /// Returns an error when the file cannot be read or contains no valid addresses.
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, String> {
        let file_path = file_path.as_ref();
        let content = std::fs::read_to_string(file_path)
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
                subnets.push(net);
            }
        }

        if subnets.is_empty() {
            return Err(format!("No valid IP addresses found in {}", file_path.display()));
        }

        Ok(Self { subnets })
    }
}

impl Operator for IpMatchFromFile {
    fn evaluate(&self, _tx: &Transaction, input: &[u8], _out: &mut Outputs) -> bool {
        // Parse input IP address
        let Ok(Ok(ip)) = std::str::from_utf8(input).map(IpAddr::from_str) else {
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
    use super::{Datasets, Operator as _, Outputs, ip_match, ip_match_from_dataset};
    use crate::transaction::Transaction;

    #[test]
    fn matches_ipv4_and_ipv6_networks_and_rejects_invalid_input() {
        let tx = Transaction::new("operator-test");
        let operator = ip_match("192.168.1.0/24, ::1").unwrap();
        assert!(operator.evaluate(&tx, b"192.168.1.10", &mut Outputs::default()));
        assert!(operator.evaluate(&tx, b"::1", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"192.168.2.10", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"\xff", &mut Outputs::default()));
        assert!(ip_match("not-an-ip").is_err());
    }

    #[test]
    fn matches_ip_dataset_entries() {
        let tx = Transaction::new("operator-test");
        let mut datasets = Datasets::new();
        datasets.insert("private".to_owned(), vec!["10.0.0.0/8".to_owned()]);
        let operator = ip_match_from_dataset("private", &datasets).unwrap();
        assert!(operator.evaluate(&tx, b"10.1.2.3", &mut Outputs::default()));
        assert!(!operator.evaluate(&tx, b"192.0.2.1", &mut Outputs::default()));
        assert!(ip_match_from_dataset("missing", &datasets).is_err());
    }
}
