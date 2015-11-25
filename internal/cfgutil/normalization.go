/*
 * Copyright (c) 2015 The btcsuite developers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package cfgutil

import "net"

// NormalizeAddress returns the normalized form of the address, adding a default
// port if necessary.  An error is returned if the address, even without a port,
// is not valid.
func NormalizeAddress(addr string, defaultPort string) (hostport string, err error) {
	// If the first SplitHostPort errors because of a missing port and not
	// for an invalid host, add the port.  If the second SplitHostPort
	// fails, then a port is not missing and the original error should be
	// returned.
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err = net.SplitHostPort(addr)
	if err != nil {
		return "", origErr
	}
	return addr, nil
}

// NormalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string) ([]string, error) {
	var (
		normalized = make([]string, 0, len(addrs))
		seenSet    = make(map[string]struct{})
	)

	for _, addr := range addrs {
		normalizedAddr, err := NormalizeAddress(addr, defaultPort)
		if err != nil {
			return nil, err
		}
		_, seen := seenSet[normalizedAddr]
		if !seen {
			normalized = append(normalized, normalizedAddr)
			seenSet[normalizedAddr] = struct{}{}
		}
	}

	return normalized, nil
}
