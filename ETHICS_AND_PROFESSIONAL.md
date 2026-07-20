# Ethics and Professional Considerations

## Dual-Use Nature of This Research

The knowledge produced by this project has dual-use implications. Understanding how to recover RSA private keys through Wiener's Attack, exploit padding oracles through Bleichenbacher's method, or measure timing signals to extract key bits is directly applicable to attacking real systems — and these attacks have been used against real systems, as the DROWN case demonstrates.

### Where I drew the line

This repository contains implementations of four attacks. The design principle throughout was:

**Demonstrate the mathematical precondition, not operational attack capability.**

Concretely:
- `wiener_attack.py` uses toy parameters and a real-scale test case to verify the continued fraction algorithm. It does not include tooling to scan for vulnerable public keys in the wild.
- `bleichenbacher_toy.py` uses a 128-bit modulus and a simulated oracle. It does not include network code to connect to real TLS servers.
- `timing_attack_demo.py` uses operation counts, not real timing measurements against a target system.
- `common_modulus_attack.py` operates entirely on given ciphertexts with no tooling to intercept real traffic.

A person with prior background in cryptography and network security could use the concepts here as a starting point for a real attack. A person without that background could not directly use these scripts to attack a real system.

## Responsible Disclosure

The three most significant real-world attacks discussed in this project were handled differently by their discoverers:

**Bleichenbacher (1998):** Published at CRYPTO 1998 with full technical detail simultaneously available to defenders and attackers. This was standard practice at the time. SSL/TLS vendors patched quickly, but the vulnerability persisted in various forms for over 20 years (DROWN, 2016; ROBOT, 2017; Marvin, 2023).

**DROWN (2016):** Coordinated disclosure with major vendors (OpenSSL, browser vendors, major HTTPS operators) before public announcement. Patches were available simultaneously with publication. This is now considered best practice.

**CacheBleed (2016):** Also coordinated disclosure, with OpenSSL notified and patched before publication.

The shift from Bleichenbacher's immediate publication to the DROWN team's coordinated disclosure reflects an 18-year change in community norms. Neither approach is universally correct — coordinated disclosure requires significant organisational effort, is harder for independent researchers, and can fail if vendors are slow to act. Immediate publication creates risk but may be the only option when the discoverer has no leverage over vendors.

## Data and Access

All papers read for this project were accessed through UNSW Library (legitimate institutional subscription). No paywalled papers were obtained through unofficial channels.

The implementations in this repository operate on synthetic data only. No real private keys, no real network traffic, no real certificates were used at any point.

## What This Project Did Not Do

- Did not scan any network for vulnerable servers
- Did not test against any system without explicit control (all targets were locally generated)
- Did not attempt to obtain real private keys from any real system
- Did not use any vulnerability that is currently unpatched in a way that could cause harm
- Did not share or publish any credential, private key, or sensitive data obtained through testing
