uTor is a compact Tor v3 communication library for Windows, written in pure C and designed as a proof of concept for minimalist, anonymous communication using .onion Hidden Services v3 (HSV3). At just 54 kilobytes, it demonstrates how HSV3 communication can be integrated into ultra-lightweight binaries using only native system calls and libraries.

The project was created to test whether malware-level anonymity could be achieved via Living Off the Land (LoL) techniques, without relying on bundled cryptographic libraries or external networking frameworks. While it broadly adheres to the HSV3 RFC, some functionality is omitted or simplified, making the implementation incomplete by Tor Project standards.

Despite its limitations, the library has been integrated into several small-scale internal tools and exhibits stable behavior under continuous operation. That said, it has not been formally tested, nor is it designed for production deployment.
Technical Highlights:

    🔒 LoL methodology leverages system-native components like bcrypt.dll, ntdll.dll, and the Windows SSL stack to minimize binary footprint and evade typical detection heuristics

    ⚠️ Compiler optimization selectively disabled in key areas to avoid breaking BCrypt or NTDLL interactions (observed through VS-generated assembly quirks)

    🔁 Partial HSV3 RFC adherence — implements core logic needed to fetch descriptors, perform onion handshakes, and request data, but lacks full feature parity

    🧪 Zero production hardening — no formal testing, security review, or coverage auditing has been performed

    Note: All internal comments were stripped automatically during CI via a Jenkins pipeline. The code remains publicly available and is intended for educational, experimental, and research contexts.

📩 Contact: mats.bosson@gmail.com
