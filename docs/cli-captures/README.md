# CLI output captures

The command-flow test generated these captures with synthetic plaintext and a loopback protocol fixture. Each transcript redacts the temporary approval URL and QR payload. The captures contain no request identifiers, certificate pins, tokens, or decrypted values.

- [Braille mode](qr-mode-braille/transcript.txt)
- [Sextant mode](qr-mode-sextant/transcript.txt)
- [Half mode](qr-mode-half/transcript.txt)
- [Kitty mode](qr-mode-kitty/transcript.txt)

The Kitty capture used piped standard error. It records the expected unsupported-terminal message and continued URL-based handoff. Unit tests check Kitty protocol framing and image data without terminal hardware; they do not verify display or scanning in a physical terminal.
