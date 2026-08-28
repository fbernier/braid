# Security Policy

## Reporting a vulnerability

Report privately through GitHub: **Security → Advisories → Report a vulnerability** on
<https://github.com/fbernier/braid>. If that is unavailable, mail
<frankbernier@gmail.com> with `braid security` in the subject.

Please do not open a public issue for anything that lets one user reach another user's
session, key material, or terminal input.

Expect an acknowledgement within seven days and an assessment within thirty. Braid is
alpha and has no release train: a fix lands on `master`, and the advisory names the
commit. There is no bounty.

## Trust model

Everything below is the ground the rest of the design stands on. A report that breaks one
of these is in scope.

- **Authentication is SSH's.** `brd` runs your `ssh` with your config and your keys, and
  adds no credential, listener or daemon reachable from the network. Anything that lets a
  session start without a successful SSH login is a vulnerability.
- **The daemon socket is same-uid only.** It lives in a `0700` directory and the daemon
  checks `SO_PEERCRED` (`getpeereid(3)` on the BSDs) against its own uid before reading a
  byte. A peer of a different uid reaching a session is a vulnerability.
- **Resume needs a capability.** A session is reattached with a 32-byte secret; only its
  BLAKE3 digest is written to disk. Recovering a live capability from on-disk state, from
  an argv, or from an environment variable is a vulnerability.
- **The datagram path is authenticated encryption.** ChaCha20-Poly1305 (RFC 8439), one
  key per epoch per direction, packet number as nonce, cleartext header as associated
  data. A nonce reuse, a key recovered off the wire, a forged or replayed datagram
  accepted as session input, or an off-path attacker capturing a session by spoofing a
  source address is a vulnerability. The datagram root secret is minted per attachment
  and delivered inside the SSH channel; a path that exposes it outside that channel is
  also a vulnerability.
- **Prediction never guesses at a prompt that has not echoed.** Locally drawn input that
  can appear on screen where the session is not echoing — a password prompt — is a
  vulnerability, not a display bug.

## Out of scope

- Anything that already requires your uid on either host. A process running as you can
  read your `~/.ssh`, your state directory and your terminal; the daemon does not defend
  against that and cannot.
- Wire protocol incompatibility between versions. The protocol is unstable by design
  during alpha; a version mismatch fails the handshake, which is the intended behaviour.
- Denial of service against your own daemon by your own uid.
- A resumed screen differing from the live one in the ways [the README's Status
  section](README.md#complete-terminal-state-across-a-resume) already names: saved cursor
  (DECSC), charset designation and tab stops are known missing, not undisclosed.
