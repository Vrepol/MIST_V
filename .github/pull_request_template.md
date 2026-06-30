## Summary

<!-- What changed? Keep this concise and concrete. -->

## Motivation

<!-- Why is this change needed for MistV? Link the issue if applicable: Closes #123 -->

## Change Type

- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Security hardening
- [ ] Documentation
- [ ] Test / CI
- [ ] Other

## MistV Scope Check

MistV is a lightweight, temporary, terminal-first encrypted chat tool. This PR should preserve that boundary.

- [ ] Does not introduce user accounts, profiles, friends, or long-term identity
- [ ] Does not introduce persistent chat history, offline messages, or cloud attachment storage
- [ ] Does not require a web admin panel or complex backend service
- [ ] Keeps the default flow simple for temporary sessions
- [ ] Treats server, network, invite codes, nicknames, file names, paths, and clipboard input as untrusted

## Security / Privacy Impact

<!-- Describe any effect on encryption, keys, invites, attachment plaintext, temp files, logs, or trust boundaries. -->

- [ ] No plaintext messages, room credentials, invite secrets, file keys, or server passwords are logged
- [ ] No received file is automatically executed
- [ ] Attachment names and paths are handled safely
- [ ] New network/protocol input has validation and error handling
- [ ] Not security-sensitive / no change to security boundary

## Testing

<!-- List the exact commands run. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all --all-features --locked`
- [ ] Manual test notes:

## Screenshots / Terminal Output

<!-- For TUI changes, paste a screenshot or terminal output if helpful. -->

## Compatibility

- [ ] Linux considered
- [ ] macOS considered
- [ ] Windows considered
- [ ] IPv4 / hostname considered
- [ ] IPv6 considered, if networking-related

## Risk and Rollback

<!-- What could break? How can we revert or disable this safely? -->

## Checklist

- [ ] Code is small enough to review clearly
- [ ] Tests or manual verification cover the main path
- [ ] Edge cases and failure paths are considered
- [ ] Documentation / README updated if user behavior changed
- [ ] Related issue linked
