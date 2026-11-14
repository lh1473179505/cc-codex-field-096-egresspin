# egresspin

Offline lab for admitting egress URLs against a frozen DNS snapshot
and a host pin store. Nothing here dials the network.

`python -m egresspin inspect --plan <file>` prints scheme, host, port,
path, and the redirect chain stored on the plan.

`python -m egresspin admit` must decide allow or deny using
`docs/admit-rules.md`. Exit 0 allow, 1 deny, 2 load failure.

Standard library only. No Docker, no network, no third-party packages.
