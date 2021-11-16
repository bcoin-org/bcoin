# Security Policy

## Supported Versions

Versions of bcoin that are currently supported with security updates:

| Version      | Supported          |
| -------      | ------------------ |
| 2.0.0+       | :white_check_mark: |
| 2.0.0-dev    | :x:                |
| 1.0.0+       | :x:                |
| < 1.0.0-beta | :x:                |

## Reporting a Vulnerability

To report security issues send an email to chjjeffrey@gmail.com (not for support).

The following keys may be used to communicate sensitive information to developers:

| Name                | Fingerprint                                        | Email                        |
| ------              | -------------                                      | -----                        |
| Braydon Fuller      | 5B7D C58D 90FE C1E9 90A3  10BA F24F 232D 108B 3AD4 | braydon@purse.io             |
| Christopher Jeffrey | B4B1 F62D BAC0 84E3 33F3  A04A 8962 AB9D E666 6BBD | chjjeffrey@gmail.com         |
| Matthew Zipkin      | E617 73CD 6E01 040E 2F1B  D78C E7E2 984B 6289 C93A | pinheadmz@gmail.com          |
| Nodari Chkuaselidze | D2B2 828B D293 74D5 E9BA  3E52 CCE6 77B0 5CC0 FE23 | nodar.chkuaselidze@gmail.com |


You can import a key by running the following command with that individual’s fingerprint:

`$ gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints containing spaces.

To import the full set:

```
gpg --recv-keys "5B7DC58D90FEC1E990A310BAF24F232D108B3AD4"
gpg --recv-keys "B4B1F62DBAC084E333F3A04A8962AB9DE6666BBD"
gpg --recv-keys "E61773CD6E01040E2F1BD78CE7E2984B6289C93A"
gpg --recv-keys "D2B2828BD29374D5E9BA3E52CCE677B05CC0FE23"
```
