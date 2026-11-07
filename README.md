# EmailValidationAddon for THUNDERBIRD

Target: 158.0.1 (64-Bit)

This addon was developed because of the lack of simple/more automated email filter technics in the THUNDERBIRD.
Mailservers are often very limited to SPAM filter technics and do require are huge effort to filter those unwanted messages.
Therefore I have created an addon which tries to follow implement an very simple approach to filter those incomming emails by validating the email domain by the following rules:

1. The domain needs to exist (so it needs to have an valid DNS record)
    - if the domain has no A-DNS record, then we are sure it is SPAM, no further processing 
2. The domin should have an MX record
    - because usually a server which send mails, should also be able to receive them
    - if it does not, it will get a negative score
3. The domain is checked for a SPF entry
    - if it does not have an SPF record, the negative score will be become much lower
4. The domain is checked for a DKIM entry
    - if it does not have an DKIM record, the negative score will be become lower
5. If domain is rated below a specific score, it will be marked as SPAM

## TODOs
- Update functions to latest API standards for Thunderbird 158.0.1 (64-Bit).
- Test current implementation for bugs and security issues.
- Test DNS lookups for performance issues.
- Test SPF record validation.
- Test DKIM record validation.
- Test If domain is rated below a specific score, it will be marked as SPAM.
- Test other features.
- Extend functions
