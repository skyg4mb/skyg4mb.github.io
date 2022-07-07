---
title: "Email Security"
date: 2021-01-30T14:42:21-06:00
draft: false

# HelloFriend Specific
hideReadMore: false
---

This post started as a quick note for securing email for unused domains but I decided I could expand upon it a bit more to define terms in a language I believe to be more clear than I've seen elsewhere, and from the view-point of an administrator or domain owner.

## Index
* [SPF](#spf)
* [DMARC](#dmarc)
* [DKIM](#dkim)
* [Securing Unused Domains](#securing-unused-domains)
* [Additional Resources](#additional-resources)

## SPF

Sender Policy Framework ([SPF](https://www.dmarcanalyzer.com/spf/)) is a method for defining domains or ips that are allowed to send email for your domain. When an email server recieves an email from your domain it will check for SPF records for your domain to confirm that the sender was authorized.

SPF records are often used to prevent anyone from spoofing emails from your domain, while allowing specific services to send emails on your behalf (think marketing services, zendesk, salesforce).

### Example
```
hostname    value
--------    -----
@           v=spf1 ip4:182.4.35.44 include:3rdpartymail.com -all
```

### Explanation
Since SPF records are just text records defined for the root of the domain, they are defined with `v=sfp1` (v as in variable). `ip4` and `include:` are fairly straight forward just approved senders. The `all` flag defines how failures happen; `-all` is a 'hard' failure to reject failures, `~all` is a 'softfail' allowing emails to be accepted but flagged.


## DMARC
Domain-based Message Authentication, Reporting, and Conformance ([DMARC](https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record)) is another method for defining send authority for your domain, but provides control over what happens with authentication fails (quarantine or reject) as well as being able to receive email reports for message failures.

```
hostname    value
--------    -----
_dmarc.           v=DMARC1; p=reject; rua=mailto:admin@example.com;

```

### Explanation
The above record ensures that email recipients will `reject` any emails that fail validation (`quarantine` or `none` being the alternatives) and `rua` (report email address) ensures that each failure is reported to admin@example.com.

## DKIM
Domain Keys Identified Mail ([DKIM](https://postmarkapp.com/guides/dkim)) provides further sender authentication to your domain through the use of public-key cryptography. When you send an email from your domain, the email will be signed by your server, and when the receiving server gets your email it will validate the signed email using the public key defined in your domain's DKIM TXT record. *This signing method isn't used for encrypting your messages, only domain sender verification*.

```
hostname                            value
--------                            -----
specific._domainkey.domain.com      v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCS
```

### Explanation
In the above, the hostname is specific to the configuration of DKIM for your domain, and the `_domainkey` is required for discovery. As before, `v` defines the TXT value as DKIM version 1. `k` is short for key, defined above as an RSA key. `p` is the RSA public key contents (the above was truncated for brevity).


## Securing Unused Domains
If you're a hoarder of domains like I am, you'll often have domains with no custom records or default registrar records. Neither of which are particularly protected from spam and phishing attackers. Below I document the bare minimum for preventing spam or phishing using your domain. 

```
hostname    value
--------    -----
@           v=spf1 -all
_dmarc.     v=DMARC1; p=reject;
```

The above settings set a hardfail for SPF with no approved senders, essentially invalidating emails sent from your domain. Next, it defines DMARC with a policy of `reject`. If you want to receive reports for rejected emails, you can add `rua=mailto:youremail@domain.com;` to the above dmarc value string.



## Additional Resources

The following are recommended resources for reading up on email security features and protecting your domain's email.

* [UpGuard - The Email Security Checklist](https://www.upguard.com/blog/the-email-security-checklist)
* [UK Gov - Set up government email services securely](https://www.gov.uk/guidance/set-up-government-email-services-securely)
