# Anatomy of a Healthy Security Operation

## The shortest primer

### Some definitions & things you may hear

- CISO/CSO: Chief Information Security Office / Chief Security Officer
- SIEM: Security Information Event Management
- Events: Single events represented as data, such as a log line from a program
- NIST: US National Institute of Standards and Technology 
- ISO27001: ISO 27001 (formally known as ISO/IEC 27001:2005) is a specification for an information security management system (ISMS)
- IOC: Indicator of Compromise - an IP, hash, etc. which is "known-bad"

### NIST Cybersecurity framework

This is one of the frameworks that can be used for healthy security operations.

- [Framework PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf)
- Framework core functions:
  Identify, Protect, Detect, Respond, Recover
- Maturity/Implementation tiers:
  - T1: Partial
  - T2: Risk Informed
  - T3: Repeatable
  - T4: Adaptive

### Incident Response typical steps

1. Identification
2. Containment
3. Eradication
4. Recovery
5. Lessons learned

### SIEM's typical capabilities

- Record incidents, live, automatically, in a collaborative manner
- Help investigation with a fast, powerful event search engine
- Assists forensics (same as above)
- Alert on known IOCs or patterns
- Take automatic containment actions where possible
- Assist manual blocking and containment
- Dashboards, reporting, metrics, visualizations

### Additional resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [SANS/CIS critical security controls](https://www.sans.org/critical-security-controls)
- [Mozilla Infosec guidelines](https://infosec.mozilla.org/#guidelines)
- [Mozilla Infosec risk assesment](https://infosec.mozilla.org/#risk-assessment)
- [Mozilla Infosec IAM](https://infosec.mozilla.org/#iam)
- [Mozilla Infosec security fundamentals](https://infosec.mozilla.org/#fundamentals (in particular, the security
  principles))


## Apply your knowledge

How would you apply this to your company? Do you already have a security team with an incident response process?
As an exercise, try to list different capabilities and areas at your company and match them with NIST's core functions
in the table below.

T1, T4, etc. represent the maturity of that function to the given area.

| Area vs Core Function                           | Identify | Protect | Detect | Respond | Recover |
|-------------------------------------------------|----------|---------|--------|---------|---------|
| Access to resources ("login", " authorization") | T1       | T4      | ...    |         |         |
| Data storage                                    |          |         |        |         |         |
| Secret handling                                 |          |         |        |         |         |
| Web properties                                  |          |         |        |         |         |

> **Note**: extend this table as you see fit! this exercise is optional and not required to understand MozDef, but will
> help you figure out where to leverage your SIEM 
