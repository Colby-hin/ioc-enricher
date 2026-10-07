# IOC Enricher

## Purpose

IOC Enricher is a Python based threat intelligence enrichment tool designed to reduce manual IOC investigation work.

The tool accepts a list of IP addresses and enriches each indicator using the VirusTotal API.

It collects useful threat intelligence context and exports the results into a structured CSV file for analyst review.

The goal is to make IP triage faster and easier when working with indicators collected from SIEM alerts, EDR alerts, firewall logs, proxy logs, threat reports, or incident investigations.

## Features

1. Reads multiple IP addresses from a text file

2. Validates IPv4 and IPv6 addresses before enrichment

3. Queries the VirusTotal API for each valid indicator

4. Collects malicious detection counts

5. Collects suspicious detection counts

6. Retrieves network ownership information

7. Retrieves available country information

8. Retrieves VirusTotal reputation data

9. Flags indicators that may require analyst review

10. Exports enrichment results into a CSV file

## Workflow

```text
Security Alert or IOC List
          |
          v
       ips.txt
          |
          v
   IP Validation
          |
          v
   VirusTotal API
          |
          v
Threat Intelligence Enrichment
          |
          v
   Review Decision
          |
          v
     results.csv