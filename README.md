# Analyzing-Phishing-Emails

##  Phishing-Pot Phishing Email Analysis Report

---

![Screenshot 2024-12-02 at 12 03 36 AM](https://github.com/user-attachments/assets/006d15ca-ec0c-4eda-b5ac-2dc87d6b1cf3)

- This report provides a comprehensive analysis of a phishing email, with the goal of identifying potential security risks and indicators of compromise (IOCs). The email claimed the recipient had won a "Sweepstakes Ultimate Nonstick Cookware entry" and required immediate action to claim the prize.
---
## 1. Header Analysis
- **Date Received**: `November 3, 2022`
- **From**: `lfzdd@electroplan.com`
- **Reply-To**: `newsletter@electroplan.com`
- **Sender IP**: `89.144.11.72`
- **SPF/DKIM**: `Failed`
- *Email Authentication failure:* The email failed basic email authentication protocols, indicating it is likely a spoofed message.
---
![Screenshot 2024-12-02 at 12 11 35 AM](https://github.com/user-attachments/assets/e81c4407-3f8d-4d16-9501-1b29b2bca8e9)

## 2. Content Analysis

- **Greeting Style**: The greeting was generic and impersonal, lacking any personalization.
- **Urgency Indicators**: The email conveyed a strong sense of urgency, suggesting immediate action was required to avoid some consequence.
- **Legitimacy of Offer**: The claim of winning a "Sweepstakes Ultimate Nonstick Cookware entry" seemed highly dubious and out of context for a typical email.

## 3. URL Analysis
- **Displayed URL**: The displayed URL, "hyptext link", was not a valid URL.
- **Actual URL**: The actual URL was not provided in the email, but the displayed URL likely redirected to "https://t.co/xY6w4URIzV", which was inaccessible, indicating the site had been taken down for phishing activities.
![Screenshot 2024-12-02 at 12 26 01 AM](https://github.com/user-attachments/assets/54b56ff5-7960-49c4-ae47-50b9b192de74)

## 4. Indicators of Compromise (IOCs)

- **Email Address**: `lfzdd@electroplan.com`
- **Reply-To Address**: `newsletter@electroplan.com`
- **Sender IP Address**: `89.144.11.72`
- **Malicious URL**: `https://t.co/xY6w4URIzV`

## *Risk Assessment*

Based on the analysis, this email exhibits multiple characteristics typical of phishing attempts, including email authentication failures, generic and impersonal content, a sense of urgency, and a dubious prize offer. These factors suggest a high probability of the email being a sophisticated phishing attack designed to steal user credentials or install malware.

---

## 5. Recommendations

- **User Awareness Training**: Provide security awareness training to employees to help them identify and report suspicious emails, such as this phishing attempt.
- **Technical Controls**: Implement email filtering and URL reputation checks to detect and block similar phishing emails in the future.
- **Threat Sharing**: Share the details of this phishing attempt, including the IOCs, with your organization's security team and relevant threat intelligence sharing platforms to help protect against similar attacks.

## Tools Used
- Thunderbird 
- VirusTotal
- Symantec SiteReview
- URLScan.io
- AbuseIPDB
