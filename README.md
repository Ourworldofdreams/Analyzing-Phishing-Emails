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
- **Subject** `Re: Shipment Pending - Ultimate Nonstick Cookware`
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




---


---


---



# Phishing-pot Phishing Email Analysis Report
![Screenshot 2024-12-12 at 4 02 00 PM](https://github.com/user-attachments/assets/18a84093-727d-486b-a0ae-2581085fc3ed)

## Metadata
- **Source**: `GitHub Phishing Sample Repository`
- **Threat Classification**: `Phishing Attempt`

## Objective:

## 1. Header Analysis
### Email Metadata
- **Date Received**: `7/29/23, 13:16`
- **To** `phishing@pot`
- **From**: `hello<otto-newsletter@newsletter.otto.de>`
- **Reply-To**: `reply_to@winner-win.art`
- **Sender IP**: `80.96.157.91`
- **DNS Lookup**:
  
### Authentication Verification
- **SPF Check**: `Softfail`
- **DKIM Verification**: `None`
- **DMARC Policy**: `Fail`

   ![Screenshot 2024-12-12 at 4 15 33 PM](https://github.com/user-attachments/assets/a8646d83-df39-483b-843b-efad224fc212)

## 2. Content Analysis
- **Content-Transfer-Encoding**: `7bit`
- **Subject**:phishing@pot, 𝕀𝕙𝕣 𝕚ℂ𝕝𝕠𝕦𝕕-𝕊𝕡𝕖𝕚𝕔𝕙𝕖𝕣 𝕚𝕤𝕥 𝕧𝕠𝕝𝕝
- ### Email Body Characteristics
- The email appears to be impersonating an Apple iCloud Drive notification, with several hyperlinks included, most likely used as credential harvesting mechanisms.     

## 3. URL Analysis
### Link Examination
- **Displayed URL**: The displayed Hypertext links are no longer active, suggesting the phishing site has been taken down. 
![Screenshot 2024-12-12 at 4 58 49 PM](https://github.com/user-attachments/assets/0a44b1a3-9298-4e76-9f10-794bf0ced4b3)

### URL Reputation Checks
- **VirusTotal Status**: `Malicious`
![Screenshot 2024-12-12 at 4 56 46 PM](https://github.com/user-attachments/assets/3a446850-41c1-4d03-b45b-775d5adc2e7a)

  ![Screenshot 2024-12-12 at 5 00 22 PM](https://github.com/user-attachments/assets/8bcba9e2-465c-493b-b4c9-018c00b2ab6d)

- **Phishtank Verification**: `Confirmed Phishing`
- **IP Geolocation**:
  - latest serving IP for the hypertextlink: `72.52.178.23` 
  - Country: `US`
  - Hosting Provider: `Liquidweb`

## 5. Indicators of Compromise (IOCs)
### Network Indicators
- **Malicious URLs of the main call-to-action buttons**: 
  -`http://bsq2.firiri.shop/V0RPUjMzbjdPeHRLVlo2RFZ4WXBqZklYbTBnY1Btc1R5aUp4cWNUMzNOUjJnNDNjUUg5NUt2U1hYQkFpYlIyVi82NHBrdDVpRnhPdG1tQWlZbWVWMUE9PQ__`
  - `https://t.co/gDHura2rGc`
  - **IP Addresses**:
  - `72.52.178.23`
  - `104.244.42.197`
**Email Addresses**:
  - `Dringend->Icloud <otto-newsletter@newsletter.otto.de`
- **Reply-To Address**:
  - `reply_to@winner-win.art`
- **Sender IP Address**:
  - `80.96.157.91`

## 8. Mitigation Recommendations
### Immediate Actions
- Block the identified malicious URLs and IP addresses at the email gateway and network firewall.
- Investigate any devices that may have interacted with the phishing content.
- Reset passwords for any potentially compromised user accounts.

### Long-term Strategies
- Implement advanced email filtering and URL reputation checks to detect and block similar phishing attempts in the future.
- Conduct regular security awareness training for employees to help them identify and report suspicious emails.
- Share the details of this phishing attack, including the IOCs, with your organization's security team and relevant threat intelligence sharing platforms.

---
## Tools Used
- `Thunderbird` 
- `VirusTotal`
- `Symantec SiteReview`
- `URLScan.io`
- `AbuseIPDB`
- `URL2PNG`
- `Whois.domaintools`
