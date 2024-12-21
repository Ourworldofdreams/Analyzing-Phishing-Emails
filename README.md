# Phishing-Pot: A Series of Phishing Email Analyses

---

# **The Phishing Analysis Labs**  
*A showcase of phishing email investigations demonstrating analytical and technical expertise.*

## **Overview**  
This repository is a collection of phishing email analyses I’ve conducted to demonstrate my experience in identifying and dissecting email-based threats. Each case study reflects my ability to investigate phishing campaigns, uncover Indicators of Compromise (IOCs), and recommend actionable defenses.  

The work highlights my skills in email header analysis, content forensics, and understanding phishing techniques, making it a portfolio I can speak to during interviews or discussions about my experience.

---

## **What’s Included?**  
Each analysis includes:  
1. **Email Header Analysis:** Details about sender information, email authentication, and signs of spoofing.  
2. **Content Analysis:** Examination of phishing tactics, social engineering methods, and intended outcomes.  
3. **Link/URL Investigation:** A dive into malicious links and their behaviors.  
4. **Indicators of Compromise (IOCs):** A summary of malicious email addresses, IPs, and URLs.  
5. **Mitigation Recommendations:** Steps to prevent and respond to similar attacks.

---

## **Why This Matters**  
Phishing remains one of the most common and effective attack methods. This repository reflects my ability to analyze these threats in-depth, demonstrate a proactive approach to identifying risks, and recommend mitigations. It showcases my ability to think critically, apply technical skills, and communicate findings effectively.

---

# **`1 Sweepstakes-Cookware`**

![Screenshot](https://github.com/user-attachments/assets/006d15ca-ec0c-4eda-b5ac-2dc87d6b1cf3)

---

## **Objective**

This report provides a detailed analysis of a phishing email that claimed the recipient had won a "Sweepstakes Ultimate Nonstick Cookware entry." The email urged immediate action to claim the prize. The goal of this report is to identify potential security risks, indicators of compromise (IOCs), and provide actionable recommendations.

---

## **1. Header Analysis**

### **Email Metadata**
- **Date Received:** November 3, 2022  
- **From:** lfzdd@electroplan.com  
- **Reply-To:** newsletter@electroplan.com  
- **Sender IP:** 89.144.11.72  

### **Authentication Verification**
- **SPF/DKIM:** Failed  
  - The sender failed standard email authentication protocols (SPF/DKIM), indicating the email is likely spoofed.  

![Email Header Screenshot](https://github.com/user-attachments/assets/e81c4407-3f8d-4d16-9501-1b29b2bca8e9)

---

## **2. Content Analysis**

### **Email Body Characteristics**
- **Subject Line:** Re: Shipment Pending - Ultimate Nonstick Cookware  
- **Greeting Style:** Generic and impersonal; no personalization of the recipient’s name or other details.  
- **Urgency Indicators:** The email emphasized a sense of urgency, pressing the recipient to take immediate action.  
- **Offer Legitimacy:**  
  - The email claimed the recipient had won a "Sweepstakes Ultimate Nonstick Cookware entry."  
  - The offer was dubious, with no supporting context to validate its authenticity.  

### **Tactics Observed**
- **Social Engineering:** Exploits urgency and curiosity by offering a "prize" to lure recipients into clicking on potentially malicious links.  
- **Generic Messaging:** Avoids personalization, a hallmark of phishing attacks targeting a broader audience.  

---

## **3. URL Analysis**

### **Displayed vs. Actual URL**
- **Displayed URL:** The URL presented in the email was invalid, likely to obscure the malicious intent.  
- **Actual URL:** Redirected to `https://t.co/xY6w4URIzV`, which is now inaccessible.  
  - The URL likely led to a phishing site that has since been taken down.  

![URL Analysis Screenshot](https://github.com/user-attachments/assets/54b56ff5-7960-49c4-ae47-50b9b192de74)

---

## **4. Indicators of Compromise (IOCs)**

### **Key Indicators**
- **Email Address:** lfzdd@electroplan.com  
- **Reply-To Address:** newsletter@electroplan.com  
- **Sender IP Address:** 89.144.11.72  
- **Malicious URL:** https://t.co/xY6w4URIzV  

---

## **5. Risk Assessment**

This email demonstrates multiple characteristics typical of phishing attempts:
1. **Authentication Failures:** SPF/DKIM failed, suggesting spoofing.  
2. **Content Indicators:** Impersonal messaging, urgency, and a dubious offer.  
3. **Malicious URL:** Redirects to a now-inaccessible phishing site, likely designed to steal credentials or deliver malware.  

### **Risk Level:** High  
**Immediate Action Required:** Yes  

---

## **6. Recommendations**

### **Immediate Actions**
1. **Block Malicious Entities:**  
   - Add `lfzdd@electroplan.com` and `newsletter@electroplan.com` to your blocklist.  
   - Block the sender IP (`89.144.11.72`) and the URL (`https://t.co/xY6w4URIzV`) at the email gateway and firewall.  

2. **Investigate Potential Exposure:**  
   - Review logs for user interactions with this email, especially clicks on the URL.  
   - Investigate devices and accounts for signs of compromise.  

3. **Notify Affected Users:**  
   - Warn recipients about this phishing attempt and advise them to avoid interacting with similar messages.  

---

### **Long-term Strategies**
1. **User Awareness Training:**  
   - Train employees to recognize phishing indicators, such as generic greetings, urgency, and suspicious links.  
   - Conduct regular phishing simulations to test user awareness and improve detection capabilities.  

2. **Implement Enhanced Email Security Controls:**  
   - Enforce SPF, DKIM, and DMARC policies to detect and block spoofed emails.  
   - Deploy advanced email filtering tools that can identify and quarantine suspicious emails.  

3. **Leverage Threat Intelligence:**  
   - Share the IOCs with threat intelligence platforms to strengthen defenses across the cybersecurity community.  
   - Stay updated on emerging phishing tactics and incorporate them into defense strategies.  

---

### **Key Takeaways**
This phishing email leveraged social engineering and spoofed email addresses to trick recipients into engaging with a malicious link. While the phishing infrastructure has been taken down, the IOCs should be disseminated to prevent similar attacks.


---


---


---

# **`2. Apple-iCloud-Spoof`**

![Screenshot](https://github.com/user-attachments/assets/18a84093-727d-486b-a0ae-2581085fc3ed)

## **Metadata**
- **Source:** GitHub Phishing Sample Repository  
- **Threat Classification:** Phishing Attempt  

---

## **Objective**
Analyze a suspected phishing email to uncover security risks, indicators of compromise (IOCs), and potential mitigations.

---

## **1. Header Analysis**

### **Email Metadata**
- **Date Received:** 7/29/2023, 13:16  
- **Recipient:** phishing@pot  
- **From:** hello `<otto-newsletter@newsletter.otto.de>`  
- **Reply-To:** reply_to@winner-win.art  
- **Sender IP:** 80.96.157.91  

### **DNS Lookup Results**
- DNS records for `newsletter.otto.de` and `winner-win.art` do not correlate with legitimate email servers.  

![DNS Screenshot](https://github.com/user-attachments/assets/72269a0f-20bd-4a31-9ec6-35c44db10e67)

### **Authentication Verification**
- **SPF Check:** Softfail (sender not authorized by domain's SPF record).  
- **DKIM Verification:** None (message not signed).  
- **DMARC Policy:** Fail.  

![Authentication Screenshot](https://github.com/user-attachments/assets/a8646d83-df39-483b-843b-efad224fc212)

---

## **2. Content Analysis**

### **Email Body Characteristics**
- **Content-Transfer-Encoding:** 7-bit  
- **Subject:** phishing@pot, 𝕀𝕙𝕣 𝕚ℂ𝕝𝕠𝕦𝕕-𝕊𝕡𝕖𝕚𝕔𝕙𝕖𝕣 𝕚𝕤𝕥 𝕧𝕠𝕝𝕝 (Translation: *Your iCloud storage is full*)  
- **Tactics Observed:**  
  - **Impersonation:** Mimics an Apple iCloud notification.  
  - **Credential Harvesting:** Includes multiple hyperlinks designed to redirect victims to malicious websites or steal login credentials.  

---

## **3. URL Analysis**

### **Link Examination**
- **Displayed URLs:**  
  The hyperlinks are inactive, suggesting that the phishing infrastructure has been dismantled.  

![URL Screenshot](https://github.com/user-attachments/assets/0a44b1a3-9298-4e76-9f10-794bf0ced4b3)

### **URL Reputation Checks**
- **VirusTotal Status:** Malicious.  

![VirusTotal Screenshot 1](https://github.com/user-attachments/assets/3a446850-41c1-4d03-b45b-775d5adc2e7a)  
![VirusTotal Screenshot 2](https://github.com/user-attachments/assets/8bcba9e2-465c-493b-b4c9-018c00b2ab6d)

### **IP Geolocation**
- **Active IP Address:** 72.52.178.23  
  - **Country:** US  
  - **Hosting Provider:** lb01.parklogic.com  

![Geolocation Screenshot](https://github.com/user-attachments/assets/0e0d6f80-770d-454f-aa45-bccd64283aa1)

---

## **4. Indicators of Compromise (IOCs)**

### **Network Indicators**
- **Malicious URLs:**  
  - `http://bsq2.firiri.shop/V0RPUjMzbjdPeHRLVlo2RFZ4WXBqZklYbTBnY1Btc1R5aUp4cWNUMzNOUjJnNDNjUUg5NUt2U1hYQkFpYlIyVi82NHBrdDVpRnhPdG1tQWlZbWVWMUE9PQ__`  
  - `https://t.co/gDHura2rGc`  

- **IP Addresses:**  
  - 72.52.178.23  
  - 104.244.42.197  

### **Email Addresses**
- **Sender Email:** otto-newsletter@newsletter.otto.de  
- **Reply-To Address:** reply_to@winner-win.art  

### **Sender IP Address**
- 80.96.157.91  

---

## **5. Mitigation Recommendations**

### **Immediate Actions**
1. **Block Malicious Entities:**  
   - Add the identified URLs and IPs to your blocklist.  
   - Prevent any further communication to/from `winner-win.art` and `newsletter.otto.de`.  

2. **Analyze Logs:**  
   - Identify if any users interacted with the email.  
   - Investigate activities involving the IPs `72.52.178.23` and `80.96.157.91`.  

3. **Secure Potentially Affected Accounts:**  
   - Reset credentials for users who engaged with the email.  
   - Enforce multi-factor authentication (MFA) on all accounts.  

### **Long-term Strategies**
1. **Enhance Email Security Controls:**  
   - Enable strict SPF, DKIM, and DMARC enforcement.  
   - Deploy email filtering solutions with URL reputation analysis.  

2. **User Awareness Training:**  
   - Conduct phishing awareness campaigns focusing on email headers, hyperlinks, and other indicators of phishing attempts.  
   - Include real-world simulations of credential phishing attacks.  

3. **Threat Intelligence Sharing:**  
   - Share the IOC data with threat intelligence platforms (e.g., ISACs, MISP) to improve community defenses.  
   - Regularly update security tools with emerging IOCs.  

---

## **6. Conclusion**

### **Key Findings**
- This phishing campaign impersonated Apple iCloud to harvest user credentials.  
- Despite being inactive, the malicious infrastructure (domains, IPs) remains a security risk.  
- Weak email authentication checks allowed the message to bypass initial defenses.  

### **Risk Level:** High  
**Urgent Mitigation Required:** Yes  

---



---



---


# **`3. Microsoft-SignIn-Spoof`**

![Screenshot 2024-12-13 at 1 03 19 PM](https://github.com/user-attachments/assets/dd1b4f0c-63ca-4706-9358-3adcc640166a)

---

# **Phishing Email Analysis Report**

## **Metadata**
- **Source:** GitHub Phishing Sample Repository  
- **Threat Classification:** Phishing Attempt  
- **Confidence Level:** High  

---

## **Objective**
Conduct a comprehensive forensic analysis of a phishing email to identify potential security risks and indicators of compromise (IOCs).

---

## **1. Header Analysis**

### **Email Metadata**
- **Date Received:** 8/4/2023, 19:09  
- **From:** Microsoft account team `<no-reply@access-accsecurity.com>`  
- **Reply-To:** solutionteamrecognizd03@gmail.com  
- **Sender IP:** 89.144.44.4  
- **Return Path:** bounce@providentusezn.co.uk
  
![Screenshot 2024-12-13 at 1 36 39 PM](https://github.com/user-attachments/assets/ca3f9189-f031-4772-8bd3-5876d25f4428)

### **DNS Lookup Results**
- No legitimate DNS records associated with **access-accsecurity.com** or **providentusezn.co.uk**.

### **Authentication Verification**
- **SPF Check:** Failed (`protection.outlook.com` indicates `providentusezn.co.uk` does not designate permitted sender hosts).  
- **DKIM Verification:** None (message not signed).  
- **DMARC Policy:** Permanent Error (`permerror`).  

### **Action Taken by Email Gateway:** None (email bypassed authentication checks).

![Screenshot 2024-12-13 at 1 35 22 PM](https://github.com/user-attachments/assets/d09402b4-65fe-49cd-930b-677f81589914)

---

## **2. Content Analysis**

### **Email Body Characteristics**
- **Content-Transfer-Encoding:** 8-bit  
- **Subject:** Microsoft account unusual sign-in activity  
- **Observed Social Engineering Tactics:**  
  - **Brand Spoofing:** Pretends to be an official Microsoft alert.  
  - **Urgency:** Warning about unusual activity to provoke immediate action.  
  - **Action-based Engagement:** Encourages interaction via hyperlinks constructed with the `mailto:` scheme, leading to direct email replies.

### **Phishing Methodology**
- **Email Link:** Instead of redirecting to a phishing website, the attacker uses a `mailto:` link.  
  - Clicking generates a pre-filled email addressed to the attacker, with subject lines and body text designed to extract sensitive information.  
  - This tactic bypasses traditional URL analysis tools and leverages human response tendencies.

---

## **3. URL Analysis**

### **Hyperlinked URLs**
- **Displayed URLs:**  
  - `mailto:solutionteamrecognizd03@gmail.com?&cc=solutionteamrecognizd03@gmail.com&subject=unusual signin activity&body=Report The User`  
  - `mailto:solutionteamrecognizd03@gmail.com?&cc=solutionteamrecognizd03@gmail.com&Subject=Unsubscribe me`
  - 
![Screenshot 2024-12-13 at 2 48 16 PM](https://github.com/user-attachments/assets/03588fa5-f1f5-4dab-baf6-968f064a593a)

### **Action Button Behavior**
- Clicking opens the user's email client to draft a reply containing attacker-defined text.  
- **Objective:** Exploiting subsequent email interactions to collect personal or account-related data.

---

## **4. Indicators of Compromise (IOCs)**

### **Network Indicators**
- **Malicious Domains:**  
  - access-accsecurity.com  
  - providentusezn.co.uk  

- **IP Addresses:**  
  - 89.144.44.4  

---

## **5. Mitigation Recommendations**

### **Immediate Actions**
1. **Blocklist Malicious Domains and IPs:**  
   - access-accsecurity.com  
   - providentusezn.co.uk  
   - 89.144.44.4  

2. **Notify End Users:** Alert recipients to identify and delete this phishing email without interacting with it.

3. **Enhance Email Gateway Rules:**  
   - Enforce SPF, DKIM, and DMARC policies.  
   - Configure filters for `mailto:` schemes used suspiciously.  

4. **Search for Similar Threats in Environment:** Use the email metadata and IOCs to scan logs for additional signs of compromise.

### **Long-term Strategies**
1. **User Awareness Training:**  
   - Educate users on identifying phishing techniques, including `mailto:` scams.  
   - Regularly simulate phishing scenarios to assess and improve response.

2. **Strengthen Email Authentication:**  
   - Deploy and enforce strict DMARC policies.  
   - Monitor and audit email authentication reports for anomalies.

3. **Deploy Advanced Threat Detection Tools:**  
   - Utilize machine learning-based email security tools that detect patterns of social engineering.  

4. **Conduct Periodic IOC Updates:** Regularly share and update threat indicators with cybersecurity intelligence platforms.

---

## **6. Conclusion**

### **Key Findings**
- The phishing email is highly sophisticated in exploiting human trust through a brand spoofing tactic.  
- It uses `mailto:` links, a less common method, to bypass URL filtering tools.  
- Weak email authentication (SPF, DKIM, DMARC) enabled the message to pass through gateway defenses.  

### **Overall Risk Level:** High  
**Immediate Action Required:** Yes  

---

## **Suggestions for Further Analysis**
- **Inspect Network Traffic:** Verify if users interacted with the phishing email and monitor for exfiltration attempts.  
- **Check for Similar Campaigns:** Search for other phishing emails originating from the identified domains/IPs.  
- **Review Email Gateway Logs:** Ensure misconfigurations allowing unauthenticated emails are corrected.

---
## Tools Used
- `Thunderbird` 
- `VirusTotal`
- `Symantec SiteReview`
- `URLScan.io`
- `AbuseIPDB`
- `URL2PNG`
- `Whois.domaintools`
- `mha.azurewebsites.net`
- `ipinfo.io`
