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
- **Reply-To:** `reply_to@winner-win.art` 
- **Sender IP:** `80.96.157.91`  

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
- **Content-Transfer-Encoding:** `7-bit`  
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
- **VirusTotal Status:** `Malicious.`  

![VirusTotal Screenshot 1](https://github.com/user-attachments/assets/3a446850-41c1-4d03-b45b-775d5adc2e7a)  
![VirusTotal Screenshot 2](https://github.com/user-attachments/assets/8bcba9e2-465c-493b-b4c9-018c00b2ab6d)

### **IP Geolocation**
- **Active IP Address:** `72[.]52[.]178[.]23`  
  - **Country:** US  
  - **Hosting Provider:** `lb01.parklogic.com`  

![Geolocation Screenshot](https://github.com/user-attachments/assets/0e0d6f80-770d-454f-aa45-bccd64283aa1)

---

## **4. Indicators of Compromise (IOCs)**

### **Network Indicators**
- **Malicious URLs:**  
  - `hxxp://bsq2[.]firiri.shop/V0RPUjMzbjdPeHRLVlo2RFZ4WXBqZklYbTBnY1Btc1R5aUp4cWNUMzNOUjJnNDNjUUg5NUt2U1hYQkFpYlIyVi82NHBrdDVpRnhPdG1tQWlZbWVWMUE9PQ__`  
  - `hxxps://t[.]co/gDHura2rGc`  

- **IP Addresses:**  
  - `72[.]52[.]178[.]23`  
  - `104[.]244[.]42[.]197`  

### **Email Addresses**
- **Sender Email:** `otto-newsletter@newsletter.otto.de`  
- **Reply-To Address:** `reply_to@winner-win.art`  

### **Sender IP Address**
- `80.96.157.91`  

---

## **5. Mitigation Recommendations**

### **Immediate Actions**
1. **Block Malicious Entities:**  
   - Add the identified URLs and IPs to your blocklist.  
   - Prevent any further communication to/from `winner-win.art` and `newsletter.otto.de`.  

2. **Analyze Logs:**  
   - Identify if any users interacted with the email.  
   - Investigate activities involving the IPs `72[.]52[.]178[.]23` and `80[.]96[.]157[.]91`.  

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
