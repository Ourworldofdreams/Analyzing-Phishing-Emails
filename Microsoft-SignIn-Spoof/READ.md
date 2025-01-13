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
- **Sender IP:** `89.144.44.4`  
- **Return Path:** `bounce@providentusezn.co.uk`
  
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
- **Content-Transfer-Encoding:** `8-bit`  
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
  - `access-accsecurity[.]com` 
  - `providentusezn[.]co[.]uk`  

- **IP Addresses:**  
  - `89[.]144[.]44[.]4`  

---

## **5. Mitigation Recommendations**

### **Immediate Actions**
1. **Blocklist Malicious Domains and IPs:**  
   - `access-accsecurity[.]com` 
   - `providentusezn[.]co[.]uk`  
   - `89[.]144[.]44[.]4`  

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
