# **`1 Sweepstakes-Cookware`**

![Screenshot](https://github.com/user-attachments/assets/006d15ca-ec0c-4eda-b5ac-2dc87d6b1cf3)

---

## **Objective**

This report provides a detailed analysis of a phishing email that claimed the recipient had won a "Sweepstakes Ultimate Nonstick Cookware entry." The email urged immediate action to claim the prize. The goal of this report is to identify potential security risks, indicators of compromise (IOCs), and provide actionable recommendations.

---

## **1. Header Analysis**

### **Email Metadata**
- **Date Received:** November 3, 2022  
- **From:** `lfzdd@electroplan.com` 
- **Reply-To:** `newsletter@electroplan.com`  
- **Sender IP:** `89.144.11.72`  

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
- **Actual URL:** Redirected to `hxxps://t[.]co/xY6w4URIzV`, which is now inaccessible.  
  - The URL likely led to a phishing site that has since been taken down.  

![URL Analysis Screenshot](https://github.com/user-attachments/assets/54b56ff5-7960-49c4-ae47-50b9b192de74)

---

## **4. Indicators of Compromise (IOCs)**

### **Key Indicators**
- **Email Address:** `lfzdd@electroplan.com`  
- **Reply-To Address:** `newsletter@electroplan.com` 
- **Sender IP Address:** `89.144.11.72`  
- **Malicious URL:** `hxxps://t[.]co/xY6w4URIzV`  

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
   - Add `lfzdd@electroplan[.]com` and `newsletter@electroplan[.]com` to your blocklist.  
   - Block the sender IP (`89[.]144[.]11[.]72`) and the URL (`hxxps://t[.]co/xY6w4URIzV`) at the email gateway and firewall.  

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
