# Activist Digital Security Guide: Tails OS & Beyond
**For Those Who Challenge Power**
*By Liz Howard, The Multiverse School*

---

## ⚡ Quick Start: Under Active Threat?

If you're reading this because something just happened:   

1. **Power off** all your regular devices. 
2. **Leave your phone at home** (or put in faraday bag). 
3. **Go to a public computer** (library, internet café). 
4. **Download Tails** onto USB drive. 
5. **Read the rest of this guide on Tails**. 

[Not an activist, just been compromised? You want this guide.](https://themultiverse.school/x/digital-security-reset)   

[Is it your partner or your ex? Are you in a bad situation? You want this guide.](https://themultiverse.school/x/six-roses)   

---

## 🎯 Understanding Your Threat Model

### As an Activist, You Face:  

**State-Level Surveillance:**  

- NSA/Five Eyes data collection
- Stingray/IMSI catchers at protests
- Facial recognition systems
- Social media monitoring
- Infiltration attempts
- Parallel construction (hiding surveillance sources)

**Corporate Surveillance:**  

- Private intelligence firms
- Social media scraping
- Data brokers selling your info
- Corporate security teams
- SLAPP suits using discovery

**Oppositional Groups:**  

- Doxxing campaigns
- Harassment coordination
- Physical surveillance
- Attempts to discredit
- Honeypot operations

**Your Data is Political. Protect It Accordingly.**  

---

## 🔐 Tails OS: Your Digital Panic Room

### What is Tails?

**T**he **A**mnesic **I**ncognito **L**ive **S**ystem  

- Runs entirely from USB/DVD
- Routes everything through Tor
- Leaves **zero** traces on the computer
- Forgets everything when shut down
- Includes encrypted persistent storage

### Why Tails for Activists?

- **No traces**: Boots fresh every time
- **Anti-forensics**: RAM wiped on shutdown
- **Tor by default**: All traffic anonymized
- **Portable**: Your secure system in your pocket
- **Free**: No corporate ties

---

## 📀 Phase 1: Creating Your Tails USB

### A. What You Need:

- [ ] 2 USB drives (8GB+ each)
- [ ] 1 hour of time
- [ ] A computer you can trust for initial download
- [ ] Internet connection (use public WiFi/VPN)

### B. Download & Verify Tails

**From a reasonably secure computer:**

1. **Go to** https://tails.net/install/
2. **Select your current OS** (Windows/Mac/Linux)
3. **Download Tails** (about 1.3GB)
4. **CRITICAL: Verify the download**
   - Download the signing key
   - Verify the ISO signature
   - This prevents backdoored versions

**Red Flag**: If verification fails, DO NOT proceed. Try different network/computer.

### C. Create Installation USB

#### **Method 1: From Windows**  


1. Download Etcher: https://etcher.balena.io/
2. Run Etcher
3. Select Tails ISO
4. Select first USB drive
5. Flash (takes ~10 minutes)


#### **Method 2: From Mac**  


1. Download Etcher (same as above). 
2. If blocked: System Preferences > Security > Allow. 
3. Follow same steps as Windows. 


#### **Method 3: From Linux**  


$ lsblk  
$ sudo dd if=tails.iso of=/dev/sdX bs=16M status=progress  


### D. Create Final Tails USB  

1. **Boot from first USB** (may need to change boot order)  
2. **Select "Tails" at boot menu**  
3. **Once in Tails**, use included installer  
4. **Install to second USB** with persistent storage  
5. **First USB becomes your backup**  

---

## 🛡️ Phase 2: Tails Operational Security

### A. Boot Discipline

**Every Single Time:**  

1. [ ] Remove battery from phone (or faraday bag)
2. [ ] Ensure no cameras can see screen
3. [ ] Boot Tails with network cable unplugged
4. [ ] Set admin password if needed
5. [ ] Connect to network only when ready

**Never:**  

- Boot Tails on employer's computer
- Use same USB for Tails and regular files
- Save non-encrypted files to persistent storage
- Log into personal accounts

### B. Persistent Storage Setup

**What to Store:**  

- [ ] GPG keys
- [ ] Password database (KeePassXC)
- [ ] Essential documents (encrypted)
- [ ] Tor Browser bookmarks
- [ ] Thunderbird email settings

**Create Persistent Storage:**  

1. Applications → Tails → Configure Persistent Volume
2. Choose strong passphrase (diceware method)
3. Select features to persist
4. Restart Tails
5. Unlock persistence at boot

### C. Network Security

**Tor Bridge Setup** (if Tor is blocked):  

1. Get bridges: https://bridges.torproject.org
2. Configure at Tails startup
3. Use obfs4 bridges for heavy censorship
4. Save working bridges to persistence

**MAC Address Spoofing:**  

- Enabled by default in Tails
- Changes hardware fingerprint
- May cause issues with some networks
- Can disable if necessary (decreases anonymity)

---

## 📱 Phase 3: Identity Compartmentalization

### A. The Activist Trinity

**1. Public Identity**  

- Real name activities
- Day job/school
- Normal social media
- Regular devices

**2. Activist Identity**  

- Consistent pseudonym
- Separate devices/accounts
- Public-facing organizing
- Semi-public actions

**3. Secure Identity**  

- Known only to trusted affinity group
- Tails-only access
- High-risk activities
- Never crosses streams

### B. Account Architecture

**Email Structure:**  

```
Public: firstname.lastname@gmail.com
Activist: [pseudonym]@protonmail.com
Secure: [randomstring]@tutanota.com (Tails only)
```

**Communication Channels:**  

```
Public: Regular SMS, WhatsApp
Activist: Signal, Element
Secure: Briar, SecureDrop, PGP
```

**Social Media:**  

```
Public: Normal Facebook/Twitter
Activist: Separate activist accounts
Secure: None. Ever.
```

---

## 🚨 Phase 4: Protest/Action Security

### A. Pre-Action Preparation

**Digital Preparation:**  

- [ ] Back up all devices
- [ ] Enable full-disk encryption
- [ ] Log out of all accounts
- [ ] Download offline maps
- [ ] Turn on airplane mode before leaving
- [ ] Consider leaving primary phone home

**Burner Phone Setup:**  

- [ ] Buy with cash, away from home
- [ ] Never turn on near home/work
- [ ] Use only for action coordination
- [ ] Share number only with affinity group
- [ ] Destroy after action if needed

### B. At Actions

**Device Protocol:**  

- [ ] NO PHONES, YOUR PHONE IS OUT OF YOUR BAG AND AT HOME
- [ ] Pack a digital camera
- [ ] No photos of faces without consent
- [ ] Blur faces before posting
- [ ] Strip metadata from images
- [ ] Use ObscuraCam for sensitive media

**If Arrested:**  

- [ ] "I am exercising my right to remain silent"
- [ ] "I do not consent to any searches"
- [ ] Never provide device passwords but this isn't a problem for you because you DON'T HAVE YOUR PHONE WITH YOU
- [ ] Biometrics can be compelled (use passwords) but again, you don't have your phone so no worries
- [ ] Have lawyer's number written on arm for the phone at the jail

### C. Post-Action Security

**Immediate Steps:**  

1. [ ] Get to safe location
2. [ ] Check in with legal support
3. [ ] Document any injuries/incidents
4. [ ] Back up evidence to encrypted storage
5. [ ] Debrief with trusted comrades only

**Digital Cleanup:**  

- [ ] Review all photos/videos before posting
- [ ] Delete location data
- [ ] Clear message histories
- [ ] Check for new followers/friends
- [ ] Monitor for doxxing attempts

---

## 🔍 Phase 5: Counter-Surveillance

### A. Physical Surveillance Detection

**The Four-Turn Rule:**  

1. Make four random turns
2. Anyone still behind you is following
3. Don't be obvious about checking
4. Have escape routes planned

**Digital Surveillance Indicators:**  

- Battery draining unusually fast
- Phone getting hot when idle
- Strange SMS messages
- Apps crashing repeatedly
- Unexpected reboots

### B. Infiltration Prevention

**Vetting New Members:**  

- [ ] Multiple trusted vouches
- [ ] Consistent story over time
- [ ] Gradual trust building
- [ ] Watch for fishing questions
- [ ] Trust your instincts

**Security Culture:**  

- Need-to-know basis
- No photos at meetings
- Separate planning/social spaces
- Regular security reviews
- Assume infiltration (compartmentalize)

---

## 📝 Phase 6: Documentation & Legal

### A. Evidence Collection

**Secure Documentation:**  

- [ ] Use Tails for sensitive docs
- [ ] GPG encrypt everything
- [ ] Multiple backup locations
- [ ] Consider lawyer cloud
- [ ] Dead drops for critical intel

**Chain of Custody:**  

- Date/time/location stamps
- Witness signatures
- Hash verification
- Secure storage
- Legal hold procedures

### B. Legal Preparedness

**Know Your Rights:**  

- Right to remain silent
- Right to refuse searches
- Right to leave (if not detained)
- Right to record police (varies by state)
- Right to attorney

**Legal Support Structure:**  

- [ ] National Lawyers Guild contact
- [ ] Bail fund information
- [ ] Know Your Rights training
- [ ] Jail support plan
- [ ] Power of attorney prepared

---

## 🌐 Phase 7: Advanced Techniques

### A. Air Gap Systems

**For Highest Security:**  

1. Computer never connects to internet
2. Transfer files via USB (carefully)
3. Use QR codes for small data
4. Encrypt everything
5. Physical security paramount

### B. Anonymous Communications

**Tor + VPN Layering:**  


    You → VPN → Tor → Internet (for hiding Tor use)
    You → Tor → VPN → Internet (for endpoint security)


**SecureDrop for Whistleblowing:**  

- Only access via Tails
- Follow source guidelines exactly
- Never access from work/home
- Use public WiFi
- Consider multiple hops

### C. Cryptocurrency for Activists

- Cryptocurrency focuses on transparency and traceability, it is not designed for anonymity.
- It is the easiest to monitor, and if your wallet identification is compromised, it can be used to compromise other elements
- It is the most likely thing to get you and other activists tagged. Avoid.


---

## 💪 Mental Security

### A. Sustainable Security

**Burnout is a Security Risk:**  

- Can't maintain discipline when exhausted
- More likely to make mistakes
- Paranoia increases with fatigue
- Build rest into security practice

**Community Care:**  

- [ ] Regular check-ins
- [ ] Trauma-informed support
- [ ] Know when to step back
- [ ] Share security duties
- [ ] Celebrate wins safely

### B. Threat Modeling Reality

**Most Activists Aren't Snowden:**  

- Scale security to actual risk
- Perfect security is impossible
- Focus on raising the cost
- Make surveillance expensive
- Force them to show their hand

---

## 📋 Quick Reference Cards

### Daily Practice Card

Morning:

□ Check news on Tails  
□ Review calendar for risks  
□ Verify backup status  

Active Period:

□ Compartmentalize identities  
□ Use appropriate devices  
□ Maintain situation awareness  

Evening:

□ Secure device check  
□ Review day's activities  
□ Plan tomorrow's security  


### Protest Day Card

Before:  

□ Backup everything  
□ Charge batteries  
□ Clean social media  
□ Prep burner phone  
□ Write lawyer number  

During:

□ Airplane mode  
□ Faraday when not needed  
□ No face photos  
□ Disappearing messages  
□ Stay with buddy  

After:

□ Safe location first  
□ Check in with legal  
□ Process media safely  
□ Secure debrief  
□ Monitor for threats  


---

## 🔗 Resources

### Essential Tools:

- **Checklists, always**: https://activistchecklist.org/
- **Tails**: https://tails.net
- **Signal**: https://signal.org
- **Tor Browser**: https://torproject.org
- **KeePassXC**: https://keepassxc.org
- **VeraCrypt**: https://veracrypt.fr

### Training & Support:

- **EFF Surveillance Self-Defense**: https://ssd.eff.org
- **National Lawyers Guild**: https://nlg.org
- **Riseup**: https://riseup.net
- **CrimethInc**: https://crimethinc.com
- **Sprout Distro**: https://sproutdistro.com

### Emergency Contacts:

- **NLG Hotline**: Check local chapter
- **ACLU**: 1-877-634-5454
- **EFF**: 1-815-687-2983
- **Tor Help**: help@torproject.org

---

## ✊ Remember:

> "You don't have to be perfect. You just have to be careful."

- Security is a practice, not a product
- The best security is collective
- Take care of each other
- No heroes, no martyrs
- We keep us safe
- Every empire falls

**Solidarity Forever.**

---

*For secure support: liz@themultiverse.school*  
*Private consultation: https://jitsi.themultiverse.school*

*This guide is for educational purposes. Always consult lawyers for legal advice.*

**Clear browser history. Stay dangerous. Stay safe.** 🏴
