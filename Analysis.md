## Information Stealers Wall of Sheep Analysis

## Table of Contents
- [Observations](#observerations)
- [Correlations](#correlations)
    - [The 'ROBO' Gang (Formerly: Correlation 'Fire Them')](#the-robo-gang-formerly-correlation-fire-them)
    - [Hello 'JoJo'](#hello-jojo)
    - [Correlation 'Repetition Makes Perfect'](#correlation-repetition-makes-perfect)
    - [Correlation 'Impersonation'](#correlation-impersonation)
    - [Correlation 'Geo Impersonation'](#correlation-geo-impersonation)
    - [Correlation 'Compromised Accounts?'](#correlation-compromised-accounts)
    - [Correlation 'Steering Towards Arid Yandex Pastures'](#correlation-steering-towards-arid-yandex-pastures)
    - [Correlation 'Gmail Abuse'](#correlation-gmail-abuse)
    - [Correlation 'The Shifters'](#correlation-the-shifters)
    - [Correlation 'Encrypt or not to Encrypt'](#correlation-encrypt-or-not-to-encrypt)
    - [Correlation 'Why even bother?'](#correlation-why-even-bother)
    - [Correlation 'FTP vs. SMTP'](#correlation-ftp-vs-smtp)
    - [Correlation 'I Speak FTP Only'](#correlation-i-speak-ftp-only)
- [Information Stealers HTTP Panels](#information-stealers-http-panels)

## Observations

- Addition of 91 samples (MassLogger and AgentTesla) associated with the 'ROBO' Gang, which also introduced 16 new email addresses.
- Between 2020-09-06 and 2020-09-07, the 'ROBO' operators started utilization the Telegram edition of AgentTesla. Stolen data is still exfiltrated over SMTP.
- 'ROBO' gang slightly changes second stage behaviors.

### 2020-08-15

- Addition of 64 samples (MassLogger and AgentTesla) associated with the 'ROBO' Gang, which also introduced 6 new email addresses.
- A legitimate but potentially compromised account is abused in one sample for data exfiltration. See correlation [Correlation 'Compromised Accounts?'](#compromised-accounts) for more details.
- Operators occasionally change passwords of existing exfiltration accounts.

### 2020-07-15

- Addition of 59 samples (MassLogger and AgentTesla) associated with the 'ROBO' Gang, which also introduced 5 new email addresses.
- Operator under 'Geo Impersonation' starts utilizing MassLogger after more than 30 samples of AgentTesla.

### 2020-07-03

- NameCheap, Inc. (AS22612) takes the lead in network abuse over PublicDomainRegistry PDR (AS394695), which is now in the second place. However, this could be a result of data bias as a recent analysis included the addition of 65 samples associated the the 'ROBO' Gang. The 'ROBO' Gang exclusively uses NameCheap, Inc for stolen data exfiltration.
- While not surprising, the number of samples that utilize SMTPS superseded the samples that use plaintext SMTP.
- Addition of 65 samples (MassLogger and AgentTesla) associated with the 'ROBO' Gang, which also includes 7 new email addresses.

### 2020-06-03

- The 'ROBO' operators heavily utilized __MassLogger__ with over 40 samples, making it a few samples away from exceeding __HawkEye__ samples.
- The 'ROBO' operators enabled HTTP POST to __MassLogger__ /panel/upload.php, along with SMTPS exfiltration.

### 2020-05-17

- A spike in __M00nD3v__ (8 unique samples) and __MassLogger__ (15 unique samples) usage is observed due to considerable adoption by the 'ROBO' operators. The same accounts and passwords are used interchangeably between the two malware families, and changed passwords for some existing accounts. The operators also attempted to influence analysis and deflect attribution by using Chinese names or the mention of the word "china" in their accounts. Probably not a smart tactic.

### 2020-05-13

- The number of unique samples and relatively recent __MassLogger__ exceeded the number of __Phoenix__ samples. This is due to large-scale adoption of MassLogger by the operators under the 'ROBO' correlation, contributing 26 unique samples so far. With this observation, the operators are known to use AgentTesla, HawkEye, M00nD3v, and Masslogger, potentially concurrently.

### 2020-05-11

- Between 2020-05-11 and 2020-05-13, the operators under the 'ROBO' correlation started utilizing __MassLogger__ keylogger, exfiltration account and password correlation; the same accounts and passwords are observed being used with AgentTesla, HawkEye, and M00nD3v samples.

### 2020-05-7

- Between 2020-05-03 and 2020-05-07, the operator under the 'Impersonation' correlation started utilizing __MassLogger__ keylogger. 
- Between 2020-05-05 and 2020-05-08, the operator of the "__tashpita__" domain under the 'I Speak FTP Only' correlation started utilizing __MassLogger__ keylogger. The opertor in this case configured the sample for both FTP and SMTP exfiltration.

### 2020-05-01

A new keylogger known as __M00nD3v__ is introduced. This keylogger is potentially used by the same operators under the 'ROBO' correlation, based on on password analysis and correlation.

- Between 2020-04-29 and 2020-05-02, the operators under the 'ROBO' correlation starting utilizing __M00nD3v__ keylogger.

### General Observations

- Most abused network for exfiltration is ~~PublicDomainRegistry PDR (AS394695).~~ NameCheap, Inc. (AS22612), followed by PublicDomainRegistry PDR (AS394695) and then Yandex LLC (AS13238) comes in third place.
- AgentTesla is the most used information stealer.
- Operators utilize samples from different information stealer families.
- Some operators shift to utilize new keyloggers such as __M00nD3v__ and __MassLogger__ as highlighted under the 'The Shifters' correlation.
- Actors abuse Gmail for SMTP exfiltration, which provides interesting correlations as demonestrated in the "Gmail Abuse" correlation.
- Operators share passwords across multiple samples, families, and exfiltration accounts.
- Although plaintext SMTP was used for the majority of exfiltration across the families, almost all families used SMTPS for encrypted exfiltration.
- SMTP, FTP, and HTTP exfiltration was observed by some families, separately. For example, AgentTesla was observed to use SMTP, FTP and HTTP, and HawkEye was observed to use SMTP and FTP.
- Some samples employed timestopming on the compilation timestamp, some of which were static.
- Some samples used a non-standard SMTP destination port 26 as a means of evasion.
- None of the binaries was signed.

[Top](#information-stealers-wall-of-sheep-analysis)

## The 'ROBO' Gang (Formerly: Correlation 'Fire Them')

The 'ROBO' name is derived from the name the operators use to refer to themselves; the "Robot Pirates". This reference is observed in their malware distribution domains, and the webshells they employ to manage their hosted malware directories. The 'ROBO' operators maintain a very active and rapid malicious profile.

```html
<title>We are the robot pirates.We have robot functions.But we have pirate duties.</title>
```

### Statistics:

- Total Unique Samples: 538
  - MassLogger: 286
  - AgentTesla: 175
  - HawkEye: 58
  - M00nD3v: 19
- Total Unique Accounts: 94
- Total Unique Passwords: 111

### Profile:

- CVE-2017-11882 malspam, mostly in the form of .RTF and .XLS documents prepared to download the 2nd-stage payload.
- Direct malspam attachements in the form of .ZIP and .RAR archives.
- Exclusively exfiltrates stolen data to ```mail.privateemail.com``` on ```198.54.122.60``` at AS22612 Namecheap, Inc (NAMECHEAP-NET).
- Access to a wide range of commodity infromation stealers.
- Occasionally, the operators timestomp compilation times to the future.
- Setup of open directories to host 2nd-stage payloads. Open directories differ in their setup as follows:
  - One open directory hosting either a signle information stealer family or a combination of two families. For example, most recently, MassLogger and M00nD3v are hosted on the same directory.
  - Maltiple sub-directories under the same parent directory. Each sub-directory contains a single malware executable.
  - Open directories often include the WSO webshell (examples: bo.php, docb.php, note.php) to allow the operators manage their payloads.
  - More recently, an upload form (example: bo.php) was added along with a log file capturing associated errors (example: error_log).
- Sharing the same malware samples across multiple open directories. For example, the hash ```cae79bd87462cf7f5134c476db64c8c9c081d512a27936deb7cf7b507079f329``` was hosted on the following open directories:
  - ```http://anythingbilliest.com/bmink/```
  - ```http://bazzardeals.com/bano/```
- Operators occasionally change passwords of existing exfiltration accounts.
- Operators occasionally utilize GuLoader.

### Confirmed Information Stealer Families:

- AgentTesla.
- HawkEye.
- MassLogger.
- M00nD3v.

### Potential Information Stealer Families:

- NanoCore.
- Formbook.

### Significant Activities Timelines:

- Between 2020-08-16 and 2020-08-17, the operators made several noticable changes:
  - Started using shortened ```Bit.ly``` URLs to the payloads hosted on open directories.
  - Changed executable extensions from the typical .EXE to .TXT.
  - Changed executable file naming conventions from ```A-Za-z0-9{15}``` to free-form text with much shorter file names.
- Before 2020-04-29, the operators utilized HawkEye and AgentTesla. HawkEye was the predominant stealer in use.
- Between 2020-04-29 and 2020-05-02, the operators started utilizing the M00nD3v stealer.
- Between 2020-05-11 and 2020-05-13, the operators started utilizing the MassLogger stealer.
- Between 2020-05-13 and 2020-06-03, the operators massively adopted MassLogger and M00nD3v for their operations.
- Between 2020-06-01 and 2020-06-03, the operators enabled HTTP-based exfiltration in MassLogger for a specific batch of samples (Jakartta).

### Associated Open Directories:
```
http://duluran.com/site/images/screen
http://scoalalunadesus.eu/revista/pdf/doxu
http://funnelwebdesigns.com/boos
http://deltacontrol.net.pk/wp-admin/docsx
http://searisevet.com/asdmins
http://transgear.in/ssc/fada
http://transgear.in/bana/
http://ng.idiawarriorqueen.com/css/
http://yatesassociates.co.za/documentato/
http://yatesassociates.co.za/panel/login/index.php (MassLogger HTTP Panel)
http://microtechnology.hk/wapdast/
http://bazzardeals.com/cyon/
http://bazzardeals.com/bano/
http://anythingbilliest.com/bmink/
http://sadiqgill.com/assets/fonts/
http://www.evolutionpublicidad.com/wp-admin/js/bgn/
http://sandiegoseaworldtickets.com/baba/
http://s3.rokket.space/
http://cama.it/op/
http://cama.it/css/ik/
http://nakkufoodsafetyconsults.org/bkb/fa/
http://nakkufoodsafetyconsults.org/bkb/mex/
http://nakkufoodsafetyconsults.org/bkb/ef/
http://nakkufoodsafetyconsults.org/bkb/wi/
http://nakkufoodsafetyconsults.org/bkb/bo/
http://nakkufoodsafetyconsults.org/bkb/ph/
http://nakkufoodsafetyconsults.org/bkb/uz/
http://nakkufoodsafetyconsults.org/bkb/ze/
http://nakkufoodsafetyconsults.org/bkb/jo/
http://nakkufoodsafetyconsults.org/bkb/mo/
http://nakkufoodsafetyconsults.org/bkb/yg/
http://nakkufoodsafetyconsults.org/bkb/ok/
http://nakkufoodsafetyconsults.org/bkb/om/
http://nakkufoodsafetyconsults.org/bkb/ik/
http://nakkufoodsafetyconsults.org/bkb/de/
http://nakkufoodsafetyconsults.org/bkb/ch/
http://aquiferchidek.com/bo/
http://aquiferchidek.com/ch/
http://aquiferchidek.com/dj/
http://aquiferchidek.com/dr/
http://aquiferchidek.com/ef/
http://aquiferchidek.com/ff/
http://aquiferchidek.com/ik/
http://aquiferchidek.com/kro/
http://aquiferchidek.com/moo/
http://aquiferchidek.com/mt/
http://aquiferchidek.com/ok/
http://aquiferchidek.com/om/
http://aquiferchidek.com/ph/
http://aquiferchidek.com/vals/
http://dinosaurdiscovery.co.nz/dvd/bil/
http://dinosaurdiscovery.co.nz/dvd/card/
http://dinosaurdiscovery.co.nz/dvd/dj/
http://dinosaurdiscovery.co.nz/dvd/dr/
http://dinosaurdiscovery.co.nz/dvd/eba/
http://dinosaurdiscovery.co.nz/dvd/ff/
http://dinosaurdiscovery.co.nz/dvd/ik/
http://dinosaurdiscovery.co.nz/dvd/jo/
http://dinosaurdiscovery.co.nz/dvd/jp/
http://dinosaurdiscovery.co.nz/dvd/kr/
http://dinosaurdiscovery.co.nz/dvd/ok/
http://dinosaurdiscovery.co.nz/dvd/om/
http://dinosaurdiscovery.co.nz/dvd/val/
http://dinosaurdiscovery.co.nz/dvd/wi/
http://dinosaurdiscovery.co.nz/dvd/ze/
http://dinosaurdiscovery.co.nz/css/dj/
http://dinosaurdiscovery.co.nz/css/dr/
http://dinosaurdiscovery.co.nz/css/fa/
http://dinosaurdiscovery.co.nz/css/ikt/
http://dinosaurdiscovery.co.nz/css/jo/
http://dinosaurdiscovery.co.nz/css/jp/
http://dinosaurdiscovery.co.nz/css/kr/
http://dinosaurdiscovery.co.nz/css/ok/
http://dinosaurdiscovery.co.nz/css/pa/
http://dinosaurdiscovery.co.nz/css/yg/
http://dinosaurdiscovery.co.nz/wps/ok/
http://listingcyprus.com/leeds/
http://listingcyprus.com/wpcon/
http://oficnna.sytes.net/boo/
http://www.cieloabiertocasahogar.com/capenter/
```

### Analysis

The below table displays the accounts and associated passwords across multiple malware families. Accounts with more than one passwords demonstrates that the operators changed the password of the account. This means that older samples with a previous password may no longer exfiltrate stolen data. This indicates the rapid nature of these operators.

| Account                                      | Total Count | Family                                            | Count                | Passwords                                                                                                   |
|----------------------------------------------|-------------|---------------------------------------------------|----------------------|-------------------------------------------------------------------------------------------------------------|
| ```billions@cairoways.me```                  | 23          | MassLogger</br>M00nD3v</br>AgentTesla</br>HawkEye | 16</br>4</br>2</br>1 | ```Whyworry90#```</br>```MOREMONEY123```                                                                    |
| ```mpa@cairoways.me```                       | 6           | MassLogger                                        | 5                    | ```BLESSEDyear20```</br>```LifeDrama@#```</br>```NewBlessings```                                            |
| ```uz@cairoways.me```                        | 7           | MassLogger                                        | 7                    | ```pAsSword@#1```</br>```09012345@```                                                                       |
| ```admin@cairoways.me```                     | 4           | MassLogger</br>M00nD3v</br>AgentTesla             | 2</br>1</br>1        | ```requestShow@```                                                                                          |
| ```sales001@cairoways.me```                  | 3           | MassLogger</br>M00nD3v                            | 2</br>1              | ```whyworry01#```                                                                                           |
| ```info@abuodehbros.co```                    | 11          | MassLogger</br>HawkEye</br>AgentTesla             | 9</br>1</br>1        | ```@willsmith1.,```</br>```ItsTrue@123```                                                                   |
| ```sales@abuodehbros.co```                   | 10          | MassLogger</br>M00nD3v</br>AgentTesla             | 8</br>1</br>1        | ```1234567890```</br>```098765432><A@```                                                                    |
| ```finance@supreme-sg.icu```                 | 10          | MassLogger</br>M00nD3v</br>AgentTesla             | 7</br>2</br>1        | ```BIGGOD1234```</br>```biggod1234@```                                                                      |
| ```binu@metalfabme.icu```                    | 10          | MassLogger                                        | 10                   | ```@Mexico1.,```</br>```@Mexico3,.```</br>```@Brazil20,,```                                                 |
| ```bob@metalfabme.icu```                     | 8           | MassLogger</br>M00nD3v</br>AgentTesla             | 6</br>1</br>1        | ```@Mexico1.,```                                                                                            |
| ```wiz@metalfabme.icu```                     | 6           | MassLogger</br>M00nD3v</br>AgentTesla             | 4</br>1</br>1        | ```Whyworry#@```                                                                                            |
| ```huangjianping@chinacables.icu```          | 5           | MassLogger</br>M00nD3v                            | 3</br>2              | ```whyworry10902020```</br>```whyworry1090#```                                                              |
| ```charif.yassin@cronimet.me```              | 5           | HawkEye</br>AgentTesla                            | 4</br>1              | ```@mile31.,```                                                                                             |
| ```produccion@servalec-com.me```             | 5           | HawkEye                                           | 5                    | ```@bongo1.,```</br>```biggod1234```</br>```BIGgod1234```                                                   |
| ```success@poylone.com```                    | 5           | HawkEye                                           | 5                    | ```@qwerty12345```                                                                                          |
| ```lchandra@bazciproduct.com```              | 20          | MassLogger</br>AgentTesla                         | 16</br>4             | ```Mariodavid89```</br>```whywori#@#```</br>```Nolies99```                                                  |
| ```info23@huatengaccessfloor.icu```          | 5           | MassLogger                                        | 5                    | ```1234567890```</br>```1234567891```                                                                       |
| ```imports@eastendfood-uk.icu```             | 5           | HawkEye                                           | 5                    | ```GGASDXZAFCVB65```</br>```GodGrace6665555```                                                              |
| ```admin@bazciproduct.com```                 | 13          | MassLogger</br>AgentTesla                         | 9</br>4              | ```@123098#```</br>```whyworry123@```</br>```Try1234567@.,```                                               |
| ```ampall@ampail.com```                      | 20          | MassLogger</br>M00nD3v</br>AgentTesla             | 12</br>7</br>1       | ```123098322@#```                                                                                           |
| ```wetground@poylone.com```                  | 4           | HawkEye                                           | 4                    | ```@qwerty12345```                                                                                          |
| ```gavin@jandregon.com```                    | 4           | HawkEye</br>AgentTesla                            | 3</br>1              | ```WHYworry??#```                                                                                           |
| ```docs@hdtrans.me```                        | 9           | MassLogger</br>M00nD3v</br>AgentTesla             | 7</br>1</br>1        | ```@A120741#```                                                                                             |
| ```rfy_sales806@dgrrfy.com```                | 4           | MassLogger                                        | 4                    | ```biggod1234@```                                                                                           |
| ```inkyu@dubhe-kr.icu```                     | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```SometimesINLIFE@```                                                                                      |
| ```m.gorecka@criiteo.com```                  | 9           | MassLogger</br>M00nD3v</br>AgentTesla             | 7</br>1</br>1        | ```efforting@```                                                                                            |
| ```gestionesolleciti@pec-warrantgroup.icu``` | 5           | MassLogger                                        | 5                    | ```NoisyGeneration#@```                                                                                     |
| ```panos@skepsis-sg.icu```                   | 3           | HawkEye                                           | 3                    | ```breakinglimit@```</br>```@Bongo1.,```                                                                    |
| ```ikuku@poylone.com```                      | 3           | AgentTesla</br>HawkEye                            | 3</br>1              | ```BLESSEDchild@```</br>```GODhelpme@#```</br>```GodAbegOo#```</br>```HELPmeLORD@```                        |
| ```yosra.gamal@csatolin.com```               | 3           | HawkEye</br>AgentTesla                            | 2</br>1              | ```HELPmeLORD@```</br>```@Mexico1.,```                                                                      |
| ```justin@allaceautoparts.me```              | 9           | MassLogger</br>AgentTesla                         | 8</br>1              | ```HelpMELord@#```</br>```NewBlessings@```</br>```GODABEG@```</br>```OneDay@time```</br>```TESTIMONY@123``` |
| ```dcaicedo@igihm.icu```                     | 3           | AgentTesla</br>HawkEye                            | 2</br>1              | ```MOREMONEY123```</br>```STAYSAFE123```                                                                    |
| ```imports@techin.icu```                     | 5           | MassLogger</br>M00nD3v                            | 4</br>1              | ```biggod12345```</br>```1234567890```</br>```MoreGrace@#```                                                |
| ```jplunkett@bellfilght.com```               | 3           | AgentTesla</br>HawkEye                            | 2</br>1              | ```biggod12345@```                                                                                          |
| ```xu@weifeng-fulton.com```                  | 3           | HawkEye                                           | 3                    | ```@bongo1.,```                                                                                             |
| ```jasmine@cinco.icu```                      | 3           | HawkEye                                           | 3                    | ```Biggod1234```</br>```biggod1234```                                                                       |
| ```s.ewaldt@otv-international.me```          | 2           | MassLogger</br>M00nD3v                            | 1</br>1              | ```1234567890```                                                                                            |
| ```jamit@cairoways.icu```                    | 2           | HawkEye                                           | 2                    | ```breakinglimit100%```                                                                                     |
| ```yg@cairoways.icu```                       | 1           | HawkEye                                           | 2                    | ```ygsus2020```                                                                                             |
| ```stephanie.giet@technsiem.com```           | 2           | HawkEye</br>AgentTesla                            | 1</br>1              | ```Whyworry90#```                                                                                           |
| ```service@ptocs.xyz```                      | 2           | HawkEye                                           | 2                    | ```bigGod1234@```                                                                                           |
| ```sales@americantrevalerinc.com```          | 8           | MassLogger                                        | 8                    | ```1q2w3e4r5t```</br>```Silence1234@```                                                                     |
| ```info@americantrevalerinc.com```           | 8           | MassLogger</br>AgentTesla                         | 7</br>1              | ```1q2w3e4r5t```                                                                                            |
| ```accounting@americantrevalerinc.com```     | 11          | MassLogger                                        | 11                   | ```1q2w3e4r5t```</br>```JULYwillBeGOOD@```                                                                  |
| ```works@americantrevalerinc.com```          | 11          | MassLogger</br>AgentTesla                         | 10</br>1             | ```1q2w3e4r```                                                                                              |
| ```supplier@americantrevalerinc.com```       | 13          | MassLogger</br>AgentTesla                         | 10</br>3             | ```1q2w3e4r```</br>```1q2w3e4```</br>```1q2w3e4x```</br>```1q2w3e4xx```                                     |
| ```doreen.muhebwa@microhaem-ug.co```         | 1           | HawkEye                                           | 1                    | ```1234567890```                                                                                            |
| ```accounts@friendships-ke.icu```            | 1           | HawkEye                                           | 1                    | ```INGODWETRUST```                                                                                          |
| ```info@friendships-ke.icu```                | 1           | HawkEye                                           | 1                    | ```@bongo1.,```                                                                                             |
| ```ahmadi@gheytarencarpet.com```             | 1           | HawkEye                                           | 1                    | ```Focus$Pray```                                                                                            |
| ```parisa@abarsiava.com```                   | 1           | HawkEye                                           | 1                    | ```@Mexico1.,```                                                                                            |
| ```sav@emeco.icu```                          | 1           | HawkEye                                           | 1                    | ```GodsPlan@#```                                                                                            |
| ```raphael@gitggn.com```                     | 1           | HawkEye                                           | 1                    | ```@mexico1.,```                                                                                            |
| ```v.clemens@slee-de.me```                   | 1           | HawkEye                                           | 1                    | ```@mexicod1.,```                                                                                           |
| ```tina.meng@wingsun-chine.com```            | 1           | MassLogger                                        | 1                    | ```@Mexico1.,```                                                                                            |
| ```candolkar.p@tecnicasreunidas-es.co```     | 7           | MassLogger</br>AgentTesla                         | 6</br>1              | ```@Mexico1.,```</br>```BILLIONLOGS123```                                                                   |
| ```sale@somakinya.com```                     | 1           | HawkEye                                           | 1                    | ```Wenenighty.,```                                                                                          |
| ```valentina.marangon@gruppodigitouch.me```  | 5           | MassLogger                                        | 5                    | ```NEWways@```                                                                                              |
| ```contact@assocham.icu```                   | 1           | HawkEye                                           | 1                    | ```GODSGRACE123```                                                                                          |
| ```g.cavitelli@sicim.icu```                  | 3           | MassLogger</br>AgentTesla                         | 2</br>1              | ```@Mexico1.,```                                                                                            |
| ```crm.sal@suprajit.me```                    | 6           | MassLogger</br>AgentTesla                         | 4</br>2              | ```@Mexico1.,```</br>```LongJohn@123```</br>```Remember@123#```                                             |
| ```christian.ferretti@fox-it.me```           | 16          | MassLogger</br>AgentTesla                         | 10</br>6             | ```@Mexico1.,```</br>```biggod1234```</br>```Biggod1234```                                                  |
| ```albanello.n@latrivenetecavi.com```        | 13          | MassLogger</br>AgentTesla                         | 10</br>3             | ```JulyBeGREAT@```                                                                                          |
| ```celal@lidyatriko-com.me```                | 5           | MassLogger                                        | 4                    | ```Tomorrow@1234#```                                                                                        |
| ```a.elayan@abuodahbros.com```               | 1           | MassLogger                                        | 1                    | ```@Mexico1.,```                                                                                            |
| ```caglar@lidyatriko-com.me```               | 5           | MassLogger                                        | 4                    | ```O1212@3213#```                                                                                           |
| ```wintom@wls-com.me```                      | 4           | MassLogger                                        | 4                    | ```TryAgain@123```                                                                                          |
| ```samco@farm-com.me```                      | 4           | MassLogger                                        | 4                    | ```whyworry@123```                                                                                          |
| ```g.oikonomopoulos@kordelos-gr.co```        | 8           | MassLogger</br>AgentTesla                         | 5</br>3              | ```@Mexico1.,```                                                                                            |
| ```export@bristol-fire.co```                 | 4           | MassLogger</br>AgentTesla                         | 3</br>1              | ```@Mexico1.,```</br>```@Mexico111.```                                                                      |
| ```fti@alltoplighting.icu```                 | 10          | AgentTesla</br>MassLogger                         | 9</br>1              | ```NewFlames@123```                                                                                         |
| ```omar.alhomsi@gpgolbal.com```              | 4           | AgentTesla</br>MassLogger                         | 3</br>1              | ```BlessedAUgust@123```                                                                                     |
| ```hany_henien@spppumps.co```                | 6           | AgentTesla</br>MassLogger                         | 5</br>1              | ```AugustBlessings@```</br>```newpassword123```                                                             |
| ```accountant@medoermw.org```                | 13          | AgentTesla</br>MassLogger                         | 10</br>3              | ```BlessedAugust@```</br>```1qa2ws3ed```</br>```NeverGiveUp@123```</br>```SeptemberBlessings@```           |
| ```binu@metalfabne.com```                    | 5           | AgentTesla</br>MassLogger                         | 3</br>2              | ```NewAugust1303@```                                                                                        |
| ```zaid.alyusuf@gpgolbal.com```              | 3           | AgentTesla</br>MassLogger                         | 2</br>1              | ```Newest@1234#```                                                                                          |
| ```director@medormw.org```                   | 7           | AgentTesla                                        | 7                    | ```@Mexico1.,```</br>```bigGod1234```                                                                       |
| ```hgalvan@vacontgo.com```                   | 6           | AgentTesla                                        | 6                    | ```@Mexico1.,```</br>```BurgerKings123@```                                                                  |
| ```kathrin.comanns@medoer.me```              | 4           | AgentTesla                                        | 4                    | ```@Mexico1.,```                                                                                            |
| ```stu@frescnoy.com```                       | 9           | AgentTesla</br>MassLogger                         | 8</br>1              | ```@Mexico1.,```</br>```@Mexico120.,```                                                                     |
| ```hussam.odeh@temico-mep.com```             | 8           | AgentTesla</br>MassLogger                         | 7</br>1              | ```@Mexico1.,```</br>```@Mexico1.```                                                                        |
| ```smita.pagade@a1fencesproducts.com```      | 8           | AgentTesla</br>MassLogger                         | 7</br>1              | ```@Mexico1.,```</br>```SURELOGS123456```</br>```BLOCKLOGS123```                                            |
| ```safety@rayanetech.com```                  | 4           | AgentTesla</br>MassLogger                         | 3</br>1              | ```Dedication100%```                                                                                        |
| ```frankvanderloop@swannberg.com```          | 5           | AgentTesla                                        | 5                    | ```Figuring@123```                                                                                          |
| ```sales1@razorwirefecning.com```            | 2           | AgentTesla                                        | 2                    | ```Biggod1234```                                                                                            |
| ```phyno@obazolu-ovim.pw```                  | 7           | AgentTesla                                        | 7                    | ```Blessings@12345```                                                                                       |
| ```challa@obazolu-ovim.pw```                 | 7           | AgentTesla</br>MassLogger                         | 5</br>1              | ```@Mexico1.,```                                                                                            |
| ```olmx@obazolu-ovim.pw```                   | 1           | AgentTesla                                        | 1                    | ```whyworry.,```                                                                                            |
| ```zeco@obazolu-ovim.pw```                   | 5           | AgentTesla                                        | 5                    | ```Remember@123```</br>```BigGod1234@```                                                                    |
| ```uz@obazolu-ovim.pw```                     | 3           | AgentTesla                                        | 3                    | ```LifeDrama@123```                                                                                         |
| ```jojo@obazolu-ovim.pw```                   | 2           | AgentTesla                                        | 2                    | ```Remember@123```                                                                                          |
| ```s.terasa@shibata-fenderteam.team```       | 1           | AgentTesla                                        | 1                    | ```WORKharder@123```                                                                                        |
| ```caglar@lidyatriko-tr.pw```                | 2           | AgentTesla                                        | 2                    | ```1234567890```                                                                                            |
| ```olamx@obazolu-ovim.pw```                  | 3           | AgentTesla                                        | 3                    | ```NewSeason@123```</br>```Miracle@123.,```                                                                 |


An interesting systematic anomaly associted with these operators is a set of 18 unique samples, which can be divided into two groups based on the domain name used in the accounts.

| Account                                      | Count | Family     | Passwords                                                                            |
|----------------------------------------------|-------|------------|--------------------------------------------------------------------------------------|
| ```obuman@akonuchenwam.org```</br>```obino@akonuchenwam.org```</br>```nednwoko@akonuchenwam.org```</br>```mobite@akonuchenwam.org```</br>```martinze@akonuchenwam.org```</br>```manman@akonuchenwam.org```</br>```dogman@akonuchenwam.org```</br>```abu@akonuchenwam.org```</br>```aboyo@akonuchenwam.org``` | 1</br>1</br>1</br>1</br>1</br>1</br>1</br>1</br>1     | MassLogger | ```(SLYNY(3```</br>```)^nveCU9```</br>```H*XyvM)5```</br>```HaLzYAY8```</br>```QMvStW^7```</br>```dho)YOW7```</br>```fySnrmX9```</br>```i^*Moaf0```</br>```mMtRZHe4``` |
| ```smithyjazz@jakartta.xyz```</br>```obuzsolidcash@jakartta.xyz```</br>```obielvosky@jakartta.xyz```</br>```nednwokoro@jakartta.xyz```</br>```mobiteeuro@jakartta.xyz```</br>```martinez@jakartta.xyz```</br>```manofficialbless@jakartta.xyz```</br>```dogdollars@jakartta.xyz```</br>```aboyo@jakartta.x``` | 1</br>1</br>1</br>1</br>1</br>1</br>1</br>1</br>1 | MassLogger | ```anosky90```</br>```bobby654```</br>```chuksweeda345```</br>```dandollars45```</br>```ginger31```</br>```moneyguy76```</br>```nwaotu65```</br>```odenigbo090```</br>```winnerq1``` |

Hashes

```
001b14d21f1f99aae9ae6b365482be3cd75568e33a8af6aba36d148129ac19dc
0088497f4ffbdf48b4b5401503a8960b7bf493e3e0ac574c6ade1695520300f9
01163e556055d4918fe33453f3aff7ca3074da1e887492c418c1f5298c691c42
015da4d338b5ccb6a5ae37b29a30bdd80445280746011616535a26c60b4be0bb
018d4e9e4a4a7324f21cf782de5d92e9cc975b350955588444752220aa86be04
02bb0ff54a31436e39c168c4e55237aeb972098a8da8e83eb1cbc99796a60394
033cccd5c1d6affd3269077550ba942b144fe64092c83e8c1a70ab06468206a7
034b8adea4ddcae055c94f0d0af361bb2e5dbe02047db9371fe0d2c189adcdef
03689c10f765e2b86440c6463e0af8da0aa5d4d46987ee86f1787c53cc678667
03968a3a5a7a880feefca31686fcfbed445080a0c06eda2b6d623757179b782c
03beb3f3181673b3c770ef7a42fa96c13c3c1b554e77885b0c2817fcbab01299
040e25260744568a97c4fab438098f03718eaee0604a22dfe5138b73578815e0
05e415b37da05805bd1057a69697f89e1766eb91dd632bf672125f37563c49d0
0689a40d09b9c6583ebae454722ec51c981866449edc13c4dd452d883da1d0a4
0698a437f4269ff030ed8c4e3bf8cc43e608cfa0768c710be3eb4dea2a348ecd
069f0dc72189e7faf5278aabd6ba9f53c386023f9d7d8ab863896e43f6a4e456
0722cedd5a2e4a5a4c94ac988f14800a6a83a8c7147f7ef52b47ae86571384e2
07236ee497bab6187ef9e5ea42f6a184a9bb32030b50d88f251a449b03890305
07426d1fa6cc07107277cedeb0ed843fba44a79bf71fd228b3e74b5aaa5b9e4b
07660fce0eb3a6f3f5036f2059a52ccb2e8e83f77a2f584d9392ad06fbf5a4e0
07c9af002dada0fa94d5d754cfd7453447b073e8e6cb9dfac6139b0afe0ec820
083c70afde1be48426ebcf28eacfa0cd47f96130790b79f5a367ae6b00eab142
093021d7dfcac2a0fb28007f98413ab66df6efd8b942571dff1198a5587c8807
0981eed2da1ddb0d93b002274bb01aa64a44a7af785c36b4bf66f21f7ba882b3
09d83ebdd5d99fe1373d3b30798800503a4c625884b1c1e3f4e190d7b4d0d9da
09fb066f4a5fbc57b4d592a8443151578605c8a573746c3989a79bd1fa28c3a2
0a375c52851b79c5d3be0d18025940bee5f68501c8e18334264f116775e57fa7
0a3f320d6e46c364aae4b55f4853d8aff3d6a9d6117cb176b957c298e9184f29
0a699d50cee9fc3eb46b0703c5502a84fbb357757853e25474683baf8f477fe0
0a7104481d9a86895362b28a49420c90427054217fd82ba9a5ebbb2a086e61a2
0a94abe0f8204402f8b82fd6e669e614f9d5818d2ccdf4bde959ab46decab453
0ac30990fdf9e06367b60690e98803de01f668f8bc6b76c673a9295acb435d16
0b8fa34b4f6551d824d43170aaf8f4a1f7771eb9af4728a508058cfda9907908
0b984d3e8a150589d7f295c6009cd856e360e44f6fe5729e18e4759536a9bd0e
0c2cc0b045d670852f628dad967894fa549de4a3dca0fd13ac5e9307a5b262a6
0d0a6d8809b9005e1e299d09c2ee38afdac93923f055db410f2923757d5654d4
0d4d3af44ed0aa3154be8537fa238439090826f9f5cc264b967e60699f0e9d4a
0e0fa75f23c79bd32ca3074a58f1ab912fef14b9712f682858148409ba972e7c
0ea5d6d7d7e520a61a396c77d166dd1cb34cde965d3788430c3484a616381c74
0f22bd1e202b2fa87adfca75ca61405ac232863a75ab7b5a71a69c3b7c22e7b1
0f589bd3c4bfdf1301a52c6b4b9f9202ab61131bb7230f4e91767b28894005b2
0f7facae07fd7efc8eb9a2b6916eb8d912fe48d3a74a9629d110856df8144a65
0f831f1d2ec54e999f14a8ef2d7f38c9fdc69670f67e55c71d9f0b7bd808fc74
0fe1edf57a62d9ace0b66f272e07ef2799a89e740a487126e1d6c5303d0913b3
0ffa7ac2091ab004e6755e1e66539633b6a628e90094d80357895df0e6092f9c
0ffe5ec768100c95dff7a6546a52e86ca14560a4810aa32bc2530ae50be27926
100d49a60d58afddbae6019095628a64e9d4fb798637d277f25c52759123e80a
10201612955aa877dffc88d0841aa1e977ca670329b0d9bb7d193b11975590f1
102ead28aad11640f46d42f5c7e94f15202ca38562de8c37a3bfbd6cb7ad12dd
10a7dd514bbfa4bd8aa3358f4330cdebc3b59658b865c66692dc66d680f1c658
10b2155331d3b0c7934808e52084c3911f82ece51f39836e3ef0e8db39ee9904
10c341f03698c730a4591d844c0d563f19e4a6b87934b45ff0447bd57808bb32
10e38bdb1a32d7a54e877e6404fa4882b0049e2ee87b1558470b19eded1f4376
1146e4d995c67932f70852ddd73410efbf0ecfbe227fa9834ec7dfea12cb6097
11855a5df64ad4ecfc2093fdcf973313404d21cd8f9198f622fd3c16d4c1b2d1
11b4c682e2712b0c6516b3800b48afb967015dae3b4a06307281539d691aee86
11bb68ef26d8625de7a87c9f3e9c9987da9f47b38b37938d71e72ab0be74781b
11bce12697f89b9a32e331d3d37a9f478df1e43015bb9a10cb7243ab1df10b72
12129dd02feff5bdfc7b2cc1832cb68efd8a2d8caeb528d82919e55c2178dc76
122d3657eca3ae04fe7072488f6b1c1cde4225462792a5466729867437003e2d
123e6cc577073220e3cb0b7a04f64af72321ae438bbbe492af90fd83c3e68edd
12c7ff58c14c67fa84752c1b136860c7c621ccf8cd947183f6b1c918b4c8c737
12f4c1a3c604546b294d2b51461229b21c86bfbfd2e8bbd040e36a411f17f32f
131bfb49b5d80492ddcab3ec34448a445806e0c992c96eca65d42311539defe6
136f1283c0c4ff708b52d89febb3a3f457247ecbe56d22868f5bdeea60158b8c
1379e36644ac0f28d83c4c8b502d96cac61961cf6835c1e11ce214c270320d38
1440ef576d0b002306600b414a15fe71fed7658b107683882b0339cc4a82a182
16d7ba996c924f71b9bec979109680f9137df4184ae69f164efce56c89000ae1
175f436a3075c4016faad4907b7fa86c0f34851ea7ec4ce0210fb1e377258aa2
1778b4170b77273169de41fc982bf9da4f675504f7aee4011aad350ba8af9072
181c9610626543c859424ae029daa9f2d17b48040e65c31d61c71d0213d269b4
1893c6a575128c947c2edb3771a87d16710d0b84c503bf0057be1f0be8fc5660
18df5b401017096d9bf5ee692ef5a4e261d5b8f349e7d6375fd38b4289733880
190da594cc201729fac0e71816274b00681b1d8720e60569c380625e5d69f643
1947b2ed119c74a87843dc49522939e178658cb768b00948ed1cd2b28b2479ea
19acd39592c857d2605521e17b61a6ce3f2b5c6d34a3a05ea8ea4d312d37091f
1a2be296b5cf4de54249a1c3a2f8ed739761ba73b1e72478407691b4722d7760
1a99e83fdf9e80eb51d0ee8857632a895e5e7715ea435ead572e23fa1f7f191c
1c0f051f220cce0652e12b02db69ba02ffae1d80409cc26c4bda3273cfe3ac97
1d72dcb3abbfac1e2f0970832958bc2c2dac25d9b869b28f6dddb5fec0d45e7f
1db65284dd73545215b9db3834b16709bf5bf5c33a417c38a205d09317cd6d0d
1deb686853276fbf2eff61acfd8340b56d710d0235f69f56ad45831253400eb4
1e5a3425debcf82d2c5bf95ae4aaabb84280402b98accc2cefa6145217093ab1
1e77cb21a9502624a6eb8dfdaf24b7f5643ef979e72df397335a8f7067c010c8
1f14007ec260152c94553054b6d0a40aeba9acbfbb7f2589ca3501106726b26e
21f06bdd31079577aef18ceb3f3333dbcfa79fbd716df5bfca457f3303f98e9f
239a40118ca9473eb4be7f1bcf0fbb00c93b7213926402d93074b2252bc72092
239fca3f5df496aab1b7c7696aaa26d77174501abc9cb1c1e12a188584d745cc
241e1a8dfb8e9fa46e86da847c315e40bcb32952f0ffea5e27cb8390d367c4db
2530df4015014e80e6fe59efc45a03f4692a80027d78eec4e1390c5f5da65576
258970d034e0216fb43795b398996dad9542e23894dd3c31a886402b5ab6d438
281f03eeead5e40ac1b27a1c972eaea91604d8ac011728413e4e401c92ab20ae
2955a7a28f30466bfb49c60ab10c2cd14f53a4456e4b6d456c976ac088f3f942
2978aabe9e13034efa30336c2a013714a9166bd482df569d5081d70a18c22a28
2bfd2788208bebdbd027bfb1220e27b8283198e5b6f05e3e09b1fad2c8b29c8e
2c8da0da6cbab2366291deabbb773bec304a9e49c87982a04d6ee33c712cd642
2d6b00e9396cb0ec14f3ce3757cc6c375a429c71fc0142dab03d3df2df7a0fd0
2e2e578826bd54a79a4a687ba2f534a4075af5e77cc1349fb0094ef1051b7307
2e5c6ecfef94f9922f152344b96041b85bf2dc01136e921e2d8c644d903b708d
2f03330687eb31f3d4f69af9c7b69223cb1fad0f9889ec79d6c65a5cab66bd84
307c775ae016fcd48f7811b312bcb4caea0b9a49f88da110e29afc0b80b6da22
30aa96552ed6d03af50adcf6557a6ec3c3cb54f78fc50ee822d6d3c2bf70f9bc
31a01efe3d5484cb4f2b635c841b493fd4d9bb819457d7471135bf640d85c1ae
31db019368c71ce1ae360fccb5e4bdb511b289f5815eb74be72fc39ef49f03d2
32055b2d52f63c415e84a3b6552b02e2773ac7939674a242b4856ff441f1adbe
3266447fc385372c0f4a5755fe396483b3856949980607ba9022598ebd82b8dd
32d271b7df9a7bd3cae2b2d7a9db56c287ede67b2ad537d1eb41701f62c3323a
33bbefb4d3bb2a66e713a55da6b852df10241fb371ebda3e5a39a761bacca0b3
3468b520ec611e72cc9cf84c15ba791b9dd4008a2766d7ce680fe5df0bdbac35
34eccafed560dec2809962627f9ca39998d062da88960e3f5c4e2c6397a238d9
3583f9dff6cb8c89815c821887873bbe19818a2c32c2580fb7dfdf35cc035eba
35cca711eeab74520897fa7d78a5228861e9eb0bd2f66e1aa3810784acf4f11c
35fed9b0364151ec00d8084a6189b22562cfc369fec2cc2416a08043797b1c64
365759dd03965a10bfb50c17454055b0272a0cf33b78aa78441ab6cc996e1090
37d6c01052425e77d38007224ac22921f1003ee757a8642d73e615ae0fdff254
3813efe9956fc0404d007a6d1a72c54f5db75470f36f4718c7a51d872826a13e
38a02e9cd2b875bee8e55377cbdb1905b7d07955713e4ffc20544d01a9cbe4f1
39b1f53d978ec28d01954e7fb10b3350cb4e18e3916296e1e364528c55b0ca7a
39de600aad05bc163c24425ed108854d5a0857e9dbe9b0f021e793ac058d1001
39f0a33dbcd8b68eb965d0149d744ec9a4e2028840b967c6cf47e3081e07d460
3a2adcac20af82cdb882ab9bd9a1a78ca30f833a488cd13a55daf8ff743271a3
3a770ad08848493bcd756afcfd27a79bc89962fb0caf2cd173892de3eaffaa83
3b2c7d8af6f1b0cadbc8708e909108333483f2550931c8fd90b1ffeea0df82d3
3b6093cef0c74b2e0f59ec4bf653b07fd160afb38076a4cde81bb3ebff4a055a
3b75cbcad5615d88443317f9ccfb93a6292835db6e8a4e1f3a11bf5dc1e0eaae
3b788ad21e6bb8e9c068488f1670c500be46802b0bdc5c475df2503220cccb07
3bc9dc7b317b7c89f28895842d68dbd314d89172d5775caad38a500cfdb27af1
3c75c540ea636d898b645dc6bbcda3568200ddd20810ab65d7b2dc0b5e01e3b1
3c969bc65ce904a957ad469246cd3e3642c881fc128b5b389e1e3195acc16f20
3d4f85aa3d78db4a67194188821fa0f6993d66b308a70c67e2bb052fe59d1f2c
3e52c8da33ee1aabec29afa3ac69f591dbca78a62a01128265963e53004a2ef3
3e6a911c8f2229431d131898a2fb046a6bae8267263a451baf93ec919d61afbd
3e7cdf6f1d6dc5c92bd31fdd89f9259baadcd4b9fa87894dbc7706f246619387
3e9bfda37753fa3bad481e1b56390fdac14c791f4a42847c04bb340a3eb8b0d5
3eb85214c777bc9b173684ee6cf0de3c415bff66e06bb0d96e11937509aee552
40d9a35d8be98dc4fb9e087c2e6ce8a5243b8bf26d4537c87768302f6b69d7c5
413d695486590ec17e4f0c2aa5123ef9c0b2ef80acfbf49ed7e2040b20d5925b
418c8e44fdc405ae7502e488f981529d7c2d834052816b34b25501d7f4a2b5c5
419d14b7d31b5d505c4a67a157454756b43697e1156a1181b8e431cad3d2106f
426110407bdba9dfe5a4f6d39d6369c8baf47008d7738765c3eb7d1ee62e3344
4270244e30ff3c565651ea2907401210355f0e0da471a9053e42aefd64488031
4308234f18880f2b6ba5023f8870147f5c7888ff1ebf418930b18854aac069b4
438b22a51b7bf77785d93d3ace1951b5b492e0b12e145178a24c5b80db9fb573
444aa203d5c61f2399aadee4715eeeab261fc56653eadd4c2aa34951f3a10d93
445ea09038d195e3bc4c27b26b4824c3581e8c6b57ac747833195d2b740c82c7
44cb5c96839eb04d707e50561a1b36fbc9b19722536275a06c32695e92bf90ec
4506fe045a37e1cf9a8642116813005cf649d3c54cc1171850583fc7a699497f
4593a512ed7dabb6be349fc4bab80909c998261426560fc851c8ceb157446e3d
45b9c054a02686f4a3187cff823fd195742de5b467f89c883ecf4feb45f83f0f
45ef1e51df38e6778aaf2cd726748b55459b4aa54a2c8c2fea445cab0885f7bc
463a59391f58c400a2daeb7da076b468be31e6dc6c61b4cfe8d257381885a787
47799b4853ffa2cb541f153f0b50fc335324a5964e04093a8316d4a62eacc8f1
47a55c0d4e6ae1ac8687f03ebdd02d79246e67ab7212d6ff9508e72183edc7c2
48d9cb77f8ed388bfccf2d12b6f10f60c69d14b8559f5d545d31e443635e465f
49dfc132c775f1a276c3c401c1258b354e78032ba77e85660d4c55a71f8f8197
4bd55192d3aa9630c8c34791ed8113087fbfa8e3e074a1e2d0304120eb19a224
4bf7de683b35ceea765ff609bbf7f161c62adf581b14d3222e8ccde251bb743e
4cca5e53350f2adb11cf4eb202ec7a994631014325e5bed0d040f564737eb38e
4cea65512dbdf77377eb95df694165cfdfd47a190efc64c7ebf3947415a8c08b
4d26f9475847da9db8be0d1a5553a15bd6473f3104008a3919c6b417f50c53da
4d304c854141d69a578a006c7982fe1b915f5424b017c46e25ec65301c66f395
4e8ee4fb631956cac9049f2c7e106554054b2af7891eb5cdff202944b7d10057
4ea208842ac49499066bfbffa3b3f29b406ae2ae26a509bc0e13719b4ee2d85e
4ede1197d5311e23fc768b683d59c02ed11405ae722c5df522d2b31a452d4bcb
4ffdd6034cad263af3664d13887f4d578a624a818de11e00775c1e10697502e7
50e6287400efcd200d7c820b943ce425728197e29d80135a519af26e97d3718b
517d8b2852f709db4e9899576e5e1b1b848427b7e0829a7f918a6dc8875772b9
521c1b6993fb062ac752617b505cb7dc237d35a5a70e6e21c1cacb386b87e4cb
521fdcdefe26b74dfe10386220135f67ca1270e945270287eb7b984b390536ee
52f47ee64260116303b07638df8c2b7f71e3bf1514f44e11e89f1d3329b42235
53723a77cc0a4fa705d3e1fd3fd815786db02afbeb2a990eeb92383a9a71a9ef
537ed2ad6904c575f7eb2ea0a9bec508dea26ad8b51e58c7ddd65fa77bc2a058
53839a530e693ca26c57fe221bd39526282954ca8cf2ed442edfec38da135d7a
538f432efeb79fc231cad11b718c20bdab951af381784208d1c66334721edec3
540a1ab8a63b1b07ea3d80939868a94dafb79f6e2fc37a8a2cc22ded21c60deb
549ebde3daa59c044fc725c988ceced294da49053f723f31cae3a0bf9c7aa93b
5580e34f50f932f27c42e1d2b8551aaed212321a4a519442ee38dadb61ecd7f9
55eac28159a33a69256885d8d0b500028d54c36390d5f7efcb4b48a3849e5ae5
56163e7e0a3743de982ba768d706af0397f5132c3b07779047d6779d45ab0f1c
562dc6b24ea581f4f285a016cab0f8243d80dfae6fb484d38533ba29972cf644
57435661ab4cd164a10b82ae964c86a96eeab749600a9e1b093794cea989a37a
577f1aaf7014272adaeffea243272a164641c90553f5d87e4dee03037b2b8a82
57ff043c50d16c5214746a27a9629d522787c1d2f85d3b453d8665fa94adeaf2
58dc9bfd9fb920e5e2359eb448df941c36eafa44b63b3d47466eff2f1a91b62d
591dec78016954f6762c1f06f6b94069155cbca2d643f0954ae3474c04e5473f
599b8bf3fb7fc2f44c016d0c7917152943cf3b43ea4e5e78362b130aea0ab07c
5a650c25d749796af6013e067b9c46b4e82901a4e73d5e560df4e13b51ceeb2b
5ab3ef96eec0b4f5d0c2c85f01c8288237179a20044a13dde5490d4447268bac
5b0cfc52bc14d591f4d60211a3f5fa7db305256ce25119aa10249e966a1fda58
5b295303eaecbabc882d61b530be6bc8c9a21b0e525ae59a418d1ab06d749961
5bbd118658e61b2c7a841cd64b36cc0a7c707d67427c6fb6ce07e01fc4e9f257
5caa04f055398103d0fe3c9906d580372807e4579626b88c894ad2fe6765c6ca
5cc630d698e1051fbb93f828b3d7d39d933b044b5dbd889ca88e0eb73b76d5c5
5e89838b965d79a4782b3f1079a810f8a801c0b91e0cd71081d9580d1b954f70
5f291378beb7c8264918b491efa4ebc66110423efbd45ee4e1258a16f9d2a401
5f2f26cf27b0ffb53cf4a5ddec0d2fcd1236eaf7f4af3a7b78d9d23a23e4cb50
5f7767c177c15c5da944ed138f0b39b6902e4bf4d896d01c9a368613b1291788
5f816f9b45889e55fc0a0c714f900968583738c6827c31f774bd45e07aec4c3f
602539024550629c94790807ab0f6b99379a53767b14375963e64b71a2185408
60fef33d394d079626952dd2cb1d7bc6c28ba789116ee87d1d263e433857a856
620fe51977578ab356bf90aec9982e03fd7928d000e75226c757b4f70163f4ba
6299f3e36dc84d0d1aa0b460cfe353d8460f8aae5b13aa75aab9d8ea2efc1a7a
632488a95f110337903d21112c4982bac033aa4328c4df85b6abac260e34bc8a
63b7d1315ae6db5a6f0c66fd1e8ade94a83a9bda0eb3864734e511c087430d7c
640ffe74b1f7d37a7e15471f5f9f3c8a556296225b5961fcfdceb33624b000fe
64917df5f523fc7c2622a523c91223cacb4f56f28158736ade67ff4210b528e0
64cf49217af987d0626bda4b48ebe5cf40e9c27b47cadda9ca5a4ff7c1914027
661b63dca6bdd7d51ec6231bc5891b029f7bd8c6fb37989212f2fdf98a0ee8c0
665981bc367a71821608c4da0f21f2fd07cc78ec740dab4c35690b68799bfc96
673a907adba8b423478f008dd0651b2ad80f00b52a5e7fc8923e66c3c5566cab
679fa9f420878adcae22033e44afc0f0350e4463c527dd036f957fa06f0657a4
67a5b58d36ef0884ee86d601a72ffb085c02aa9cfa40cd3a869ea6806084a011
6855062ed35b045f8773b1c2d999cb7c9fb9c0871341e2a1a1f965cad2d07c95
6a3f1450067ea0cf97a48658d5c935debc1ae14a4a5a540585cf85938aeb0379
6b3cd352e4b01ecef8ac98c4d871fe98a8e07c4f1d082574b57d90b6dcfccfd6
6ba94140ceb5ebde3137b53ac7173f99caa66b0672887705d808ed1f0508415a
6cc2308593a84f59b12946fc87e0c14ec847a304d0efdc4193f41f27af24159f
6d23e4cb2a7704f3ebeaf44893bb9c1df101f0f03d522ceb51a0e1cfc7f8e8ec
6e042b1e9b57979ff67476adac3b38e7ca2a45228ef361ab0faa7d1f59072d2b
6ebdd810e46d96ffefcc9bb771377431bea8b2c31c51ae585045810cb7e826c0
6f1724a590699e9041015699f4646c500764cbbbf4fac0d0065be1a36b86c4d3
6f386875b5039c4f6322daafac454769be06e1823879d6de068f415ee01893b2
6f3c24c620d2e4908ae09fc17656f0a61dafa63df181ebd8c7c5fcc3369cf7f6
6fadee8038751819aef12bc1abc18e17efbc53a8cdfb977dc5cde08e5d0c1552
7021a189f24167ad53bdfc259eee5b6f94d8413f79a0a399220504583dee8455
7029f74bfaf5637a25dad61b7a7462141833886ac9637790d0fdaf7e72d84a3f
7042e48f18a5ca3ee1f07fe417f42e89369a3f3f22e11bada7df9929362ad63a
70502bb6c9fd88cdce1092f83ef2f6408a039c7b9de5652cd22087159dd8ba28
70bace206efc5066e6179603dc6af05a89773629eb5b00c921daad016c46f41f
70ff378c8e14c09654fe4859c8e9a613f6af2e6c7775628e2e8f52dbb595b1a5
717cc1c1cd1788a45027d549ae018a57f72e8f5f7586be633055c2400440b489
71e00f0a18ce6d6cd5e183b7cf13dfe659754eb939368b6a003792797c45056b
72664b33c75b2d624ad3068510b3716bf6d7c09b0c3b259ac26637433d396fed
72efa7a21b9fc50bbf85f55643c0ad695e0cec56d619b096ed51734dbb688ea6
7462afbe83515ab5553b43bac8010a45b1733cf2175fb6646732efacd6cfce1e
749112fd2fc84f3f5c1da92a3c8c14ff6dbacde09dd63e25a04e425ba25bab14
74f68545f08cae0fd9d9e2de016e0a10876df82136be0f06f852cde31f486b4c
750fad3db3f495fec07ac204f7e3717e75324ea9beed2fce1c48350015b888c5
7601104485381f818f5b171b8be6630c0f6b4792e14695e6146c876ff852cb3c
7655af3409edfa80d6495e486c394ab9f2eb0398fb83830835da15fe3966d3a9
765b949ea7303df0165e0d79e9456fb7bf6f70e88128cbcceabdd9f6efe9b757
765baabf2cffedacadb1b683f242396bdf147f045a14e90e50cea2c164756b10
76886075c158597451b514883b75f84fbf5660fc5445de4124662b7aba132cf0
76ad36b4eee5e98fe6b7fdedcbec83e5840129541b9eb0d67a2713812dd2da71
76ffdc89320bb54ff75c47bec51044802d96efa3f4456a7dc5cd338f9a80c333
77b7fa89c446b127b0c1d8ad0c5dc5fb57c8121dd3c40a67b77e5c0a35d75114
7813570d5bf14980d9fd7a7527559b478e830552248ae5b9b39af1ac107bf900
78222a2681d18f4f2b0b33503eab25be3f4ac00604fa0fb4d5546e2c88043758
78c0358132b22eb6cb91f783aee538a62aa6d266a55f88819cb5269e77cfc0a6
79823c206d8b844c67dbd9db4a0345b11930b699ce1a545cea9601f9f89a51c1
799ad2e1325621191989046263aa5e431ea36eec156451afeb41aeb04afca9a9
79d97d58dbb9845b2101ad4a03a987b9fc8e937e43b4b9f5bfe3a47f71a6f113
7a0d8c4542b1e1ba4dab3b3f3fed19c02862c7b8e77732eb4c87551f09e06d29
7a3879038204d61be582004425e7f0772af3eae39a2c8770f955c52ac5729388
7a93cc0c53a02b539c07c06f9fc2d0e9b3794e6c33165e4e7cbe34c569e31278
7ab8a8df13e309d4f59aab15d727a9fbb076cda63f5bf69ddf1189adb9ce2ab7
7aefff47da5ec1a633a406297cd1decd1569d9ff0948ce39c80be809129ebf6d
7b601d4a67aedd2c161de142b4799032a3a298905beb96a732e4ce0157de2aa8
7b61b337fa911a993574e9094f17f0d48247551929cee1369a0259349ede3ea7
7c38161b50bfa0d62fba13ee1daaaad2a86e59fc5e9693dcaccbb29046644347
7ccf0424b23d23ba33937f84b5ebfae2391c023beb1567b7145d1df81593e1c0
7d3633f4d63dd8e95075561828126a43b45cd0687c7e9fd58a8e556c311f5519
7d47f11a565adc0b68333cdc0a70dfc6748a200c2a85bdada22d4c23545dcb56
7e99363c7c9914ed54d176de130b1d4b00ad5a43476d9315096201a3ddbc3e5e
7faf3c9684350e8a8b4836ecdf7a01ddb8f3b8655941ea940125a144f4cbadfd
7fb6e9a788b18806469167cf64458dd590122593a04489cf70bb70434905a246
80b1f627af23d7aaefc6fec3a72e8f7e3299f600251acfbb682fa3b80a702798
82a9252b7d18acc69cff2c82b740d9b810d8a5042ef65a532b680ee4020effae
82c58393e0d855e14a9a3dadf046d823134e3d65c098146c9689df121739334b
82db2e4b20a00fd41fcf246a014913067d07c4fc97f0c360af12b3cb066a19a6
82f755397b3e305be68747fc964dd8c5702c271bca7c85a2dbe2ca726dcafbc8
8380f95847f1a226d620c15fab7c1612f9ae7d375b78d004ed12f4ed9787faf3
838352d1425aaae03fda3d7cfcd5ed398e17bd22c6d0248ac1576aa47f4e1b52
8435871f09b1ba4c78f547c3bda0c509e426601221f60b455f6b6cb9d8a2f1ce
8459e6fc893b7dd880895eb1be14cf8a3bec6003bbb8493f819e48ba84491b87
84b2ba9419479eb514c9db1c1f76d4cc422a93485db4c724f348b490c168cc39
84c802d78bf74bf211b90902ddd97a6c13589a39e5ab776e819886853609eec6
85361ea462a29e3bbd43480a70fbec9bb8507bc03713d64b9c5cb725383b8968
853eefbbfdc888ff893c5dfe288d8791dfa219e856e4e6ffea4a217846244614
86284f4e247cbadd3b43ad1914daaf591621d4d88b9200b500b5a7683c920e4a
862c3c7bef5e6eef0c13e8381f69fa45eec9c859434fdf1620776e99094ab996
86c4ac690b82025a2dbaea573b94bb919980ff2a11e2a95e9e3561fa29924614
876ba8d76dfcb4cca54ca50f4c9a8c8d23c0e1edc3d671982402a61e7db8fa12
883bff3bf4fa910b0842dd7ca716783b7f2f08dba9226f6e84d3f2d726ed8274
884611a77b2db18c1a48e6086ae41fcf97541e2cd4214063ee6dac7b308f33cd
890e68851e2214fa07e35f03d6583ecaaa16c4ce33d42e88f675d576b296ea8d
8a463f15c830e566292963bf3473b16288e71350e97d84359499fd33b7329a66
8abbccff3728412d8bf3191adbdd9e2079c18312ec3ac379e96314f270791183
8aef7422bb8ccc4560fb78875a0fb5d4644108a905febacd2b609012930e5744
8b1417b74ac31f2e60a6a9f5ed507caf06026191354ce0e4b6bf0816fd3f512d
8b78178c8fd8a72412c7dcc6f381a90fbecd96d7195fb5cfc84c1a079935bff1
8b8c9004dcd535fac3d7339e3bad79a7df697c0c3c76fb8a8dc5fb442c50151f
8c89e18a5767f56e3809bcd83d1ed5bc6ae92e4f448b1b37fcd7d928034d35b6
8cb14b0233584540a257d1189f2fc36f44c34847778476d1be5bd6441353a7d1
8d11ba27a06091c918e76fa6d26cb14254ca651bdcfcc4efe60f99b828a29578
8d8bbb9fda24c4255cb7f54601aa618d83572aac35e3bf0a83174b3442c4e4d5
8de3e7ab77e48ac3caa3d6ffb0112bb8a71665f907aaee271d01c3557634a733
8e4b63db4255d1428f0856d7e89ab1c147599416d8edd4e4e506d3f0420d77a4
8f4df940d9a199c45165a84eeb227c027203a66713ca8ea602ccf28e75e3b0bc
8f5a34f80165dd3b125af00e0f799000581693356c589931ac12a3eca44dba2d
8f7ce48631d067be88170413507cc534ca0b5dcb00d6bae77a8de7700c4f5568
8fa58f1d8bebadae9b7f4990b37984b93220efa7d516ef678cf0506e6dce772d
902924b52c5bb0479fecdd9802b067aaa25f1cf89ac97c91abe6cbe59a2ba21c
9037fd514562b5a5bb717551f43d2f56bd7a0e6563b35c189d80b56a24da711b
917fb117aae8de377745a76481d7805f9fbf7a2a27970239e0448e5ecb94608a
92276f87f48836d141ee02c8b6f75398ded9a3e4b12b84441e3125933af6c755
92592af7724d81176c48b78acaee5815e3327827cf8c9c1d449f27d068bb44d6
926fc118ca249c3207c30b3ad18f21b726c3a8e1bb55e1899a6db4f6effeef16
9292f7f271bcfead51e1b7acbd880d00e4b0348a5b543429db067c66a7aa2ec3
92fe26c8230e536786caaa0932023f795e94d364ef3221a728d81d7ef90afd2a
930b122390468b932430ba102ce11c672c668663e0c3d1798527bc5c75f7fbf5
935c1b6816cc3d2a345699871fae59120f0ca8abfb777b9cdc2a3fd6e2c73c45
94a7869cc453d09c871f60696ab6be459092f98fd62eda189fe455e1d04c42a6
94de343851ddec428f261bdce99fad1148420d7949e31c6e25ab6cbaa36218ca
9570bbdb530065408a2c3d51801fcbb4bd0e5de8ce10b71096dcc8eac4571988
958a75638f244908b46438a9b3d3b86449cdcebb6b0fce3552a1f0a31b65c9ae
96425dbadde8f6374899265654e2e0d7e471c756c34dff01f7d5ab08cb0c6a23
977df7d2ed2d9247143c2659e97c36f64b6d6a577c4321735e262165321204d9
978760723983e42e83dfc1d23a929d44c7edfb6631c7257df2a598603ec4e25d
9837ba70f7d9df220a25f6f3ac7cb395d09928226deec41d9d68983e6a377c27
983dc47e548902d54a287f18da0b25eba76c66054e514f597e989be6b0e02269
99d8aa2226c22f96aac10d32c9feb6ffff2e399786e1e31304b7b5f31bc176c1
9afb1afff030f6cb575c9f66e9d21257e82fd4320751ea78dfe6711a2b047fa6
9b5b44ded4ede28d92834c4db286780a5628d02597a739ff3633f808d47f0939
9b66bcea2cd1e6f08b4f5500a367e12c9a9f33a4ed756037d63dc2121071beda
9b8b18328c40299c8663c96d8462a5349aa21b0180c263696b174f171c82b93b
9bb6aba0ebc1593ed13ff5e00907397ac508944f95232e17e5afa194ee4c6002
9c540121838f41e7c79f41447981c2af7be1f326eb116a56ccb2d760953e4afc
9d2f06cdfc272bb58fa2e4150f06a8984506466ac684a0a4a43b8a417ee5a8fe
9d751dab810a9b6e7660228e09be5aeae77a8cc9bc735e2b0790b8c6db610d3c
9d84786f19587aff8ed8a7d7ac2def4c15969bf6f1fcaade1fd8e5d60c33f21c
9e4af1376e0045314e358ea71ecc87a7d6a5f2e036476c5e5d86c6cf28007998
9f873fccfa560d5fddea520012267c961abea33bd1fbe7026e75930aca9788da
9fb242a4adc557d4eb4f638c7815f58dd590fbd20e4132dbc358eadae42fe44d
a0128feeab40984785d7cdf293c46bf9e4c1b84d41af5a109bd26717c56b08ef
a11b83f414ad201f60db4af79dc55b41b0e7820e3381951e106a330da49af2d4
a2335089d3fba76c21e8fdc3ee5796695226ad78c5e4f75c90e73050626e7d30
a2487e3d6a48b6e8b6098b6a82f5d26b09a1250782c4f34051e06857936ea882
a2ca137ab1650809aad7bff3029454c6e7fcdd7716b5bb6fc95822c15c208974
a49487fe3a9aab6df57c5eec240286b3b3a1b80a4b6e81d59eb9106a72483d9a
a4b07204b33173093041072e00e88d0083c88b88f634561aabe46ec8992f9332
a4cebe4913d275f7387b8d8b2acb7d76324550746e8802f28d432a15d3608194
a5ddd635bbbf579e865bd324329ef64b9d750c92eef0e9599e23916139a0b1c7
a77e9393c4000e96d483a677574a78f004e87837013f7bd1414567d436014b6e
a7ea153cb1790d301791a424a6de0c320ec1d3eb7efdc0b71e6447e3b33fdacd
a8bbc7876686552c1f18cd611c2b512f0038f5b65ffc8915dbbe59cf6ed0d262
a93bc040a1ef7a2f2b6660396984e66b876cf64c61576a086ec16265fd6ac0b8
a9c005e6683d52eadd9f94e29a576ff2053a60809181619714b053002c5d2e6f
aa3f7d356fc1b9a5bd198a9cae0aaf86bba906bc51027d58b424e7caa8550723
aaee037bd7631c72f08d7d9b8261c02da2a0d7a69fd98e5b4a0d51b71d4ca89c
ab50736803967469f2a5ae5624f5e06cfd299f92ac94e255c39d0ee7bc30e40a
ab6bbb348634bfb3df677d9b6c1c9ae03d1fe404847cb2e688ad88d978f67188
abb96fbc3e4b80337204e33d19134498c7eca75ba47390fe4df7939383515e6d
ac4887cea34f3afad0e8dc289a8900c5284ce45ac4bb695c382f7ba82abc0848
adb0d88a8655a39400e194d8ac9df6e6f3ac28defadf5e4a2686fbcf688bf259
adb35f04f0e72fdbde5d24f2a590e71fd4424ef5e1ea354ed546eb1c17a1b6d5
adfd200a16ffe7c04631176e3ad03ded8785c7ecf9581f42915ea199f8c27e9b
ae8c7f63195f1f39ebf09f87b61fd3f27ced535bf9035900d2f185aa7662f728
ae9728810c470303c2769a7e6c100509f13c99180726e8203b0291285a5b0f14
af1dfb63504e698918cb9af2ddae7d21c978191824515f0d08420bcb870463d2
af52a469ef5d9dd3b9b9c5bc1ea20c9fdd486b7c24aa7df6be3f006f82d228d6
af5562054a38fd1eef5465883393189cb1f862d6a52e85441f6efa638a8e119b
afdef065db92bacabeb6a8b638ff1adcded1a0f578c36ac89128d13cdf701234
afe8f18b512300d323cfa43350cf7f84f3d7d269f4c179d094ad3d6d46fe146c
b07b89a722de05928f4f674bcb7e9901e45c29a2af387a6e8e8c12a171eb2373
b0f89d59febc0907d2dadaaddc90f5a236cb1d876fdb7346139aa9d8ee3babc0
b18c9e75825836541b9d7015a4a53dacddae7bb29c3bedbca9758349d9de7425
b28bb290703c9bd1606bd009753854d31ef8071e21fb98185ddad138f98cbac7
b291c75213ed2f0fbbc19fd6f4a8d138df1c8e03082eff6ede5985be0545096f
b31dd79e419348812f9889d5b875aaaed2ccb4e51ad31300229dfd497688ef47
b3437763b42f2e89a3e2e143fb181beb5522a593e8e0d891b03b6e94cb100d01
b37d20f35c23ecee0198e90d8d1efb7e9cd7f47a4d1999fe35562aeab4e82e01
b40551ea3f577d38778a762b4983ab25ef3247f4227b30a2bc47acab8224afe5
b4b26f178787cead9da1e8b5ddb204aa27d72817ff23a0fa2335bd5f22c0f866
b61808ecd5aa0c6abd3df46e1f2ec32a18fc9da837d5b7db895214d5a4745682
b633d14b6eb77ceeae4348f54df5f0dd430df22e5455862edd2d13bd2d53ef6b
b68c6e9c0b287cf9d7e82707c44708f7762213b90bfe2cfbeefe4cb3f0667442
b6f3204e492d91b15e67583db1b35c9f18a110367d91bae3985d3c06ee10f539
b6f457aebc800db12b08ccda58e0be7a2d15a043e9b2f10457168e9d99c9b854
b7e415a16cfc8d84c09f105709910d808f0ad13e64c7feb4169b135fe57c7f99
b8942b158c02dd3f2b985eacd89c0947964812f01f0ecfd22f6349a130c77542
b8a97b4c697cfa9f47414d83d6dbc0bf21b52281c1d018904ebcfe52cf88a108
b9105cf604b9ad1920c062d8538f8096ea0ab0cfe81a0e8697366726f2b01db7
b936d9e5e432bc7e6a60dbdc0fe06f7503fc1c053aa26ab61263b64f6a06027d
b98030335337f01183cc474feefbb351d45afe8263ddfcfa7fd5554b97147362
bac48e9a9fad6c9afa0387fe592bb1eabd56cfbcbffef2bbc765e32de2846478
bb99a151f60484be5fbbe2dd9db7d6ab7ab82eabbcffbfbe19eca68ed0675663
bc115dc2be13d9053e04bcac9c102a26391d7c76134d9364cddb798e800949f7
bc2b7f03d0f487024e5ac4cbb2a39ffe41aad9865c1c1cb6c9c45d61859db1cb
bd878970ab0cbcf5b29bf5a7e2f9ae25e81279ddc0cc30d59bdd242f40a465c2
be328d6a63dbbc984c1902a57b8ec0a317816d551b96bbeb81a0f8c25993d82a
bec324abe89a4466ea31b46a11270f69ee71fb01d6a640edaad566f589aa9ef9
bf1e3e21bfb678c9f7c1cfd2063c68c91d46056289bba3c93877cfd7e28a4cad
bfc3d6d12ca4a76297cf920edbdfe491c6be14e42e6b9c0722ff5efb5bfb6377
bfd922757fc0667e42b7d5de0b6cf78f7a08a335b3beef49782be73b8433619e
c0278c21b6310485b5546d072c1703a390dcf10ad01dfbde1e1fe1e4f796d9f4
c27b6225d0b71fc9be2da1b7616f979663aced2ecd76e32814697ac027d0c282
c2cc66ffc0aa0e8aca95e53d21258868583a2048d0c25538c5b25b47621224b7
c2fe8ce700771308a283bcf219b19472c58f5a994e498132eccf22fdb1073ec0
c38440fde99869002aec2e422f28e4ba360bced59bbe6ea769d0caad763fdc6e
c3a8830187f24899610607a4537fc6615cd46a640cd01f4abc0577f6a3edf894
c3eea2f6442912bb4aed67e57f65c65f65adf4bfd9689553e1ea516ac0990479
c4c3c994e1b56b45e57e747cdd6a78cf9d0b735d169538b499ec94b1670f0b99
c4daccf0ac446a6160b18ea3fbf9ab3166ee4181c0e9a40d1c7f26702dea5a69
c4decb86958771c4332bce4748a7eb4867dd9f66258dfba85a88bc8eb1822a38
c4f6077458402ab0803226800fdcfc92c58169ce94435cd62d688588ccfe89f1
c52e200d0834f27c2cfd75aad8402bf07a8f982efa950141806a086594e3343c
c5ed1cf6f6be1689ce7d401f5687e91fae56bbac4c2e665385a341135d91d4e1
c68b5425cf8300b031a775846e07e65dd5a419e01584213671ede25381188dc1
c730e6287aa786e04d22daa4e6c77b504cdf80dc4f09877a15bc79bac84403f6
c77b479ead371d060f45186dc10d6bb2c9d32aac0275de27fab94b2f65a54500
c7c057a2a841138af9f5e5d0919aa2099c27453600d87c3186896836ba812399
c8c4dc99c1afaf623acc44d947a5b0841b0c49cb0514c2353d7d70240a9f9ad1
c934f420deed334d4e556218917127d2cece872416a33be4bc40707e8f21abaf
ca2edeee5d4e8017503333240d938c3ac2ea6ad9818f41d54a637c0c2099ebca
ca313b26bf374909bd0232772f86c613e206f33a77e7c66452429a684693c5f9
cae79bd87462cf7f5134c476db64c8c9c081d512a27936deb7cf7b507079f329
cae8cc4a40faf9c3474f86baf427e7eb1c63c4d75afec8a99da5f616752ffbdd
cbccb0494dc3b5ef6810a203851c68cd00cc2c397bca55898ebf82981c1ba648
cbe0ec259077679463a23abb44d85529e27d54bdc0f1c5afbf72e7f8cba4b8f2
cc515ffc7f4d8b46c81220995aa18193d4fdb9ece4211034a289c65177b66492
ce741606b0ecf619924513f80c43418a02c0b966aa3f1f7ef8cd961362ae5b3f
cf282b407f84bf06ccdf0146d3a250991f7f38e310a7296870e64b38378c7196
d0a5ea1fe235fab5d540999cf1dc87788fcd4f5072642f2eb7875e5c150d7211
d0d2aa0220d8d55fe5a028d41f02af236a0c5f6ad5d39054621aec63fc1bef83
d37a05507ee7da9f95d5fab0b52f03248bb3e160643c17a1e2668db80c077846
d43c6aba8577d6f6e846545d25587748ff13e676320936f4c3104ba94e22e24c
d5a6ab788954e96a9c2be8f4d466e9a4b5fb7d871849d28260e03cd05e9e9ccb
d61269cd056651464d86917efba3270f3fe8018c16ec553c09444b8ff0683878
d6560333f140f32f097c228b427bb8fb0b334e5d0b25d8ac2ce664c0d0871916
d65c564ac7ecbe786ab6f66b4a2aff57b21ef70e24d25727307d6a51a722da7e
d6d443e15091dad8a8f884a3d17cd8d19e917e34ed0a319eed0940f34a5e18ea
d74851c570a31d103a0eea545516261f5e903261fb92f95fc4c01677575b0681
d76b4212f4b378be4ebac39567fb86df9b1bddffabf4e041d2e45503c441914a
d76bb3281390d0706a2e17735005ebac0cdaee6f8f04c69719502eef2d2c5481
d788acb4f4c4b97e515f77d61a994832ded56994a3334314f861020c85587363
d78a290c068063c097c194ea37c73e49ef30806fff458330797011b23c9f3fbd
d7e12e3d7cd55ad4fc698a7cd6a39f3f6ec873aeba78742ae2d74ccd19ed3da5
d85f877f8d4d56ebfe56be1f8e11d3de68632c13b258955ed52cabad19a4e783
d871694564319f19892ade1b3e34486883d95b384b1f07185bd572777303fea5
d879b76d757e6b789eec5ff4a396396902be4fbb19e90412b7b1f64f16e4d619
d8bf954c993177ef79e36ce8ef7f625633b24702c1a55034483ed193ab74418d
d9105bd42fdab5c865980300f0700490933fcb93aa9223e5a1051b780f036cae
d9146883a7ac6f961a504acac6cd2e2a538eb102aec9c07d571541ac1ea976aa
da192e3c40c906d947993aba743113a796cff63779db7ac7f7789f51873c192d
da6f7b3b59260d0dcb45aa5b8e2212e99cf75d8c4bc36e56c720b02496ef816f
dace2f4b76d741282866cb3e5038e7b2008817ed8f7079d5d764099be01d34bb
db374ba72eeceb56a67ec78c6f5c98d2e454ece2e83e3c4c1b1ac044baeb2cc0
dbd37ae8f25704a4f34a5bc21a026dfe3afb6724fc850e3077028b219a93a7b6
dd0b44aeb504ee47ac61b86d092f14b7f3955b76c4b227458237acc4c9f55663
dd1ccdaf08e9374dfa9214180830f32a8b0ce4344854496ad48a5fc3963ef0ca
df24d49406b6c7ff6624d90324115a646bb1643742dd955ea18569b406dfd01a
df43aec4416c5ccf985815877a169241c06edf747b5695c048665d4a40323afc
df62315f5c8cdf498cef05c05386c8fc4f994a67551f40118f5be265267a2217
dfb0266da4ad6a4334216c26cab2383155a702a1b0738be8c8e2d671e1c998e7
e05b4f9346fb036210507d8372c47682ef97a95ce9d773ddb18e8f7ac1f216aa
e06e5ba87ec0ed09101fcd62c238777c90c6a59be6bba4ced6890250948e6a4b
e0c5b0ed76a720cb7b40e0712b5d39800c5e7b2cb8c4f24e0b2de53bb5141b44
e168b9f5827cb011c151049535ce63362ecf08f39655485c1f3c899474d04634
e23d300d4caacb13390b018df922798b7e4de2c012670776d1a5fb45b787eb2b
e2a6da17233e298551a6a59b762b35900a7767e18d1d375afca6d735382e0b30
e4031bfc8a9e6268a0c5c85697424583fcf998bc75728a3b9b2f779879f167a4
e4b1c7f2f04d674f545b52a14617dfc553b65991c4779d1b22bf41982d1201ff
e4dff6694f28d833ff1087e64c1498c9c9232abdcebf324bffdcbe322a125bb3
e56f554fbbd10426e2fc784847a2ba8c8554b4f5c6248294e6da3a5a07555ef0
e6475b9ec4e5494a4952074f2acc6352ce617dea4c39b0646e3af2a67c99fddb
e741316cdee811177ffe7b20cfdd1616cf29d63d475b5abcf4be45f0165b2095
e75146f8ff6b18c900a5896fd04dd76f772ec6770b6378963de96dcf67ba894b
e7611fac5c7603bc7a9f342efe76c656ed04e267192ef0620e827ebddac5520a
e83f6a6f47e7d51ad62415e6c07a5e8e9fd5408a107b9afbdba5657c9d6882c0
ea05802a8a6ac055e735378cad6469d1f7819d461d1402d78ae23aa125ab03dc
ea73e56a48fe4a3cc6ec0006c7d802f3902b8bd2d491586d4943795c7bcb5811
eabd45e874589dd8a61a40c5e17dfa1fb4b0a9c78d7ea1f4f783f1de74f5377d
eaf233924580f52342e12c63fd6a33ec5db002b85a20b26a3e7534147d292bc5
eafb46760c6ca2a826af095d5b71423b93ff9a0ce5e6b2369d55d51bae5ba5cd
eb185e6d132bbedd392160872e4329a96977f6d338014696fcdae3b35f195cc8
ebfc585bba8bfa8b1b8c617577a7238373fa336dd5d411dbee720dd4a906e365
ec25ebfcfee56043773ef08bafa21683befbe3f74fa39c2ff3e149a25c7831d7
ec71f5a55f7af75de19957a7283f209ca6f171ffd5cafd6acd52e02570e025d9
ecb4832aec029ecf6342defa825866821f610695bbb132b56e44884318f44b91
ecfc5666224f8beb3dabe6fbed257eaecc8f0c063c2041879e0d0404ff2acf96
ed6f85aed6c250545a123c5c3be00af5fe28018b0fe6e42fce10b9cc73afee21
edd4ed935c2607a173722c89b329ad9dbc39d1a6204fa8ed22987f5df7955838
ef7af4b3a2e3860e7b210b8c24dff885515573d28204053c8e4523eccfd6aa36
efe3a916d8946435407de5ca7f8110d93ad788aade74f8b83c698b5d7ae8338e
f0159cc8ce4568753a7475824095dc94555c724302a817943ae6c670cfc24c9f
f1b5f045df72f5e6f35be5014e0884ef0a5ce1255b558461647340044573ba9e
f23b9e7560ded009508ff2a4dd75507d7bf087ad69c47fc5320af052d95fa814
f390a59156f666b03a254da3ad44ef0cf1c990d1695619bc1f873530d79643d8
f442caaea63f4ea2a4b270f04adc9e6ce707cdf24fc07b297a3adf61b2e7276e
f4629c7de5efbbc0047ca88cfdb4403619b94651fb01dd144cfa6283f3840cd8
f4d0e6be4fa21b836500f0254352dd10a7f5a26abebeb1e7b7980e1896570796
f56d7d52023e3a3dd1f6b2c2dc31b11a509d6175ca1385459bcc1cf4a67c9c2f
f6853a25abff371818a7a5852ecaf8b01482577e3f2a4eb1ca2093b739d1601c
f6c5412b5b16428b3898f8e534318b6e5e1e19981302d4301a308c8486e4e3ff
f70e37d9c9380b978df1ccb8a67f644bb7d90174c420ff4b90beb61edb9e5f99
f712e3d1f64a9b4c8847f9f0c624615cc0faea60e052e186da1ab965cb49569b
f71822de24a50ca44db81e8529d59bc071ca457318dc5c4d35ce02a1ccef3b53
f7f0e23c36ef2e5d2c3a50f3214f01bdf2d9b1d4a2e8cc361e97e42a51442a3e
f97797ca0d80a8406dec8f939c725445742a884d734c9d339321c10e88bb4433
f994013af4ac4aec934bcbf4267a169982cd58451b2586450abf86523b301653
f9a12bd3805ccb30888cf55b8145dcbdeb64ecab5cc2be9d1ab831585ee2831b
f9aa404e6b892570fa59a968eb1e6f2069cb6e6105632e323ae91d7c8005fe57
f9d23884ea2c8b181615c7e0eaeee633d85d5c7c76ed347ce02fb89c5529ebe7
fa5b139ba84bcbe572db3ed6cd29793f70f2c7f77d7f60e403a91d96a06db7e8
face960fd123b7e2fa14e9f4bf832fcbcdbe7bfa1b85d40d09aaba519175d272
fae134e18334300e543ec348d156397bcd51dcaa83fcc2330b0263fa43f38c8c
fb085874ccc515ae84118ccfdbd9f7eaf718ff1194b0f8dbf5b62caec906516e
fb4c19ce89d08a9056fcca54a158693109901dfab61adfeaf449ca230786945f
fbc6193466853c3733172b8e384bde2e132c9135d0f6f0659cab5b1a0eee14f7
fccaaabe6cdd5c817df1a5dd597fb210e79a509edb1c660fb2553618cacdd0da
fdedefc3bfaab269d3d3333f49ed2dcd43b036d1da3d80b4239d7629149b8d85
fe34305a1c146a4f4a3415b7d199f66473d56fc149b59d5c5225af050e2c71a6
fe51673d1972f95d5e172ffc8a841c3808372470eed0b99039395122eb4cdaee
feba095b82700027b488def99613f3de7d281a2e5fd34ead69519fc12208c883
ff426a58a852e0960291fb86f188f62bf25105280922251aa1a2d66092c43b55
ffaddaa50a635dcb4a0d8d17fc4864f65b81b09c0fa221d327d31ae42a48b26f
ffc5491643c07ce077831156a0e1d74fbcf18f8826a8b78fd95dfa5282fc3e90
ffed64fdf03ed762c8dbf6f3409dfd01a5e7f83497c9da48e8c8e2a223e11c31
```

[Top](#information-stealers-wall-of-sheep-analysis)

## Hello 'JoJo'

This operator ustilizes AgentTesla (61 samples) for their malice. However, they were observed to experiment with MassLogger (2 samples) and HawkEye (1 sample). The operator runs a single IP address of ```162.241.27.33``` for exfiltration, with three domains, namely, ```qatarpharmas.org```, ```mail.platinships.net``` and ```mail.novaa-ship.com```. This operator is responsible for 64 unique samples, with the majority operating under the domain ```qatarpharmas.org```. This domain might be an attempt to impersonate or target a pharmaceutical company in Qatar with the legitimate domain ```qatarpharma.org```.

The operator also appears to have managed the following addresses for hosting the second stage payloads after successfull CVE-2017-11882 exploitation:

- ```http://88.218.16.20/```
- ```http://88.218.16.151/```
- ```http://192.3.31.219/```
- ```http://biz9holdings.com/```
- ```http://synergyship.com.ng```

| IP Address          | Count | Domain                     | User                               | Count | Password                 | Family     |
|---------------------|-------|----------------------------|------------------------------------|-------|--------------------------|------------|
| ```162.241.27.33``` | 64    | ```mail.platinships.net``` | ```amani@platinships.net```</br>```armani@platinships.net```</br>```garang@platinships.net```</br>```phyno@platinships.net```</br>```chima@platinships.net```</br>```don@platinships.net```   | 2</br>4</br>5</br>6</br>5</br>1   | ```Azz%LcQK%sb!```</br>```#%c,*lVZNIXctE.!BA```</br>```%izARl@$-zHKEYwlHM```</br>```J~5v.F5[G06H6}ct{!```</br>```R[2](NaueJp!6tL?sW```</br>```Vn,?+Es5;dNayEvk]*```       | AgentTesla |
|                     |       | ```mail.novaa-ship.com```  | ```ebase@novaa-ship.com```</br>```flo@novaa-ship.com```</br>```armani@novaa-ship.com``` | 1</br>1</br>1</br>     | ```O-xgNxpHw~?h5H.ZEB```</br>```KyayQQ{Kn$TJ+f;dRd```</br>```Azz%LcQK%sb!``` | AgentTesla</br>AgentTesla</br>HawkEye |
|                     |       | ```qatarpharmas.org```     | ```royal@qatarpharmas.org```</br>```flo@qatarpharmas.org```</br>```jojo@qatarpharmas.org```</br>```vip@qatarpharmas.org```</br>```nd@pantheomtankers.com```</br>```mic@qatarpharmas.org```</br>```uaa@qatarpharmas.org```</br>```don@qatarpharmas.org``` | 10</br>7</br>7</br>6</br>3</br>2</br>2</br>1   | ```@dX2#^%HWdg?fZ;g5n```</br>```?A4$!,SpMP@YwVn0qV```</br>```v~t-0~GGykudc@r&u*```</br>```YEK7Ne@.6,m]vBXKQw```</br>```;oB-_Sf.+F4e{^!I1@```</br>```jd9}ohRMh(cIz~&)%n```</br>```{[g(XaBNF%aJkU*U72```</br>```eY^H[nPuV3lMJl6Cw%``` | AgentTesla</br>MassLogger |

The operator could be suffering from dementia. Recently they started naming their samples or use initials in sample names that match the exfiltration email addresses used in each sample. It is suggested that the operator go through a mental check up before they start the next campaign.

| Sample Name    | Email                        |
|----------------|------------------------------|
```uaade.exe```  | ```uaa@qatarpharmas.org```   |
```jojode.exe``` | ```jojo@qatarpharmas.org```  |
```nde.exe```	   | ```nd@pantheomtankers.com``` |
```dc.exe```	   | ```don@qatarpharmas.org```   |
```rbp.exe```	   | ```royal@qatarpharmas.org``` |
```vbp.exe```	   | ```vip@qatarpharmas.org```   |
```ubp.exe```	   | ```uaa@qatarpharmas.org```   |
```jde.exe```	   | ```jojo@qatarpharmas.org```  |
```fbp.exe```	   | ```flo@qatarpharmas.org```   |
```r.exe```	     | ```royal@qatarpharmas.org``` |
```n.exe```	     | ```nd@pantheomtankers.com``` |
```v.exe```	     | ```vip@qatarpharmas.org```   |
```ndc.exe```	   | ```nd@pantheomtankers.com``` |
```floc.exe```	 | ```flo@qatarpharmas.org```   |
```j.exe```	     | ```jojo@qatarpharmas.org```  |
```rc.exe```	   | ```royal@qatarpharmas.org``` |
```jc.exe```	   | ```jojo@qatarpharmas.org```  |
```royalc.exe``` | ```royal@qatarpharmas.org``` |

## Correlation 'Repetition Makes Perfect'

### Use-Case 1

The first use-case invloves 44 unique AgentTesla samples exfiltrating to IP addresses Virtual Systems LLC, two of which reside on the same /24 subnet. Another common characteristic among these samples is that none of them resolves a domain name. Additionally, the user/sender and recipient addresses are the same with the addition of "1" to the end of the recipient addresses. Finally, the passwords associated with these accounts follow the same pattern and length.

| IP Address                                  | User                                 | Recipient                             | Password       | Count |
|---------------------------------------------|--------------------------------------|---------------------------------------|----------------|-------|
| ```78.142.19.111```                         | ```brooyu@larbaxpo.com```            | ```brooyu1@larbaxpo.com```            | ```UmX3iJQg``` | 32    |
| ```78.142.19.101```                         | ```urc@emmannar.com```               | ```urc1@emmannar.com```               | ```r1NmBO4h``` | 4     |
| ```78.142.19.101```</br>```77.83.117.234``` | ```dave@emmannar.com```              | ```dave1@emmannar.com```              | ```cwEqoinR``` | 4     |
| ```78.142.19.101```</br>```77.83.117.234``` | ```pcs@deepsaeemirates.com```        | ```pcs1@deepsaeemirates.com```        | ```J3fP8xWq``` | 2     |
| ```78.142.19.101```                         | ```auth@deepsaeemirates.com```       | ```hp@deepsaeemirates.com```          | ```8txksCNY``` | 1     |
| ```78.142.19.101```                         | ```slimshades@deepsaeemirates.com``` | ```slimshades1@deepsaeemirates.com``` | ```NAEgz9DX``` | 1     |

### Use-Case 2

The second use-case belongs to the operator "strykeir". Initially, the operator operated 32 unqiue AgentTesla samples under the same user/sender/recipient addresses. The last sample under the "strykeir" domain changed the password from "iyke112@@@333" to "@@Io419090@@". At time progressed, pivoting on the latter password reveals new accounts, domains, and information stealer families. Between 2020-05-12 and 2020-05-15, the operator introduced their first observed HawkEye sample.

| Password                                   | Count    | User                           | Count | Family     |
|--------------------------------------------|----------|--------------------------------|-------|------------|
| ```iyke112@@@333```</br>```@@Io419090@@``` | 32</br>1 | ```star-origin@strykeir.com``` | 33    | AgentTesla |
| ```@@Io419090@@```                         | 11       | ```staronuegbu@yandex.com```</br>```hselimoglu@bmssrevis.com```</br>```brajesh@cropchemicals.co.in```</br>```cjmyguy@yandex.com``` | 6</br>2</br>1</br>2 | AgentTesla</br>AgentTesla</br>AgentTesla</br>HawkEye |

### Use-Case 3

The third use-case involves 6 initial AgentTesla samples with the same password of ```greateman32```. Later on, the operator appears to have decided to shift to Yandex as opposed to the custom domain, while maintaining the same password among all 9 samples.

| Password          | Count | User                                                        | Count       |
|-------------------|-------|-------------------------------------------------------------|-------------|
| ```greateman32``` | 9     | ```yyaqob@trevisqa.com```</br>```fffffffgggd@yandex.com```  | 6</br>3     |

### Use-Case 4

Another use-case of correlated passwords is the password ```wassodedon22```, which is used 17 in 17 samples with 6 different accounts. Pivoting by the domain in the account ```reallife@jpme.org.in``` reveals 5 accounts potentially linked to the same operator, all of which used PDR network for exfiltration.

| Password           | Count | User                                                                                                                                                                                          | Count                      |
|--------------------|-------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|
| ```wassodedon22``` | 17    | ```chinaloggers@juili-tw.com```</br>```fallin@damllakimya.com```</br>```loggers@sitechukandlreland.com```</br>```money@zellico.com```</br>```thb@tbh-tw.com```</br>```reallife@jpme.org.in``` | 10</br>2</br>2</br>1</br>1 |

| Password           | Count | User                       | Count       |
|--------------------|-------|----------------------------|-------------|
| ```Ehimembano1@``` | 5     | ```fuckoff@jpme.org.in```  | 5           |

### Use-Case 5

The account ```issac@anding-tw.com``` is observed to reference two different domains with obvious similarities, allowing correlating of additional accounts and passwords.

| Domain                                                 | User                                                                                   | Count          | Password                                                                                |
|--------------------------------------------------------|----------------------------------------------------------------------------------------|----------------|-----------------------------------------------------------------------------------------|
| ```smtp.blowtac-tw.com```</br>```smtp.anding-tw.com``` | ```eileen@blowtac-tw.com```</br>```issac@anding-tw.com```</br>```dabo@anding-tw.com``` | 14</br>6</br>2 | ```FBZmjprY*6```</br>```znL#cNm1```</br>```zra1@!G8gQ+i```</br>```Daberechukwuego123``` |


### Additional Use-Cases:

| User                                                                         | Recipient                                                                                               | Password                                         | Count  | Family                 |
|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|--------------------------------------------------|--------|------------------------|
| ```satinder@bodycarecreations.com```                                         | ```satinder@bodycarecreations.com```                                                                    | ```Lion@4321```                                  | 7      | AgentTesla             |
| ```enquiry@waman.in```                                                       | ```enquiry@waman.in```                                                                                  | ```enquiry@2020```                               | 5      | AgentTesla             |
| ```shahid@onyxfreight.com```                                                 | ```shahid@onyxfreight.com```                                                                            | ```jiashah123```                                 | 5      | AgentTesla             |
| ```onlineboxmonitor@tehnopan.rs```</br>```onlineboxmonitor@fiscalitate.eu``` | ```nwekeboxs@tehnopan.rs```</br>```nwekeboxs@fiscalitate.eu```                                          | ```;&7]PU*4yzVJ```                               | 15     | Phoenix</br>AgentTesla |
| ```accounts2@oilexindia.com```                                               | ```accounts2@oilexindia.com```                                                                          | ```Kamal@2019```                                 | 13     | AgentTesla             |
| ```snp@1st-ship.com```                                                       | ```snp@1st-ship.com```                                                                                  | ```441101474992991313053992```                   | 10     | AgentTesla             |
| ```fuckoff@jpme.org.in```                                                    | ```fuckoff@jpme.org.in```                                                                               | ```Ehimembano1@```                               | 5      | AgentTesla             |
| ```skt@startranslogistics.com```                                             | ```skt@startranslogistics.com```                                                                        | ```SIALKOT12345```                               | 11     | AgentTesla             |
| ```msg@acroative.com```                                                      | ```hm@acroative.com```</br>```nu@acroative.com```</br>```jn@acroative.com```</br>```nx@acroative.com``` | ```onegod5050()```                               | 6      | AgentTesla             |
| ```info@pat.ps```                                                            | ```info@pat.ps```                                                                                       | ```Firas2017!```                                 | 3      | AgentTesla             |
| ```elekus2020@aerotacctvn.com```                                             | ```elekus2020@aerotacctvn.com```                                                                        | ```sOeKk#E6```                                   | 14     | AgentTesla             |
| ```finance@enmark.com.my```                                                  | ```finance@enmark.com.my```                                                                             | ```08Jan1963```                                  | 4      | AgentTesla             |
| ```finance@manunggalkaroseri.com```                                          | ```finance@manunggalkaroseri.com```                                                                     | ```123572525finance```                           | 9      | AgentTesla             |
| ```tegaworks@masterindo.net```                                               | ```tegaworks@masterindo.net```                                                                          | ```Gp:b2Qgqa3*}```</br>```uLrOsjJYN9```          | 11     | AgentTesla             |
| ```donga3@dongaseimcon.com```                                                | ```donga3@dongaseimcon.com```                                                                           | ```rDdlJ%h9```                                   | 4      | Phoenix                |
| ```moin.ansari@sapgroup.com.pk```                                            | ```moin.ansari@sapgroup.com.pk```                                                                       | ```moin@26919```                                 | 8      | Phoenix                |
| ```pulsit.c@spinteng.com```                                                  | ```pulsit.c@spinteng.com```                                                                             | ```Spie#th2017```                                | 4      | Phoenix                |
| ```sbourdais@sielupz.com```                                                  | ```sbourdais@sielupz.com```                                                                             | ```eJkG%KP9```                                   | 5      | Phoenix                |
| ```ranger@canvanatransport.com```</br>```ranger@seltrabank.com```</br>```ranger2@amisglobaltransport.com```</br>```anger@canvanatransport.com```</br>```grant3@leltbank.com``` | ```ranger@canvanatransport.com```</br>```ranger@seltrabank.com```</br>```ranger2@amisglobaltransport.com```</br>```anger@canvanatransport.com```</br>```grant3@leltbank.com``` | ```newpassword216```           | 37     | AgentTesla             |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Impersonation'

This correlation invloves two different malware families under the same exfiltration domain, namely, AgentTesla and MassLogger. Interestingly, the domain appears to impersonate General Electric (GE) with the use of a look-a-like typosquatted domain. The operator of this domain started with the use of AgentTesla. However, between 2020-05-03 and 2020-05-07, the operator started utilizing MassLogger.

| User                        | Count | Domain                     | Password       | Count | Family     |
|-----------------------------|-------|----------------------------|----------------|-------|------------|
| ```slim1@ge-lndustry.com``` | 4     | ```smtp.ge-lndustry.com``` | ```J)*(EIv4``` | 4     | AgentTesla |
| ```admin@ge-lndustry.com``` | 5     | ```smtp.ge-lndustry.com``` | ```tvyTkyG1``` | 5     | MassLogger |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Geo Impersonation'

Some operators opted to impersonate or target or illud association with entities within countries.

### Use-Cae 1

The operator's domain ```usamilitarydept.com``` might be an attempt to impersonate or target the US Departemtn of Defense (Military).

| Domain                         | IP                   | User                                 | Password       | Family     |
|--------------------------------|----------------------|--------------------------------------|----------------|------------|
| ```smtp.usamilitarydept.com``` | ```208.91.198.143``` | ```leaveboard@usamilitarydept.com``` | ```qqkgpIN2``` | AgentTesla |

See correlation [Hello 'JoJo'](#hello-jojo) for another use case of potential geo-impersonation.

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Compromised Accounts?'

An AgentTesla sample ```973de14a37f6408161ec0ec249a50527d3cdf4bf7482a67134ac7b0c9e3b7a25``` was observed to (ab)use a legitimate but potentially compromised email address to exfiltrate data stolen by AgentTesla. The email address appears to belong to a one Goverment official __Mr. Bosko Stojanov__, the Head of Sector for normative-legal, general affairs, affairs of the Mayor, public activities and work with the Council of the Municipality of "Gjorce Petrov", of the city of Skopje, the capital of North Macedonia.

| Sender                                 | Password | Recipient                    |
|----------------------------------------|----------|------------------------------|
| ```b.stojanov@opstinagpetrov.gov.mk``` | REDACTED | ```confirmed@graduate.org``` |

Reviewing the website ```opstinagpetrov.gov.mk```, in particular ```http://opstinagpetrov.gov.mk/opstinska-administracija/```, identifies the email address and the owner of this email address.

![image](https://github.com/ditekshen/is-wos/raw/master/img/compromised_account_infor.jpg)
![image](https://github.com/ditekshen/is-wos/raw/master/img/compromised_account_info.jpg)

The recipient domain ```graduate.org``` appears to be a parked domain.

![image](https://github.com/ditekshen/is-wos/raw/master/img/parked_domain.png)

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Steering Towards Arid Yandex Pastures'

In general, 202 samples fully abused Yandex as an exfiltration platform.

| User                                   | Password                                       | Family                    | Count |
|----------------------------------------|------------------------------------------------|---------------------------|-------|
| ```ikpc1@yandex.com```                 | ```ikechukwu112```                             | AgentTesla                | 20    |
| ```mullarwhite@yandex.com```           | ```challenge12345```</br>```challenge12345@``` | AgentTesla                | 20    |
| ```tim3.44@yandex.com```               | ```Obaten10```                                 | AgentTesla                | 9     |
| ```staronuegbu@yandex.com```           | ```@@Io419090@@```                             | AgentTesla                | 6     |
| ```irina.macrotek@yandex.ru```         | ```hygiene@789```                              | AgentTesla                | 6     |
| ```okirinwajesus@yandex.com```         | ```07062487004```                              | AgentTesla                | 5     |
| ```johnsonpikyu@yandex.com```          | ```cr*fDaW&m@2y6u```                           | AgentTesla                | 5     |
| ```selecttools@yandex.com```           | ```biafra123```                                | AgentTesla                | 4     |
| ```petersonhouston@yandex.com```       | ```faith12AB```                                | AgentTesla                | 4     |
| ```houstondavidson@yandex.com```       | ```faith12AB```                                | AgentTesla                | 2     |
| ```lucinedauglas@yandex.com```         | ```myhp6000```                                 | AgentTesla                | 4     |
| ```genuxpc@yandex.com```               | ```africa@@@@@```                              | AgentTesla                | 4     |
| ```chijiokejackson121@yandex.com```    | ```chijiokejackson```                          | AgentTesla                | 4     |
| ```chi.eb@yandex.com```                | ```sages101```                                 | AgentTesla                | 4     |
| ```tt.swift@yandex.com```              | ```Sages101*```                                | AgentTesla                | 1     |
| ```sleeves100@yandex.com```            | ```@Sleeves100```                              | AgentTesla                | 3     |
| ```rose.nunez@yandex.ru```             | ```lochmann2```                                | AgentTesla                | 4     |
| ```r.tome@yandex.com```                | ```qwerty123@@```                              | AgentTesla                | 3     |
| ```p.origin@yandex.com```              | ```Loverboy123```                              | AgentTesla                | 3     |
| ```fxxxfuz@yandex.com```               | ```genesis070```                               | AgentTesla                | 3     |
| ```fffffffgggd@yandex.com```           | ```greatman32```                               | AgentTesla                | 3     |
| ```zecospiritual101@yandex.com```      | ```07030452451```                              | AgentTesla                | 2     |
| ```resultbox042@yandex.com```          | ```OGOM12345```                                | AgentTesla                | 2     |
| ```result.package@yandex.ru```         | ```Blessing123```                              | AgentTesla                | 2     |
| ```lightmusic12345@yandex.ru```        | ```chibuike12345@@@@@```                       | AgentTesla                | 2     |
| ```james.cho8282@yandex.com```         | ```klassic1993```                              | AgentTesla                | 2     |
| ```cruizjames@yandex.ru```             | ```cruizjamesvhjkl@```                         | AgentTesla                | 2     |
| ```cjmyguy@yandex.com```               | ```@@Io419090@@```                             | HawkEye                   | 2     |
| ```chinapeace@yandex.com```            | ```chibuikelightwork1```                       | AgentTesla                | 2     |
| ```Goodluck2k20@yandex.com```          | ```Pl@nedon1234```                             | AgentTesla                | 2     |
| ```pauline.vostropiatova@yandex.com``` | ```kaka1234@1@1```                             | AgentTesla                | 1     |
| ```boymouse@yandex.com```              | ```333link00win```                             | AgentTesla</br>HawkEye    | 2     |
| ```annwilso@yandex.com```              | ```theoldlady```</br>```HueCycle```            | AgentTesla                | 2     |
| ```zhu.china@yandex.com```             | ```KOSI213141```                               | AgentTesla                | 1     |
| ```vipa.agraindustry1@yandex.com```    | ```chosen@@@123456```</br>```chosen@@@123```   | MassLogger</br>AgentTesla | 2     |
| ```mor440ney@yandex.com```             | ```castor123@```                               | HawkEye</br>AgentTesla    | 2     |
| ```victormuller10@yandex.com```        | ```Mummy212```                                 | AgentTesla                | 1     |
| ```sly-originlogs@yandex.ru```         | ```JesusChrist007```                           | AgentTesla                | 1     |
| ```oriego1@yandex.ru```                | ```Ijeomam288```                               | AgentTesla                | 1     |
| ```mobile.mailer@yandex.com```         | ```qwerty123@```                               | AgentTesla                | 1     |
| ```magagraceman@yandex.ru```           | ```tonero4417```                               | HawkEye                   | 1     |
| ```jessicafaithjessica@yandex.com```   | ```123abc1!```                                 | AgentTesla                | 1     |
| ```iykelog1@yandex.com```              | ```Conversation2```                            | AgentTesla                | 1     |
| ```iren159k@yandex.com```              | ```Protected@123```                            | AgentTesla                | 1     |
| ```info.pana@yandex.com```             | ```user@12345```                               | AgentTesla                | 1     |
| ```import22.export@yandex.com```       | ```khalifa2019```                              | AgentTesla                | 1     |
| ```genaral1122@yandex.ru```            | ```kukeremaster1122```                         | AgentTesla                | 1     |
| ```freshclinton8269@yandex.com```      | ```fresh826699```                              | AgentTesla                | 1     |
| ```frank.got@yandex.ru```              | ```godson00```                                 | AgentTesla                | 1     |
| ```cupjul@yandex.com```                | ```esut96092```                                | HawkEye                   | 1     |
| ```blr@saharaexpress.com```            | ```Sahara*542```                               | AgentTesla                | 1     |
| ```acksonjogodo121@yandex.com```       | ```jacksonjogodo```                            | AgentTesla                | 1     |
| ```account.info1000@yandex.com```      | ```4canada1A@```                               | AgentTesla                | 1     |
| ```Alibabalogs657@yandex.com```        | ```austinmilla```                              | AgentTesla                | 1     |
| ```jerryedward1@yandex.ru```           | ```enugu042```                                 | AgentTesla                | 2     |
| ```kom.upakovkai@yandex.com```         | ```Ilovegod12```                               | HawkEye                   | 1     |
| ```jaffinmark@yandex.ru```             | ```@jaffinmarknma@344```                       | MassLogger                | 2     |
| ```wpollczyk@yandex.com```             | ```qwertyuiop[]\```                            | Phoenix                   | 1     |
| ```passjones@yandex.com```             | ```kings@8088```                               | AgentTesla                | 1     |
| ```luc4smail@yandex.com```             | ```Lucas@9842```                               | AgentTesla                | 2     |
| ```glowhub@yandex.com```               | ```INfinity12345```                            | AgentTesla                | 1     |
| ```lawman7070@yandex.com```            | ```sirohms442037```                            | AgentTesla                | 1     |

Other operators opted to exfiltrate to Yandex recipient accounts without using Yandex as for the user/sender accounts. Yet, different user/sender accounts send to the same Yandex recipient account. An example is the accounts ```charlesxmoni@yandex.com``` and ```stanleybox@yandex.com```, which appears to belong to the same operator.

| Recipient                         | User                                                                                                                           | Password                                                                             | Family                                                  | Count                  |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|---------------------------------------------------------|------------------------|
| ```vicky.br0wn@yandex.com```      | ```zainab@almushrefcoop.com```                                                                                                 | ```zainab123```                                                                      | AgentTesla                                              | 8                      |
| ```charlesxmoni@yandex.com```     | ```info@jaccontracting.com```</br>```ijaz@hsisteels.com```</br>```zafar@guddupak.com```                                        | ```#07_WAKvjLG]```</br>```Azizgroup@2018```</br>```imzafar75```                      | AgentTesla</br>MassLogger</br>AgentTesla                | 2</br>1</br>1          |
| ```stanleybox@yandex.com```       | ```zafar@guddupak.com```</br>```info@jaccontracting.com```</br>```kshitij@activepumps.com```</br>```kshitij@activepumps.com``` | ```imzafar75```</br>```#07_WAKvjLG]```</br>```X5=KN(JJIXso```</br>```X5=KN(JJIXso``` | AgentTesla</br>AgentTesla</br>AgentTesla</br>MassLogger | 1</br>1</br>2</br>1    |
| ```esime77@yandex.com```          | ```info@mondastudio.com```</br>```sales@asplparts.com```                                                                       | ```Nigels1975!```</br>```f3nu6R4lH```                                                | AgentTesla                                              | 2</br>1                |
| ```boxblessings7744@yandex.com``` | ```emingles@ilclaw.com.ph```                                                                                                   | ```P@ssw0rd```                                                                       | AgentTesla                                              | 1                      |
| ```logsdetails0@yandex.com```     | ```lot1567@okgrocer.co.za```                                                                                                   | ```Theunis@123```                                                                    | AgentTesla                                              | 1                      |
| ```morrishome1@yandex.com```      | ```limcor@le-belt.co.za```                                                                                                     | ```bemi6ERe```                                                                       | AgentTesla                                              | 1                      |
| ```ffangfang@yandex.com```        | ```info@excellent.ba```                                                                                                        | ```Ilidza_1322```                                                                    | AgentTesla                                              | 1                      |
| ```billionvain@yandex.com```      | ```supin@daiphatfood.com.vn```                                                                                                 | ```jn&6kG~_w;;A```                                                                   | AgentTesla                                              | 1                      |
| ```thedropboxx88@yandex.com```    | ```finance@wowwow.com.sg```                                                                                                    | ```$$wow_5405*```                                                                    | AgentTesla                                              | 1                      |
| ```fresh.italian@yandex.com```    | ```finance@wowwow.com.sg```                                                                                                    | ```$$wow_5405*```                                                                    | AgentTesla                                              | 1                      |
| ```l3ebenard@yandex.com```        | ```finance@wowwow.com.sg```                                                                                                    | ```$$wow_5405*```                                                                    | AgentTesla                                              | 1                      |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Gmail Abuse'

Several operators and families abused Gmail sender/recipient accounts for data exfiltration.

| Sender                                                                   | Recipient                                                                                    | Password                                  | Fmaily     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|-------------------------------------------|------------|
| ```regan10586@gmail.com```                                               | ```regan10586@gmail.com```                                                                   | ```231father```                           | MassLogger |
| ```fletcherjohnsgt@gmail.com```                                          | ```fletcherjohnsgt@gmail.com```                                                              | ```moneymustdrop```                       | MassLogger |
| ```sanbrith112@gmail.com```                                              | ```sanbrith112@gmail.com```                                                                  | ```pointaz45```                           | MassLogger |
| ```2020@website-practise.site```</br>```practice@webdesign-class.site``` | ```sumayyah.diijlafood@gmail.com```</br>```jplorrder@gmail.com```                            | ```Best4666##@@```</br>```A$sfxcedvcc1``` | AgentTesla |
| ```saleem@ejazontheweb.com```                                            | ```nisanelactricals.pro@gmail.com```</br>```hoke.sales01@gmail.com```                        | ```t%[D2FmSeQezu,}e```                    | AgentTesla |
| ```testing@bhavnatutor.com```                                            | ```gabandtee@gmail.com```                                                                    | ```Onyeoba111```                          | Phoenix    |
| ```postmaster@unitedparcelsservices.com```                               | ```jameshamilton7544@gmail.com```                                                            | ```Dw1e7Tlo1id```                         | AgentTesla |
| ```tou013@efx.net.nz```                                                  | ```ourplastic22@gmail.com```                                                                 | ```etou01315```                           | AgentTesla |
| ```pulsit.c@spinteng.com```</br>```varahi@varahi.in```                   | ```lightbabamusic@gmail.com```                                                               | ```Spie#th2017```</br>```Pass@#2019```    | Phoenix    |
| ```lal@montaneshipping.com```                                            | ```pedroalex716@gmail.com```</br>```hoke.sales01@gmail.com```</br>```i.sibrmiov@gmail.com``` | ```Montanemumbai*@*@*@321```              | AgentTesla |
| ```bellalice897@gmail.com```                                             | ```bellalice897@gmail.com```                                                                 | ```Germany777@@```                        | MassLogger |
| ```proyectos@santiagogarcia.es```                                        | ```miguelipscc@gmail.com```</br>```nurifrost556@gmail.com```                                 | ```964Arantza&&??@68```                   | AgentTesla |
| ```bellalice897@gmail.com```                                             | ```bellalice897@gmail.com```                                                                 | ```Germany777@@```                        | MassLogger |
| ```ratna@askon.co.id```                                                  | ```scdcytc@gmail.com```                                                                      | ```r4tn41226```                           | AgentTesla |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'The Shifters'

Based on accounts and passwords analysis and correlation, many actors are observed to alternate malware families, more recently, M00nDev and MassLogger stealers. While the data in this correlation may be repetitive, it highlights the operators accessibility and persistence. Correlations are not inclusive of all samples operated by the same group.

- Between 2020-07-12 and 2020-07-14, the operator under the 'Geo Impersonation' correlation started utilizing MassLogger. See [Correlation 'Geo Impersonation'](#correlation-geo-impersonation) for samples associated with this opertator.

  | User                         | Domain                      | Password                 | Family     | Shifts            |
  |------------------------------|-----------------------------|--------------------------|------------|-------------------|
  | ```jojo@qatarpharmas.org```  | ```mail.qatarpharmas.org``` | ```?A4$!,SpMP@YwVn0qV``` | AgentTesla | Before 2020-07-12 |
  | ```royal@qatarpharmas.org``` | ```mail.qatarpharmas.org``` | ```@dX2#^%HWdg?fZ;g5n``` | AgentTesla | Before 2020-07-12 |
  | ```jojo@qatarpharmas.org```  | ```mail.qatarpharmas.org``` | ```?A4$!,SpMP@YwVn0qV``` | MassLogger | After 2020-07-12  |
  | ```royal@qatarpharmas.org``` | ```mail.qatarpharmas.org``` | ```@dX2#^%HWdg?fZ;g5n``` | MassLogger | After 2020-07-12  |

- Between 2020-04-29 and 2020-05-02, the 'ROBO' operators started utilizing M00nD3v.
- Between 2020-05-11 and 2020-05-13, the same operators started utilizing MassLogger. See [The 'ROBO' Gang (Formerly: Correlation 'Fire Them')](#the-robo-gang-formerly-correlation-fire-them) for samples associated with this opertator.

  | User                        | Password            | Family     | Shifts            |
  |-----------------------------|---------------------|------------|-------------------|
  | ```billions@cairoways.me``` | ```Whyworry90#```   | M00nD3v    | After 2020-04-29  |
  | ```admin@cairoways.me```    | ```requestShow@```  | M00nD3v    | After 2020-04-29  |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | HawkEye    | Before 2020-04-29 |
  | ```admin@cairoways.me```    | ```requestShow@```  | AgentTesla | Before 2020-04-29 |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | AgentTesla | Before 2020-04-29 |
  | ```billions@cairoways.me``` | ```Whyworry90#```   | MassLogger | After 2020-05-11  |
  | ```admin@cairoways.me```    | ```requestShow@```  | MassLogger | After 2020-05-11  |

- Between 2020-05-03 and 2020-05-07, the operator under the 'Impersonation' correlation started utilizing MassLogger keylogger. See [Correlation 'Impersonation'](#correlation-impersonation) for samples associated with this opertator.

  | User                        | Domain                     | Password       | Family     | Shifts            |
  |-----------------------------|----------------------------|----------------|------------|-------------------|
  | ```slim1@ge-lndustry.com``` | ```smtp.ge-lndustry.com``` | ```J)*(EIv4``` | AgentTesla | Before 2020-05-03 |
  | ```admin@ge-lndustry.com``` | ```smtp.ge-lndustry.com``` | ```tvyTkyG1``` | MassLogger | After 2020-05-03  |

- Between 2020-05-05 and 2020-05-08, the operator of the "tashpita" domain started utilizing MassLogger keylogger. The opertor configered the MassLogger sample to perform both, FTP and SMTP exfiltration. Previously, the operator utilized FTP-based AgentTesla exclusively. See [Correlation 'I Speak FTP Only'](#correlation-i-speak-ftp-only) for samples associated with this opertator.

  | Domain                 | Count | IP Address         | Count |
  |------------------------|-------|--------------------|-------|
  | ```ftp.tashipta.com``` | 10    | ```103.21.59.28``` | 11    |

  | Password            | User                                                    | Fmaily     | Protocol | Shifts            |
  |---------------------|---------------------------------------------------------|------------|----------|-------------------|
  | ```server1123455``` | ```server@tashipta.com```                               | AgentTesla | FTP      | Before 2020-05-05 |
  | ```router11477```   | ```router11477@tashipta.com```                          | AgentTesla | FTP      | Before 2020-05-05 |
  | ```server1543211``` | ```server1@tashipta.com```                              | AgentTesla | FTP      | Before 2020-05-05 |
  | ```success2020```   | ```mails@tashipta.com```</br>```server1@tashipta.com``` | AgentTesla | FTP      | Before 2020-05-05 |
  | ```prosperity1```   | ```xmoni@tashipta.com```                                | AgentTesla | FTP      | Before 2020-05-05 |
  | ```@Success$2020``` | ```xmoni-w@tashipta.com```                              | MassLogger | FTP      | After 2020-05-05  |
  | ```moneymustdrop``` | ```fletcherjohnsgt@gmail.com```                         | MassLogger | SMTP     | After 2020-05-05  |

- Between 2020-05-30 and 2020-06-01, the operator of "flood-protection" domain started utilizing MassLogger after 22 samples of AgentTesla. See [Correlation 'Why even bother?'](#correlation-why-even-bother) for more samples associated with this opertator.

  | User                              | Password         | Family     | Shifts            |
  |-----------------------------------|------------------|------------|-------------------|
  | ```sender@flood-protection.org``` | ```kelex2424@``` | AgentTesla | Before 2020-05-30 |
  | ```sender@flood-protection.org``` | ```kelex2424@``` | MassLogger | After 2020-05-30  |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Encrypt or not to Encrypt'

25 unique AgentTesla samples exfiltrating to a Saudi domain associated with 3 IP addresses, two of which are adjacent, and all of them belonging to Hetzner Online GmbH. The operator(s) appear to encrypt SMTP with one account but not the other, despite the fact that their passwords simply swtich word locations, suggesting that both accounts belong to the same operator(s). The last account with 3 observed samples slightly changed the password in an uninnovative way, further tying the sample with the same operator(s).

* Registrant Org: مصنع وضوح الشرق للحديد (Bright East Steel Factory)
* Registrant Country: المملكة العربية السعودية (Kingdom of Saudia Arabia)
* Tech Contact: وضحي محمد (Wadhi Mohammed)

| Domain                  | Count | IP Address            | Count |
|-------------------------|-------|-----------------------|-------|
| ```mail.besco.com.sa``` | 22    | ```136.243.194.254``` | 15    |
|                         |       | ```46.4.159.174```    | 7     |
| ```besco.com.sa```      | 3     | ```136.243.194.253``` | 2     |
|                         |       | ```136.243.194.254``` | 1     |

| User                         | Count | Password                 | Count |
|------------------------------|-------|--------------------------|-------|
| ```khalid@besco.com.sa```    | 16    | ```besco2020admin```     | 16    |
| ```pavan@besco.com.sa```     | 6     | ```admin2020besco```     | 6     |
| ```al_ghamaz@besco.com.sa``` | 3     | ```admin2000besco2005``` | 3     |

| User                         | SMTPS | Count |
|------------------------------|-------|-------|
| ```khalid@besco.com.sa```    | false | 15    |
| ```khalid@besco.com.sa```    | true  | 1     |
| ```pavan@besco.com.sa```     | true  | 6     |
| ```al_ghamaz@besco.com.sa``` | false | 3     |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'Why even bother?'

The uses cases in this correlation demonstrate that some operators attempted to hide their repetitive offenses by using different sender/recipient accounts, domains, and passwords among different malware families, with a great failure rate.

### Use-Case 1

| User                          | Count | Password     | Recipient                                                                                                                                                                                       | Family     |
|-------------------------------|-------|--------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| ```ikostadinov@cargoair.bg``` | 10    | ```334455``` |```info@agri-chernicals.net```</br>```grace_pan@traingle-cn.com```</br>```e.pezzli@giivin.com```</br>```stan@iskreameco.com```</br>```brunolugnani@arrmet.in```</br>```neo.ycwang@mindroy.com``` | AgentTesla |

### Use-Case 2

| IP Address           | Count | Domain                          | User                              | Password         | Count    | Family     |
|----------------------|-------|---------------------------------|-----------------------------------|------------------|----------|------------|
| ```85.187.154.178``` | 28    | ```mail.flood-protection.org``` | ```clark@flood-protection.org```  | ```clark2424@``` | 3        | AgentTesla |
|                      |       |                                 | ```fido@flood-protection.org```   | ```fido2424@```  | 3        | AgentTesla |
|                      |       |                                 | ```sender@flood-protection.org``` | ```kelex2424@``` | 10</br>2 | AgentTesla</br> MassLoggger |
|                      |       |                                 | ```somc@flood-protection.org```   | ```somc2424@```  | 2        | AgentTesla |
|                      |       |                                 | ```wale@flood-protection.org```   | ```wale2424@```  | 2        | AgentTesla |
|                      |       |                                 | ```udug@flood-protection.org```   | ```udug2424@```  | 1        | AgentTesla |
|                      |       |                                 | ```sepp@flood-protection.org```   | ```sepp2424@```  | 4        | AgentTesla |
|                      |       |                                 | ```dom@flood-protection.org```    | ```dom2424@```   | 1        | AgentTesla |

### Use-Case 3

Same operator attempted to change by using the "kingmezz" domain, though everything else is almost the same.

| User                     | Count | Password                | Family     |
|--------------------------|-------|-------------------------|------------|
| ```urch@damienzy.xyz```  | 5     | ```@damienzy.xyz2240``` | AgentTesla |
| ```david@damienzy.xyz``` | 4     | ```@damienzy.xyz2240``` | AgentTesla |
| ```ck@kingmezz.xyz```    | 1     | ```@kingmezz.xyz```     | AgentTesla |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'FTP vs. SMTP'

This group of operators alernates between SMTP and FTP exfiltration under the same domain. Each domain has two sub-domains based on the exfiltration path configured in the sample.

### Use-Case 1

| Domain                                         | Count   | IP Address         | Count |
|------------------------------------------------|---------|--------------------|-------|
| ```mail.flyxop.com```</br>```ftp.flyxpo.com``` | 8</br>5 | ```67.225.141.8``` | 13    |

| User                   | Count | Password               | Count | Protocol |
|------------------------|-------|------------------------|-------|----------|
| ```stan@flyxpo.com```  | 10    | ```schenkerokani123``` | 8     | FTP      |
| ```kene@flyxpo.com```  | 5     | ```success2020@```     | 3     | SMTP     |
| ```xmweb@flyxpo.com``` | 5     | ```Success0803959```   | 2     | SMTP     |

### Use-Case 2

| Domain                                                                           | Count   | IP Address          | Count |
|----------------------------------------------------------------------------------|---------|---------------------|-------|
| ```mail.scandinavian-collection.com```</br>```ftp.scandinavian-collection.com``` | 1</br>2 | ```206.72.205.67``` | 3     |

| User                                  | Count | Password                                   | Count   | Protocol     |
|---------------------------------------|-------|--------------------------------------------|---------|--------------|
| ```may@scandinavian-collection.com``` | 3     | ```kR6d.DFet#7w```</br> ```=piYR_r.%[Ch``` | 1</br>2 | SMTP</br>FTP |

[Top](#information-stealers-wall-of-sheep-analysis)

## Correlation 'I Speak FTP Only'

Operators in this correlation solely utilize FTP for exfiltration in their samples. One exception to this rule is the operator "tashipta", and only when they shifted from AgentTesla to MassLogger. In the MassLogger sample, the operator configured both, FTP and SMTP (abusing Gmail) exfiltration.

| Domain                 | Count | IP Address         | Count |
|------------------------|-------|--------------------|-------|
| ```ftp.tashipta.com``` | 10    | ```103.21.59.28``` | 11    |

| Password            | Count | User                                                    | Count   | Fmaily     | Protocol |
|---------------------|-------|---------------------------------------------------------|---------|------------|----------|
| ```server1123455``` | 3     | ```server@tashipta.com```                               | 3       | AgentTesla | FTP      |
| ```router11477```   | 2     | ```router11477@tashipta.com```                          | 2       | AgentTesla | FTP      |
| ```server1543211``` | 2     | ```server1@tashipta.com```                              | 2       | AgentTesla | FTP      |
| ```success2020```   | 2     | ```mails@tashipta.com```</br>```server1@tashipta.com``` | 1</br>1 | AgentTesla | FTP      |
| ```prosperity1```   | 1     | ```xmoni@tashipta.com```                                | 1       | AgentTesla | FTP      |
| ```@Success$2020``` | 1     | ```xmoni-w@tashipta.com```                              | 1       | MassLogger | FTP      |
| ```moneymustdrop``` | 1     | ```fletcherjohnsgt@gmail.com```                         | 1       | MassLogger | SMTP     |

Additional FTP-based samples.

| Domain                           | Count | IP Address            | User                                                     | Password                                  | Family                 |
|----------------------------------|-------|-----------------------|----------------------------------------------------------|-------------------------------------------|------------------------|
| ```ftp.kassohome.com.tr```       | 5     | ```95.130.175.151```  | ```bringlogs@kassohome.com.tr```                         | ```J%jCb2L=!5~E```                        | AgentTesla</br>HawkEye |
| ```ftp.fox8live.com```           | 3     | ```207.191.38.36```   | ```production```                                         | ```pr0duct10n```                          | AgentTesla             |
| ```ftp.trirekaperkasa.com```     | 2     | ```139.162.57.218```  | ```trirek@trirekaperkasa.com```                          | ```^CuvfABJJ1OM```                        | AgentTesla             |
| ```ftp.hustle360.a2hosted.com``` | 2     | ```68.66.248.24```    | ```kftp@hustle360.a2hosted.com```                        | ```-szG^tj_nEpo```                        | AgentTesla             |
| ```ftp.exploits.site```          | 2     | ```199.188.206.58```  | ```bbstar@exploits.site```</br>```milli@exploits.site``` | ```{Zo3Dn4H#3G)```</br>```)J@i^p#%m4*N``` | AgentTesla             |
| ```files.000webhost.com```       | 2     | ```145.14.145.53```   | ```plein-air-adhesives```                                | ```dragonflam123```                       | HawkEye                |
| ```ftp.aydangroup.com.my```      | 2     | ```43.252.214.149```  | ```original@aydangroup.com.my```                         | ```^l@2~))DQq,z```                        | AgentTesla             |
| ```ftp.filelog.info```           | 1     | ```162.213.253.54```  | ```Burna@filelog.info```                                 | ```^{Opb6h,rjW^```                        | HawkEye                |
| ```ftp.faltelecom.com```         | 1     | ```43.255.154.108```  | ```faltelecom@faltelecom.com```                          | ```Playboy@11```                          | HawkEye                |
| ```ftp.eloelokendi.com```        | 1     | ```107.172.93.44```   | ```hhhpp@eloelokendi.com```                              | ```boygirl654321```                       | HawkEye                |
| ```ftp.connectus-trade.net```    | 1     | ```104.247.74.6```    | ```one@connectus-trade.net```                            | ```o^Z0CIU?^yL2```                        | AgentTesla             |
| ```ftp.nedtek.com.au```          | 1     | ```116.0.23.212```    | ```abs00001@nedtek.com.au```                             | ```philomina1234567890```                 | AgentTesla             |
| ```ftp.talleresmartos.com```     | 1     | ```149.202.247.154``` | ```ntums@talleresmartos.com```                           | ```alibaba.com```                         | MassLogger             |

[Top](#information-stealers-wall-of-sheep-analysis)

## Information Stealers HTTP Panels

Some samples opted to exfiltrate via HTTP only, or both HTTP and SMTP.

| Family     | MD5                                    | Exfil. URL                                                              | Panel URL                                                                    | IP:Port                |
|------------|----------------------------------------|-------------------------------------------------------------------------|------------------------------------------------------------------------------|------------------------|
| M00nD3v    | ```10e2d3c8c81501b0b70f6cdf8ea5c872``` | ```http://ark.makinghapen.com/api.php```                                | ```http://ark.makinghapen.com/?signin```                                     | ```104.28.24.79:80```  |
| MassLogger | ```e52e5dd7cd8cda6e283f96a76a5f4855``` | ```http://yatesassociates.co.za/panel/upload.php```                     | ```http://yatesassociates.co.za/panel/login/index.php```                     | ```196.41.127.42:80``` |
| MassLogger | ```14a59177297e9458dafa83ef55acd445``` | ```https://drngetu.co.za/fruit/panel/upload.php```                      | ```https://drngetu.co.za/fruit/panel/login/index.php```                      | ```154.0.175.94:443``` |
| MassLogger | ```eaa8776e7fe85e8f5f8e240a94ff0eaf``` | ```https://baileybluesclothing.com/themes/wind/images/ukr/upload.php``` | ```https://baileybluesclothing.com/themes/wind/images/ukr/login/index.php``` | ```68.66.216.8:443```  |


- ```10e2d3c8c81501b0b70f6cdf8ea5c872```</br>
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/m00ndev_panel_10e2d3c8c81501b0b70f6cdf8ea5c872.png)

- ```e52e5dd7cd8cda6e283f96a76a5f4855```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_e52e5dd7cd8cda6e283f96a76a5f4855.png)

- ```14a59177297e9458dafa83ef55acd445```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_14a59177297e9458dafa83ef55acd445.png)

- ```eaa8776e7fe85e8f5f8e240a94ff0eaf```
  ![image](https://github.com/ditekshen/is-wos/raw/master/img/masslogger_panel_eaa8776e7fe85e8f5f8e240a94ff0eaf.png)

[Top](#information-stealers-wall-of-sheep-analysis)

#AS20201111