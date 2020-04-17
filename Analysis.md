## Correlation 'Repetition Makes Perfect'

44 unique samples distributed between AgentTesla-T1 and AgentTesla-T2 that do not issue DNS queries as part of therir C&C as seen in the "Top 10 Domains" table. 42 samples exfiltrate to two IP addresses on the same /24 subnet on Virtual Systems LLC. Emails addresses, particularly the user and recipient addresses as well as passwords follow the same patterns, potenially linking all 43 samples to the same operator.

| IP Address    | Count |
|---------------|-------|
| 77.83.117.234 | 2     |
| 78.142.19.101 | 10    |
| 78.142.19.111 | 32    |
  
| User                           | Recipient                       | Password | Count |
|--------------------------------|---------------------------------|----------|-------|
| brooyu\@larbaxpo.com            | brooyu1@larbaxpo.com           | UmX3iJQg | 32    |
| urc@emmannar.com               | urc1@emmannar.com               | r1NmBO4h | 4     |
| dave@emmannar.com              | dave1@emmannar.com              | cwEqoinR | 4     |
| pcs@deepsaeemirates.com        | pcs1@deepsaeemirates.com        | J3fP8xWq | 2     |
| auth@deepsaeemirates.com       | hp@deepsaeemirates.com          | 8txksCNY | 1     |
| slimshades@deepsaeemirates.com | slimshades1@deepsaeemirates.com | NAEgz9DX | 1     |

## Correlation 'Fire Them'

The operators in this correlation mostly utilize HawkEye with 34 unique samples. Between 2020-03-19/20 and 2020-03-24/25 and forward, the operators started utilizing AgentTesla-T2 with 11 unique samples. The accounts and passwords used across both families overlap. The operators are also active in creating new accounts and regularly changing passwords of existing accounts. If you work with or hire these operators, quit or fire them, they are already costing you money.

HawkEye Samples:

| User                         | Count | Password          | Count |
|------------------------------|-------|-------------------|-------|
| produccion@servalec-com.me   | 4     | biggod1234        | 2     |
|                              |       | BIGgod1234        | 1     |
|                              |       | @bongo1.,         | 1     |
| success@poylone.com          | 3     | @qwerty12345      | 3     |
| wetground@poylone.com        | 3     | @qwerty12345      | 3     |
| charif.yassin@cronimet.me    | 3     | @mile31.,         | 3     |
| panos@skepsis-sg.icu         | 2     | @Bongo1.,         | 1     |
|                              |       | breakinglimit@    | 1     |
| service@ptocs.xyz            | 2     | bigGod1234@       | 2     |
| gavin@jandregon.com          | 2     | WHYworry??#       | 2     |
| yosra.gamal@csatolin.com     | 2     | @Mexico1.,        | 1     |
|                              |       | HELPmeLORD@       | 1     |
| stephanie.giet@technsiem.com | 1     | Whyworry90#       | 1     |
| parisa@abarsiava.com         | 1     | @Mexico1.,        | 1     |
| jplunkett@bellfilght.com     | 1     | biggod12345@      | 1     |
| ikuku@poylone.com            | 1     | GODhelpme@#       | 1     |
| sav@emeco.icu                | 1     | GodsPlan@#        | 1     |
| raphael@gitggn.com           | 1     | @mexico1.,        | 1     |
| v.clemens@slee-de.me         | 1     | @mexico1.,        | 1     |
| sale@somakinya.com           | 1     | Wenenighty.,      | 1     |
| xu@weifeng-fulton.com        | 1     | @bongo1.,         | 1     |
| jamit@cairoways.icu          | 1     | breakinglimit100% | 1     |
| accounts@friendships-ke.icu  | 1     | INGODWETRUST      | 1     |
| dcaicedo@igihm.icu           | 1     | STAYSAFE123       | 2     |
| ahmadi@gheytarencarpet.com   | 1     | Focus$Pray        | 1     |

AgentTesla-T2 Samples:

| User                         | Count | Password          | Count |
|------------------------------|-------|-------------------|-------|
| jplunkett@bellfilght.com     | 2     | biggod12345@      | 2     |
| dcaicedo@igihm.icu           | 2     | MOREMONEY123      | 2     |
| charif.yassin@cronimet.me    | 1     | @mile31.,         | 1     |
| gavin@jandregon.com          | 1     | WHYworry??#       | 1     |
| stephanie.giet@technsiem.com | 1     | Whyworry90#       | 1     |
| ikuku@poylone.com            | 3     | BLESSEDchild@     | 1     |
|                              |       | GodAbegOo#        | 1     |
|                              |       | HELPmeLORD@       | 1     |
| yosra.gamal@csatolin.com     | 1     | HELPmeLORD@       | 1     |

## Correlation 'Impersonation'

4 uniqe AgentTesla-T2 samples, potentially attempting to impersonate General Electric (GE) with the use of a look-a-like typosquatted domain.

| User                  | Count | Domain               | Password | Count |
|-----------------------|-------|----------------------|----------|-------|
| slim1@ge-lndustry.com | 4     | smtp.ge-lndustry.com | J)*(EIv4 | 4     |

## Correlation 'Steering Towards Arid Yandex Pastures'

### Use-Case 1

The operator strykeir is prolific with 33 unique samples distributed between AgentTesla-T1 and AgentTesla-T2. One of the samples used a different password. Pivoting on this password reveals that the same password is also used with different accounts, more recently with a Yandex account.

| User                           | Count | Password      | Count |
|--------------------------------|-------|---------------|-------|
| star-origin@strykeir.com       | 33    | iyke112@@@333 | 32    |
|                                |       | @@Io419090@@  | 1     |

| User                        | Count | Password     | Count |
|-----------------------------|-------|--------------|-------|
| staronuegbu@yandex.com      | 6     | @@Io419090@@ | 10    |
| hselimoglu@bmssrevis.com    | 2     |              |       |
| brajesh@cropchemicals.co.in | 1     |              |       |
| star-origin@strykeir.com    | 1     |              |       |

### Use-Case 2

Another sample shifting to Yandex is the operator of the trevisqa domain. With only 9 unique AgentTesla-T2 samples sharing the same account password, the shift occured from the custom account in 6 samples to 2 more recent samples with Yandex.

| User                   | Count | Password     | Count |
|------------------------|-------|--------------|-------|
| yyaqob@trevisqa.com    | 6     | greateman32  | 9     |
| fffffffgggd@yandex.com | 3     |              |       |


In general, 84 AgentTesla-T2 and 2 HawkEye samples rely on Yandex for data exfiltration.

| User                          | Password            | Family                 | Count |
|-------------------------------|---------------------|------------------------|-------|
| mullarwhite@yandex.com        | challenge12345      | AgentTesla-T2          | 10    |
| tim3.44@yandex.com            | Obaten10            | AgentTesla-T2          | 7     |
| ikpc1@yandex.com              | ikechukwu112        | AgentTesla-T2          | 7     |
| staronuegbu@yandex.com        | @@Io419090@@        | AgentTesla-T2          | 6     |
| okirinwajesus@yandex.com      | 07062487004         | AgentTesla-T2          | 5     |
| selecttools@yandex.com        | biafra123           | AgentTesla-T2          | 4     |
| johnsonpikyu@yandex.com       | cr*fDaW&m@2y6u      | AgentTesla-T2          | 4     |
| genuxpc@yandex.com            | africa@@@@@         | AgentTesla-T2          | 4     |
| chijiokejackson121@yandex.com | chijiokejackson     | AgentTesla-T2          | 4     |
| rose.nunez@yandex.ru          | lochmann2           | AgentTesla-T2          | 3     |
| r.tome@yandex.com             | qwerty123@@         | AgentTesla-T2          | 3     |
| fffffffgggd@yandex.com        | greatman32          | AgentTesla-T2          | 3     |
| chi.eb@yandex.com             | sages101            | AgentTesla-T2          | 3     |
| sleeves100@yandex.com         | @Sleeves100         | AgentTesla-T2          | 2     |
| resultbox042@yandex.com       | OGOM12345           | AgentTesla-T2          | 2     |
| p.origin@yandex.com           | Loverboy123         | AgentTesla-T2          | 2     |
| boymouse@yandex.com           | 333link00win        | AgentTesla-T2, HawkEye | 2     |
| lucinedauglas@yandex.com      | myhp6000            | AgentTesla-T2          | 2     |
| zhu.china@yandex.com          | KOSI213141          | AgentTesla-T2          | 1     |
| sly-originlogs@yandex.ru      | JesusChrist007      | AgentTesla-T2          | 1     |
| oriego1@yandex.ru             | Ijeomam288          | AgentTesla-T2          | 1     |
| iykelog1@yandex.com           | Conversation2       | AgentTesla-T2          | 1     |
| iren159k@yandex.com           | Protected@123       | AgentTesla-T2          | 1     |
| import22.export@yandex.com    | khalifa2019         | AgentTesla-T2          | 1     |
| freshclinton8269@yandex.com   | fresh826699         | AgentTesla-T2          | 1     |
| cupjul@yandex.com             | esut96092           | HawkEye                | 1     |
| blr@saharaexpress.com         | Sahara*542          | AgentTesla-T2          | 1     |
| acksonjogodo121@yandex.com    | jacksonjogodo       | AgentTesla-T2          | 1     |
| account.info1000@yandex.com   | 4canada1A@          | AgentTesla-T2          | 1     |
| annwilso@yandex.com           | theoldlady          | AgentTesla-T2          | 1     |
| annwilso@yandex.com           | HueCycle            | AgentTesla-T2          | 1     |

## Correlation 'God is Great'

27 unique samples distributed among HawkEye, AgentTesla-T2 and AgentTesla-T1, respectively, had religiously themed passwords, with specific patterns that potentially tie the accounts to the same operator. This is particularly evident when the origins of samples are correlated to the same source(s). No God condones theft, stealing, or crime.

| User                        | Count | Password            | Count | Family                 |
|-----------------------------|-------|---------------------|-------|------------------------|
| ikuku@poylone.com           | 4     | GODhelpme@#         | 1     | HawkEye                |
|                             |       | BLESSEDchild@       | 1     | AgentTesla-T2          |
|                             |       | GodAbegOo#          | 1     | AgentTesla-T2          |
|                             |       | HELPmeLORD@         | 1     | AgentTesla-T2          |
| yosra.gamal@csatolin.com    | 1     | HELPmeLORD@         | 2     | HawkEye                |
| produccion@servalec-com.me  | 3     | biggod1234          | 2     | HawkEye                |
|                             |       | BIGgod1234          | 1     | HawkEye                |
| jplunkett@bellfilght.com    | 3     | biggod12345@        | 3     | HawkEye, AgentTesla-T2 |
| jasmine@cinco.icu           | 3     | Biggod1234          | 2     | HawkEye                |
|                             |       | biggod1234          | 1     | HawkEye                |
| elber@wtsele.net            | 2     | .,?!miracleGod12345 | 2     | AgentTesla-T2          |
| imports@eastendfood-uk.icu  | 2     | GodGrace6665555     | 2     | HawkEye                |
| carolyne@dandopub.mu        | 2     | OhMyGod#357         | 2     | AgentTesla-T1          |
| service@ptocs.xyz           | 2     | bigGod1234@         | 2     | HawkEye                |
| sav@emeco.icu               | 1     | GodsPlan@#          | 1     | HawkEye                |
| frank.got@yandex.ru         | 1     | godson00            | 1     | AgentTesla-T2          |
| accounts@friendships-ke.icu | 1     | INGODWETRUST        | 1     | HawkEye                |
| contact@assocham.icu        | 1     | GODSGRACE123        | 1     | HawkEye                |
| ahmadi@gheytarencarpet.com  | 1     | Focus$Pray          | 1     | HawkEye                |
| sly-originlogs@yandex.ru    | 1     | JesusChrist007      | 1     | AgentTesla-T2          |

# Correlation 'Why even bother?'

Some operators attempted to hide thier repetitive offenses by using different recipient addresses, domains, or accounts and passwords as demonestrated in the below two uses cases.

### Use-Case 1

| User                    | Count | Password | Recipient                 | Family        |
|-------------------------|-------|----------|---------------------------|---------------|
| ikostadinov@cargoair.bg | 10    | 334455   | info@agri-chernicals.net  | AgentTesla-T2 |
|                         |       |          | grace_pan@traingle-cn.com |               |
|                         |       |          | e.pezzli@giivin.com       |               |
|                         |       |          | stan@iskreameco.com       |               |
|                         |       |          | brunolugnani@arrmet.in    |               |
|                         |       |          | neo.ycwang@mindroy.com    |               |

### Use-Case 2

| IP Address    | Count | Domain               | User                   | Password           | Family        |
|---------------|-------|----------------------|------------------------|--------------------|---------------|
| 162.241.27.33 | 10    | mail.platinships.net | amani@platinships.net  | Azz%LcQK%sb!       | AgentTesla-T2 |
|               |       | mail.platinships.net | garang@platinships.net | %izARl@$-zHKEYwlHM | AgentTesla-T2 |
|               |       | mail.platinships.net | phyno@platinships.net  | J~5v.F5[G06H6}ct{! | AgentTesla-T2 |
|               |       | mail.platinships.net | chima@platinships.net  | R[2](NaueJp!6tL?sW | AgentTesla-T2 |
|               |       | mail.novaa-ship.com  | ebase@novaa-ship.com   | O-xgNxpHw~?h5H.ZEB | AgentTesla-T2 |
|               |       | mail.novaa-ship.com  | flo@novaa-ship.com     | KyayQQ{Kn$TJ+f;dRd | AgentTesla-T2 |
|               |       | mail.novaa-ship.com  | armani@novaa-ship.com  | Azz%LcQK%sb!       | HawkEye       |

## Correlation '.,'

Some samples, mostly HawkEye, associated with the same actor alternated the accounts as well as the paswords used for exfiltration. Yet, the passwords still followed the same pattern, not to mention the origins of these samples.

| User                       | Count | Password     | Count | Family                 |
|----------------------------|-------|--------------|-------|------------------------|
| charif.yassin@cronimet.me  | 5     | @mile31.,    | 5     | HawkEye, AgentTesla-T2 |
| xu@weifeng-fulton.com      | 3     | @bongo1.,    | 3     | HawkEye                |
| produccion@servalec-com.me | 2     | @bongo1.,    | 2     | HawkEye                |
| info@friendships-ke.icu    | 1     | @bongo1.,    | 1     | HawkEye                |
| panos@skepsis-sg.icu       | 1     | @Bongo1.,    | 1     | HawkEye                |
| michellej@fernsturm.com    | 1     | @Ranger1.,   | 1     | AgentTesla-T2          |
| raphael@gitggn.com         | 1     | @mexico1.,   | 1     | HawkEye                |
| v.clemens@slee-de.me       | 1     | @mexico1.,   | 1     | HawkEye                |
| parisa@abarsiava.com       | 1     | @Mexico1.,   | 1     | HawkEye                |
| yosra.gamal@csatolin.com   | 1     | @Mexico1.,   | 1     | HawkEye                |
| sale@somakinya.com         | 1     | Wenenighty., | 1     | HawkEye                |

### Correlation 'Encrypt or not to Encrypt'

22 unique AgentTesla-T2 samples exfiltrating to a Saudi domain associated with 2 IP addresses, both belonging to Hetzner Online GmbH, appear to encrypt SMTP with one account but not the other, despite the fact that their passwords simply swtich word locations, suggesting that both accounts belonging to the same operator.

* Registrant Org: مصنع وضوح الشرق للحديد (Bright East Steel Factory)
* Registrant Country: المملكة العربية السعودية (Kingdom of Saudia Arabia)
* Tech Contact: وضحي محمد (Wadhi Mohammed)

| Domain            | Count | IP Address      | Count |
|-------------------|-------|-----------------|-------|
| mail.besco.com.sa | 22    | 136.243.194.254 | 15    |
|                   |       | 46.4.159.174    | 7     |

| User                | Count | Password       | Count |
|---------------------|-------|----------------|-------|
| khalid@besco.com.sa | 16    | besco2020admin | 16    |
| pavan@besco.com.sa  | 6     | admin2020besco | 6     |

| User                | SMTPS | Count |
|---------------------|-------|-------|
| khalid@besco.com.sa | false | 15    |
| khalid@besco.com.sa | true  | 1     |
| pavan@besco.com.sa  | true  | 6     |

### Correlation 'FTP vs. SMTP'

The operator of the flyxpo domain with unique 13 AgentTesla-T2 samples and C&C to single IP address on Liquid Web, L.L.C, exclusively. The operator alternates between FTP and SMTP for exfiltration, each of which has their own sub-domain, aptly named, ftp and mail.

| Domain          | Count | IP Address   | Count |
|-----------------|-------|--------------|-------|
| mail.flyxop.com | 8     | 67.225.141.8 | 13    |
| ftp.flyxpo.com  | 5     |              |       |

| User             | Count | Password         | Count |
|------------------|-------|------------------|-------|
| stan@flyxpo.com  | 10    | schenkerokani123 | 8     |
| kene@flyxpo.com  | 5     | success2020@     | 3     |
| xmweb@flyxpo.com | 5     | Success0803959   | 2     |

| User             | Domain           | Count |
|------------------|------------------|-------|
| stan@flyxpo.com  | ftp.flyxpo.com   | 8     |
| kene@flyxpo.com  | mail.flyxpo.com  | 3     |
| xmweb@flyxpo.com | mail.flyxpo.com  | 2     |

### Correlation 'I Speak FTP Only'

The 10 samples evenly distributed between HawkEye and AgentTesla-T2 exfiltrating to the tashipta domain only do so over FTP. Only a signle aptly named sub-domain associating to a single IP address are used. Almost all passwords relate to their respective account. 

| Domain          | Count | IP Address   | Count |
|-----------------|-------|--------------|-------|
|ftp.tashipta.com | 10    | 103.21.59.28 | 10    |

| Password      | Count | User                     | Count |
|---------------|-------|--------------------------|-------|
| server1123455 | 3     | server@tashipta.com      | 3     |
| router11477   | 2     | router11477@tashipta.com | 2     |
| server1543211 | 2     | server1@tashipta.com     | 2     |
| success2020   | 2     | mails@tashipta.com       | 1     |
|               |       | server1@tashipta.com     | 1     |
| prosperity1   | 1     | xmoni@tashipta.com       | 1     |


#AS20200417