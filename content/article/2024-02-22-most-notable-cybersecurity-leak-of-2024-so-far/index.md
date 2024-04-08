---
title: "Most Notable Cybersecurity Leak of 2024 So Far - The I-Soon Leak Reveals a Trove of Information About Chinese State-Supported Hacking Operations"
date: 2024-02-22T19:28:11+03:00

categories: ["IT and Cybersecurity"]
tags: ["Cybersecurity", "Hacking"]
toc: false
author: "Petteri Nakamura"
---

I-Soon (上海安洵) is a Shanghai based Chinese info-sec company that contracts for many Chinese government agencies like the Ministry of Public Security, Ministry of State Security, and People’s Liberation Army. A trove of documents and chat messages between employees was leaked on GitHub on 16 February showing inner workings of the company, targeted organizations and fees earned from hacking them (Apparently collecting data from the Vietnam Ministry of Economy was worth $55 000 and access to a Vietnamese traffic police private website was worth $15 000), technical documents showing custom snooping devices, people complaining about low wages, and a discussion about receiving zero-day vulnerabilities from the Chinese government.

The story hit the news internationally in the beginning of the week with also the Finnish national news agency Yle running a story. The www.i-soon.net website was down on Thursday and according to the news the Chinese police is looking for the "whistleblower". This unique data leak is going to keep security researchers busy for some time. While reviewing the material, the discussion about zero-day vulnerabilities caught my eye. Zero-day vulnerabilities are vulnerabilities in software products unknown to the vendors so there is no way to defend against exploiting them, as there are no fixes available and people don’t even know about them. A zero-day vulnerability is therefore particularly useful for an attacker, but it loses it’s usefulness as soon as it is discovered and fixed, or other ways to defend against it are found. In 2021 China published regulations requiring all companies operating within the country to report all discovered vulnerabilities to the Ministry of Industry and Information Technology (MIIT) within two days.  The motivation for this was broadly suspected to be collecting and weaponizing zero-day vulnerabilities for use in hacking operations and, for example, the CEO of Qihoo360, a Chinese cybersecurity company, reportedly called zero-day vulnerabilities "important strategic resources" that should remain within China.

The next year Microsoft reported an increase in the number of zero-day vulnerabilities exploited by China-attributed hacking groups. Later the new Chinese cybersecurity and anti-espionage laws also prohibited disclosure of information that is in Chinese national interests (very broad definition) by any company operating in China to foreign governments without express permission from the Chinese authorities. The regulations show an apparent concerted effort to collect zero-day vulnerabilities as soon as they are found and to prevent them from being reported elsewhere.

The I-Soon leak includes employees discussing receiving zero-day vulnerabilities, that were found in the Chinese Tianfu cup cybersecurity contest, and proofs of concept (POC) for them from the government, and turning the POC's to exploit code (EXP) for their operations. The conversation suggests a prioritization system where vulnerabilities are distributed to various provinces and further to different operators based on some kind of strategic importance consideration. The apparent targets mentioned in the material include NATO and government organizations and telecom companies in several countries including UK, South Korea, Thailand and India. 

The leak appears to have been done to embarrass the company but it also gives a one of a kind window into the operation of these companies and the ecosystem of Chinese state-supported hacking operations, carried out by Chinese private contractors. This is a wake-up call for all companies and organizations and shows what kinds of tools and support these companies have at their disposal. Dakota Cary and Aleksandar Milenkoski from Sentinel Labs remarked that for business leaders the message is: "your organization’s threat model likely includes underpaid technical experts making a fraction of the value they may pilfer from your organization".

Don’t forget that the underpaid hackers are armed with state collected and distributed zero-day vulnerabilities and proofs of concepts to facilitate their work. 

- https://www.sentinelone.com/labs/unmasking-i-soon-the-leak-that-revealed-chinas-cyber-operations/
- https://www.atlanticcouncil.org/in-depth-research-reports/report/sleight-of-hand-how-china-weaponizes-software-vulnerability/
- https://eu.usatoday.com/story/news/world/2024/02/22/chinese-hacking-company-i-soon-document-leak/72696462007/
- https://yle.fi/a/74-20075858

