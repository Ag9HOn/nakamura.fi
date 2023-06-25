---
title: "D.. What? SPF, DKIM, and DMARC; What Exactly Are They"
date: 2019-01-09T19:28:11+03:00

categories: ["IT and Cybersecurity"]
tags: ["DMARC", "DKIM", "SPF", "Email",]
toc: false
author: "Petteri Nakamura"
---

IT is wrought with acronyms and e-mail is no exception. In this post, I will explain how these three help battle spam and other malicious emails, that we all get every day. All of these work behind the scenes and are not visible to the end users of e-mail services, if they don't go looking for them specifically.


# Some Background

I have often likened e-mail to sending post cards. You write your message on a piece of hard paper, add the recipient address, sign your name, and off it goes. The post office delivers the card but the recipient, upon accepting the message, has no way of knowing that it actually came from you. E-mail was born to a time that could not foresee the immense problems caused by spam and phishing these days, thus the original standard and implementations do not provide any authentication methods and anyone can send email as anyone from anywhere. Just write what ever you want on the card, impersonating anyone you like, and send the message away. The person being impersonated won't have any idea of the fact unless the recipient contacts him directly.

This creates a two-fold problem. The recipient of the messages needs to be able to decide which ones are genuine and which ones are not. On the other hand, the sender needs to be able to convince the recipient that the message actually came from. It would also be great if he had a way of knowing if someone was sending messages in his name, and to prevent it, as he stands to to incur significant harm in reputation from such spoofing.

As the problems of spamming and phishing are becoming more prominent, different parties have come up with all kinds of methods of checking e-mails in order to decide if they are legitimate, unwanted, scams, or outright malicious and dangerous. This is largely based on guesswork, but the dawn of the third millennia has seen new techniques to address this problem, that are slowly gaining ground. The responsibility to check and respect the policies, laid down by the sending organization, still completely lies with the receiver of e-mail, but SPF, DKIM, and DMARC together form a toolbox for e-mail administrators to publish rules for where they allow their e-mail to originate, cryptographically prove that the messages actually originate from their systems, and to give the recipient systems instructions on how to verify the messages, what to do with the messages that don't pass the scrutiny, and how to report back about the behavior of the originating systems.


# SPF

SPF stands for Sender Policy Framework and is basically a way for the domain administrator to publish a list of internet addresses that are allowed to send e-mail using their domain name along with a policy for what to do with messages from other sources. To continue the post office analogy, a company would publish a policy saying something like "our company sends all of it's mail through this post office in Helsinki, please, discard any message that doesn't come from there", the receiving post office will then check the cancellation mark on the stamp, before delivering it to the recipient, and discard the message if it isn't stamped by the authorized post office.

SPF was [published as experimental in 2006](https://tools.ietf.org/html/rfc4408) and as [proposed standard in 2014](https://tools.ietf.org/html/rfc7208). According to a [recent study by Hang Hu and Gang Wang](https://people.cs.vt.edu/gangwang/usenix-draft.pdf) from Virginia Tech, 44.9% of the domains for the [Alexa](https://aws.amazon.com/alexa-top-sites/) 1 million top sites had valid SPF records in January 2018 (40% in 2015) and for the top 1000 popular sites, the adoption rate was 73%. According to Hu and Wang, 31 out of 35 large e-mail service providers, tested in their study, support SPF and [Google reports](https://security.googleblog.com/2013/12/internet-wide-efforts-to-fight-email.html) that in 2016 95.7% of all incoming e-mail, that they see, is protected by SPF. Of the three techniques, SPF is thus the most widely deployed.


# DKIM

While SPF is used to specify where a message may originate from, DomainKey Identified Mail, or DKIM, is used to authenticate the sender. In the post office example, a company, using the post service, has published a key that can be used to check the signatures on any messages that they send. An employee would write a message and submit it for the company for delivery. The company will then take the message and sign it along with instructions for where to find the key to check the signature. The message is then given to the authorized post office that will deliver it to the post office responsible for delivering it to the end recipient. Before delivery, the receiving post office will find the message signed with the company signature, go find the public key using the instructions by the company, and check the signature. If the signature matches the public key, the recipient will know that the author of the message was authorized by the company to send it.

A [Proposed Standard](https://tools.ietf.org/html/rfc4871) for DKIM was published in 2007 and an [Internet Standard](https://tools.ietf.org/html/rfc6376) was published in 2011. Google reports that in 2016 87,6% of all incoming e-mail, that they see, was DKIM protected and Hu and Wang report that 27 out of 35 large email service providers in their study support DKIM.


# DMARC

Domain-based Message Authentication, Reporting and Conformance, or DMARC, is the newest of the three and was created on top of SPF and DKIM to enable senders to publish policies regarding the handling of unauthenticated e-mail, and to enable them to receive reports from the recipients regarding the authentication of the e-mails. In the post office example, the company now also publishes a policy that says something like "We use SPF and DKIM to authenticate our mail, we require all out-going email to comply with the SPF policy and to be signed by our company. Please, discard any message that doesn't fulfill these requirements, and send your reports to this address". The employee will submit the message to the company for delivery, the company will sign it and give it to the authorized post office, the message will be delivered to the receiving post office, who will first check if the sender has a DMARC policy, then check that the message came from the required post office, then check that the signature on the message matches to the public key that the company has published, and only then deliver the message to the recipient as all requirements are met. Lastly, the receiving post office compiles a report of all passed and failed messages from the sender and sends the report to the address defined by the company

A draft specification for DMARC has been maintained since 2012 and an [informational Request for Comments](https://tools.ietf.org/html/rfc7489) was published in 2015. Hu and Wang report that in 2018 16 out of 35 large email service providers support DMARC and 5.1% of the 1 million domains have valid DMARC records, but for the 1000 most popular domains the number is a whopping 41%, which in my opinion is a very good number considering how new the protocol is and the 73% adoption rate for SPF.


# The Low Hanging Fruits

Setting up SPF is already quite a standard thing to do when setting up e-mail for your company, whether you are setting up e-mail in a hosted system like O365 or G Suite, or setting up an on-premises mail system. With the former the service provider will provide you with the SPF record that you need to create in your public Domain Name Service (DNS), and with the latter you need the public IP address of your sending e-mail server for the DNS. If you have multiple servers sending e-mail, this will cause other email servers to drop some of your e-mails if you didn't specify all of the IP addresses.

With DKIM you need to generate a private/public key pair, publish the public key, and use the private key to sign your outgoing e-mail. With a hosted system the service provider will do most of this for you and you only need to publish the public key, but with an on-premises solution you will need to configure everything yourself. DKIM however doesn't include policies, so setting it up won't affect the delivery of other, unsigned, e-mails until you set up your DMARC record.

DMARC is enabled by creating a _dmarc record for the domain in DNS. DMARC also allows for creating a policy that lets all messages pass and gives the recipients the e-mail address where to send the reports, so if you have some infrastructure in place already and you're not sure where all the e-mail is being sent from, you can create the record and start collecting the reports to find out what's going on. When you have correctly set up SPF and/or DKIM, you can start gradually making the policy stricter while monitoring the impact.

If a domain is not meant to send e-mail at all, it makes sense to still set up a DMARC Reject policy so no-one can spoof it.

# Sources and Referenced Material

- https://people.cs.vt.edu/gangwang/usenix-draft.pdf
- https://security.googleblog.com/2013/12/internet-wide-efforts-to-fight-email.html
- https://tools.ietf.org/html/rfc4408
- https://tools.ietf.org/html/rfc7208
- https://tools.ietf.org/html/rfc4871
- https://tools.ietf.org/html/rfc6376
- https://tools.ietf.org/html/rfc7489
- https://aws.amazon.com/alexa-top-sites/
- https://en.wikipedia.org/wiki/Sender_Policy_Framework
- https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail
- https://en.wikipedia.org/wiki/DMARC

