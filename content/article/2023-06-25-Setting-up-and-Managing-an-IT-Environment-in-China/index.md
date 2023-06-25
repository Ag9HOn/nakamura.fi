---
title: "Setting up and Managing an IT Environment in China"
date: 2023-06-25T15:28:11+03:00

categories: ["IT and Cybersecurity"]
tags: ["China", "IT"]
toc: true
author: "Petteri Nakamura"
---


In the past six and half years, I've had the privilege to serve in various IT roles in a company with an office in China. Through roles as a Network and Server Administrator, IT Service Manager, and a Cybersecurity Manager, I've gained unique insights into the dynamics of operating an IT environment in China and while many Finnish companies operate in China and it is common wisdom that the operating environment in the country is very different from Finland, I personally have not met many other IT people with insights and experience working with Chinese colleagues or building, maintaining and improving an IT environment as a part of a Finnish or other European company there. Therefore, I decided to write this blog post to share my insights on what to consider from Finnish IT professional’s point of view.

<!--more-->

Technology itself is largely the same everywhere, but most of the differences I want to cover have more to do with cultural differences than technical issues, though the cultural differences also induce technical challenges, most notably the so called “Great Firewall of China”. Other things to understand when operating in China, is the regulation and legislation regarding censorship, transfer and collection of personal data, cybersecurity, and espionage, which will have an impact on the architecture and design of your environment.


# To Consider Before Beginning Designing the Environment

The IT environment is essentially about setting up technology to support the processes run and required by the people to run the business. While it might seem that setting up an IT environment anywhere, not just in China, is about getting some network equipment and computers, setting them up, installing operating systems, and configuring basic network services, before designing the environment, it is useful to understand these three interdependent aspects of the business. Who is going to use and maintain it? What are they going to do with it and how they are going to manage it? And finally, what should the environment have and how should it be set up? The business processes might be the same or similar to what the company has in other locations, but the regulation might give them twists after considering what data can and cannot be saved or transmitted in each location, the people value different things and act and react differently to things in different cultures, and the technology that can be deployed in one location may be different than what you can deploy in another, a good example being Google services being blocked in China, so a company heavily using Google cloud services would need to reconsider its approach in China.


## Technology

Technology is about the equipment, computers, cloud services, and connectivity required by the environment to support the business. Network equipment, servers, computers, networking protocols, etc. are the same everywhere, but a peculiarity in China is its very controlling attitude toward the internet and the services in it. For a foreign company setting up an IT environment, the major manifestation of this control is the so-called "Great Firewall", though there are other things to consider too.


### The Great Firewall

When thinking about setting up and IT environment in China, the first thing to come in mind may naturally be the so-called Great Firewall. However, the term “Great Firewall” is misleading as it is not in fact a separate array of firewall equipment at the border of the Chinese Internet policing incoming and outgoing packets, but rather an array of regulatory and technical means to censor and restrict communications between mainland China and elsewhere. There are three state owned telecom companies, or ISP’s (Internet Service Providers), that dominate the telecom industry in China: China Telecom, China Unicom, and China Mobile and the state controls the access points connecting the mainland Chinese internet to the global internet. The state issues requirements for the telecom industry and other operators on the internet regarding censoring and monitoring content and traffic and the telecom industry is responsible for blocking access to forbidden sites and services. The telecom companies use techniques like Destination IP address blocking, DNS poisoning, TCP reset attacks, deep packet inspection, fake SSL root certificates, active probing, and blocking app downloads to perform their censoring obligations. However, their performance is not uniform, likely because of differences in implementation, and while these techniques, combined with latency, can often make even allowed foreign services feel sluggish, when used in mainland China, some ISPs interfere with allowed traffic a lot more than others. For example, the O365 services are not blocked in China, but my personal experience, testing with all three ISP’s is that the services have worked the best with China Unicom connections while China Telecom has almost rendered some services unusable.

The Great Firewall blocks access to most of the services that any Finnish or other European visitor is accustomed to use, such as Google services like the search engine, Gmail, YouTube, and Google Maps, Facebook, Twitter, Signal, WhatsApp, and most high-profile news sites. The Chinese users often won’t notice any problems because they are used to using Chinese domestic equivalents like Bilibili for videos, WeChat for messaging, and Weibo for tweeting. The Great Firewall has also helped Chinese technology companies grow without competition from western rivals while giving the Chinese Communist party strong control over the tech companies operating virtually all the social network and other internet services in the country. On the other hand, access to some sites and services inside China is blocked from outside of the country, for example access to public databases providing financial information about Chinese companies for due diligence firms was blocked from outside the country in 2023. Also, if you need to host a website or other internet services inside China, you will need to register the site with the authorities, or the ISP will block access to the port.

Providing VPN services in China is allowed if the service is registered and apparently this requires implementing restrictions on the traffic and providing logs to the authorities when requested. OpenSSL and IPsec connections between sites usually work, but speeds can drop without discernable reason or connections can stop working altogether for periods of time. I have observed IPsec tunnel not being able to connect for months due to IKE packaged being dropped on the way causing the tunnel never to form.

The quality of the network connections between your Chinese office and the services outside of China should be tested with each available ISP and an SD-WAN setup with multiple ISPs should also be considered before making the decision on the ISP. If you require a reliable connection between your Chinese environment and your infrastructure outside of China, like most do, you should also consider MPLS as an option. Though costly, it provides the most reliable private connection that does not traverse through the mayhem in the public internet. Just remember that the MPLS is not encrypted, and your “private” line will pass through the systems of multiple ISPs in multiple countries, all of which will have visibility to your traffic, unless you encrypt it inside the MPLS channel. 


### Cloud Services

As mentioned before, many cloud services, used elsewhere, are blocked in China. For example, in case of Google the block is due to Google not agreeing to censor its content and search results to the liking of the Chinese authorities and instead deciding to end its business in China. Other US companies like Apple and Microsoft operate in China and Microsoft has licensed its O365 service to a Chinese company called 21Vianet, but it is a separate instance of O365 and not compatible with the one outside of China. The companies operating in China must accommodate the requirements for censorship and information sharing with the authorities, but it is not safe to expect their services to stay allowed in China over the next 5, 10, or 15 years, especially as the Chinese government is promoting greater technological self-sufficiency and control over cyberspace. It is prudent’ to consider the Chinese equivalents, like the 21vianet O365, Baidu Cloud, etc. for cloud services, but fitting these into the company technology stack may be difficult and the data flows need to be considered carefully to mitigate data privacy risks and to comply with regulation like the General Data Protection Regulation (GDPR) in the EU and Personal Information Protection Law (PIPL) in China.


### Procuring Hardware

Generally, hardware is easier to procure in China and install it there rather than to install it elsewhere, ship it to China, and deal with the customs. However, the kinds of leasing arrangements, common in Finland, where computers are leased for three or four years and returned afterwards don’t seem to be common in China. It is likely that you will need to purchase all hardware, including the staff computers, and take care of their whole lifecycle, including recycling or selling them, yourself.


## Processes

Processes are about how the business achieves its business goals and in regard to IT, they are about how people use the IT assets at their disposal, the equipment and accesses they have. The processes are also subject to the external regulations and the internal policies of the company. Over the past two decades, both regions, China, and EU, have invested heavily in strengthening data protection and cybersecurity and the trend has only accelerated since 2016.

### Legislation in EU and China

Both EU and Chinese legislation enforces principles such as privacy protection, cybersecurity, and regulations for international data transfers. The EU aims to create unified legislation to maintain common data protection standards across the union in order to protect the personal data of its citizens. Meanwhile, China focuses on protecting national security and sovereignty, resulting in stricter rules on data storage and transfer outside its borders.

Both regions will likely continue to adapt their laws to new technologies like artificial intelligence, blockchain, and cloud services and companies will have to adjust to the rapidly changing legislation. This adaptation will require investments in cybersecurity, transparency in personal data processing, enhancing data protection, and developing data classification and processes to know exactly what data is stored and transferred where. Also conflicts in regulations may pose business risks.

While the EU and China's cybersecurity and data protection laws share the goals of protecting personal data and improving cybersecurity, he EU legislation emphasizes individual rights and demands strict data protection and security standards from companies and restricts transfer of data about EU citizens to countries that don't have equivalent protections. The Chinese legislation on the other hand focuses more on state control and national security issues, requiring collaboration by the companies, including handing over data to the authorities when requested, outlines restrictions on transferring data to outside of China about Chinese citizens and extremely broadly defined data concerning national security and interests.

Lists of pertinent legislation to review include:

**EU Legislation:**

- Directive 95/46/EC (1995): The first significant EU data protection legislation.
- Directive 2002/58/EC (ePrivacy Directive, 2002): Focused on electronic communication privacy and security.
- Directive 2013/40/EU (NIS Directive, 2016): The first EU-wide cybersecurity legislation.
- General Data Protection Regulation (GDPR, 2016): Replaced Directive 95/46/EC and introduced substantial changes.
- Whistleblower Directive (2019): Provides protection for employees who report illegal activities or misuse, including data breaches.
- NIS2 Directive (2023): Revises the NIS Directive and aims to increase the overall level of cybersecurity across EU member states and entities.

**Chinese Legislation:**

- Information Security Law (2006): China's first law focusing on information security and privacy.
- Network Information Security Law (2013): Stressed the importance of information security for national security.
- Cybersecurity Law (2017): China's first comprehensive cybersecurity legislation.
- Data Security Law (DSL, 2021): Broadly focuses on data security and processing requirements.
- Personal Information Protection Law (PIPL, 2021): China's first legislation specifically addressing personal data protection.
- Counter-Espionage Law (Updated, 2023): A wide-ranging update to the existing anti-espionage legislation, banning the transfer of any information related to "national security and interests" and expanding the definition of espionage. The law also grants authorities conducting an anti-espionage investigation the power to access data, electronic equipment, and information on personal property, and the ability to ban border crossings.

An international company must decide exactly what data can be stored in China and data can be transferred out of China. Examples include designing the Active Directory structure, HR systems, customer and user databases, and other systems so that only the necessary data is transferred between locations and conflicts of interests can be avoided.


### Company Policies

Business processes and company policies that work in Finland or in the EU, may not be directly applicable in China. For example, a company policy might require all software on user computers to be run with basic user rights and not with elevated admin user rights, but for example some tax declaration applications in China, that are required for the companies to file taxes with the government, may require local admin rights to run. Plans must be in place how these kinds of applications can be accommodated in the environment.

Another example is that a company may require all communication with external customers or stake holders to be conducted using the company email or Teams or other collaboration software. Also, when sending files, secure file shares or encrypted emails may be required. However, in China email is seen as a very formal means of communication and people will regularly use WeChat for work communication and sending files simply because it is convenient and everyone else is using it too, even though it is known to be a heavily monitored and censored service. It may also not be possible to avoid using WeChat as customers may require it. The company should have clear guidelines for using WeChat and make sure that for example the firewall rules allow or deny using it based on the company policy and that the helpdesk knows how to support the users regarding the allowed collaboration software.


## People

People are about the cultural differences that impact how the people will view technology and interact with it and what kind of support they may need or require.


### Work Equipment

In Finland it is common practice for the companies to provide the work equipment to the staff, but many Chinese prefer a blend of BYOD (Bring Your Own Device) and company-provided computers. Sometimes the managers too seem to prefer the users use their own computers as it can save the company money buying computers. The users may also use their computers like their own personal computers and seek to install WeChat, Baidu Cloud agents to sync their own files, or other their own preferred software instead of using the company provided software. I once discussed upgrading the company computers with a Chinese person, and she said that because Chinese people like to compare the bonuses their companies give them for the Chinese New Year, we should give everyone new computers as Chinese New Year bonuses. It was an interesting idea that highlighted a completely different kind of approach to the computers from mine. One where the computers were not just tools provided by the company, but personal items given to the employees.


### Communication

I find that the Chinese people are very open and easy to communicate with and there are many similarities in our communication styles. The staff members will generally follow instructions and policies probably better than Finnish people will even if their reasons aren't very clear, however, Finns are sometimes slow in their responses to emails and may not reply anything until they are sure about something. Work life being very competitive in China and quick results being appreciated, if they don't get responses to helpdesk tickets quick enough, the Chinese will very quickly find some quick fix to get on with their work, even if it doesn't align with the company policies. While it's a diminishing practice, the quick fix may also still include downloading illegal or pirated software or license generators for popular applications.


### Language Barrier

Overcoming the language barrier and navigating cultural differences are among the biggest challenges in this environment. English proficiency varies greatly, so patience, clear communication, avoiding assumptions and asking instead, are key. For me personally learning Mandarin Chinese has helped immensely in communicating with my Chinese colleagues and understanding key aspects of the Chinese culture such as respect for hierarchy, indirect communication, strong group orientation, high competitiveness, and the concept of "face" have helped my communication with my Chinese colleagues immensely.


To address these differences, the company policies should state clear rules about the use of company devices and allowed applications, while considering both the company requirements and the Chinese culture, the people should be provided with ample training on the policies, and the support should be made available quickly when needed. Also, because personal relationships are very important in China, a company should invest in sending its Europe based people who work regularly with the Chinese office, including helpdesk engineers if helpdesk is offered for the Chinese office remotely from some other location, to visit their Chinese colleagues. This will improve co-operation and problem solving immensely, help people in the other offices understand the issues in the Chinese office and the other way around, and also help the Chinese colleagues be more comfortable seeking help when they need it.


# Conclusion

Establishing an IT environment in China, like anywhere else, entails a comprehensive understanding of your business needs, workforce behavior and requirements, and regulatory constraints. However, the specificity of the Chinese context introduces some distinctive challenges that must be carefully navigated to ensure efficient operations.

We tend to view the internet as a uniform service that should be the same everywhere, while it is actually not, and China's Great Firewall and its rigorous data and cybersecurity laws reshape the digital landscape in ways unfamiliar to many people affecting decisions regarding cloud services, hardware procurement, and connectivity. Despite these unique obstacles, the principles of setting up an effective IT environment remain the same. Understand the requirements, evaluate your options, and adapt your strategy to meet the local norms and regulations.

The cultural nuances embedded in business processes and company policies are another key component to consider when operating in China. While the essential elements remain the same as in other regions, details such as understanding of BYOD and company-provided equipment, the speed responses and problem-solving, and the significance of personal relationships add an additional layer of complexity that must be considered.

Overcoming the language barrier and developing personal relationships within the workforce can lead to better cooperation and mutual understanding. These human-centric approaches are universally valuable, but carry added weight in China, where personal relationships play a crucial role in business operations.

Establishing an IT environment in China may come with its unique set of challenges and adaptation is key when considering how to adjust to the specific requirements, how to teach the company policies to the staff, how to implement the company processes, how to adjust to the local regulation, and how to protect the company data, systems, and business from threats. Recognizing the similarities while addressing the differences paves the way for the successful creation of an efficient, functional, and compliant IT environment.



**Sources:**
- https://protonvpn.com/blog/great-firewall-china/
- https://digital-strategy.ec.europa.eu/en/policies/cybersecurity-strategy
- https://gdpr-info.eu/
- https://eur-lex.europa.eu/legal-content/FI/TXT/?uri=CELEX%3A32016R0679
- https://eur-lex.europa.eu/eli/dir/2016/1148/oj
- https://digital-strategy.ec.europa.eu/en/policies/nis-directive
- https://www.europarl.europa.eu/thinktank/en/document/EPRS_BRI(2021)689333
- https://www.nis-2-directive.com/
- https://eur-lex.europa.eu/legal-content/Fi/ALL/?uri=CELEX%3A32002L0058
- https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32019L1937
- https://flk.npc.gov.cn/detail2.html?MmM5MDlmZGQ2NzhiZjE3OTAxNjc4YmY4Mjc2ZjA5M2Q%3D
- http://www.npc.gov.cn/englishnpc/c23934/202112/1abd8829788946ecab270e469b13c39c.shtml
- https://digichina.stanford.edu/work/translation-personal-information-protection-law-of-the-peoples-republic-of-china-effective-nov-1-2021/


