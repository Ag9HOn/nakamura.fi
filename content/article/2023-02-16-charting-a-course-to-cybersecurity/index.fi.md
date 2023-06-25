---
title: "Kurssi kohti kyberturvallisuutta: Merenkulkualan vastaus kasvaviin uhkiin"
date: 2023-02-16T19:28:11+03:00

categories: ["IT ja Kyberturvallisuus"]
tags: ["Kyberturvallisuus", "Säädökset", "Meriliikenteen kyberturvallisuus"]
toc: false
author: "Petteri Nakamura"
---


Viimesen vuoden aikana olen osallistunut moniin keskusteluihin kyberturvallisuudesta merenkulkualalla. Kyberhyökkäysten määrä alalla kasvaa ja ne ovat aiheuttaneet paljon häiriöitä ja taloudellisia tappioita yrityksille ja organisaatioille. Merenkulkuala on erityisen haavoittuvainen näille uhille johtuen alusten pitkistä elinkaarista, laitevalmistajien ja varustamoiden kasvavasta pilvipohjaisten ratkaisujen käytöstä sekä uudisrakennuksissa että lisäyksinä käytössä oleviin aluksiin etähuollon ja datan keruun mahdollistamiseksi. Tämä johtaa helposti lukuisiin etäyhteyksiin aluksen ja eri järjestelmätoimittajien välillä, samalla kun ympäristön kokonaisturvallisuudesta ei ehkä ole vastuussa kukaan. Luokituslaitos Bureau Veritas siteerasi viime vuonna webinaarissa kyberincidenttien määrän kasvaneen 900% merenkulkualalla kolmen viime vuoden aikana ja totesi, että hakkeri ilman toimialakohtaista osaamsita, voisi upottaa aluksen 14 tunnissa. Myös neljä johtavaa konttialusoperaattoria on jo julkisesti myöntänyt kärsineensä kyberhyökkäyksistä.

Ehkä merkittävin viime vuosien tapaus alalla oli Maerskin kärsimä kyberhyökkäys vuonna 2017, jossa NotPetya-kiristyshaittaohjelma levisi yhtiön verkoissa ja salasi Maerskin järjestelmät, aiheuttaen laajoja häiriöitä ja merkittäviä taloudellisia tappioita. Hyökkäys vaikutti yhtiön toimintaan maailmanlaajuisesti, kuten sen terminaaleihin, satamiin ja meriliikenneväyliin, ja hyökkäyksen seurauksena Maerskin oli pakko sulkea tietojärjestelmänsä useiksi päiviksi. Hyökkäys oli yksi suurimmista ja laajimmista kiristyshaittaohjelmahyökkäyksistä tähän mennessä, ja Maersk oli vain yksi hyökkäyksen kohteista. Tämä korostaa merenkulkuteollisuuden haavoittuvuutta.

Alukset ovat yhä enemmän yhteydessä verkkoon, joten riski vastaavien tapausten sattumiselle merellä oleville aluksille kasvaa myös. Sadantuhannen tonnin meressä kaikenlaisen lastin ja ihmisten kanssa kelluvan datacenterin hakkeroinnin seuraukset voivat helposti olla taloudellisia tappioita merkittävämmät sisältäen myös henkilövahinkoja ja laajat ympäristövahingot.

# Uudet kyberturvallisuusvaatimukset aluksille

Näiden haasteiden ratkaisemiseksi Kansainvälinen merenkulkujärjestö (IMO) julkaisi vuonna 2017 MSC-FAL.1/Circ.3:n tarjotakseen ohjeita merenkulkualan kyberriskien hallintaan sekä päätöslauselman MSC.428(98) kyberriskien hallinnasta turvallisuuden hallintajärjestelmissä, korostaen tarvetta integroida kyberriskien hallinta osaksi yleistäturvallisuudenhallintajärjestelmää 1 tammikuuta 2021 mennessä. Lisäksi Kansainvälinen luokituslaitosten kattoyhdistys (IACS) on kehittänyt kaksi uutta, 1 tammikuuta 2024 voimaan tulevaa, vaatimusta kyberturvan suhteen aluksilla. IACS:n UR E26 uudisrakennuksille ja IACS:n UR E27 laitevalmistajille pohjautuvat laajasti tunnustettuihin kyberturvallisuuden viitekehyksiin ja ohjeisiin, kuten NIST:n kyberturvallisuuden viitekehykseen ja ISO/IEC 27001. Ne pyrkivät asettamaan minimivaatimukset alusten kyberturvallisuudelle sekä aluksilla olevien järjestelmien ja laitteiden kyberresilienssille.

Monet luokituslaitokset, joiden hyväksyntä on vaatimus aluksen lastin saamiseksi vakuutettua, kuten Bureau Veritas, DNV ja RINA, ovat jo luoneet useita ohjeita kyberturvallisuuden käsittelemiseksi merenkulkualalla. Esimerkkeinä DNV-luokan ohjeet sekä Bureau Veritasin ja RINAn säännöt. Jotkut näistä ovat jo hyvin kattavia, ja toiset lähinnä viittaavat IACS:n ja IMO:n julkaisemiin aineistoihin ohjeiden saamiseksi. Olen henkilökohtaisesti tällä hetkellä eniten perehtynyt Bureau Veritasin sääntöihin, ja he ovat viime vuona seuraamassani  webinaarissa ilmoittaneet, että heidän nykyinen valinnainen sääntökirjansa kyberturvallisuudesta tulee olemaan osa heidän vaatimuksiaan 1. tammikuuta 2024 alkaen. Muiden luokitusyhdistysten vaatimukset ovat kuitenkin hyvin samanlaisia, koska ne kaikki perustuvat samoille IMO/IACS-vaatimuksille.

Säännöt pohjimmiltaan edellyttävät kaikkien OT-järjestelmien, kuten navigointi- ja automaatiojärjestelmien, ja IT-järjestelmien, kuten toimistoverkkojen, viihdejärjestelmien ja myymälöissä olevien kassakoneiden, sekä niiden laitteistojen ja niiden välisten yhteyksien inventaariota. Seuraavaksi kaikille järjestelmille on tehtävä riskinarviointi ja tunnistettu riski on käsiteltävä, jotta alus voi saada luokkahyväksynnän. OT ja IT-järjestelmiä ei voida käsitellä erikseen, vaan niiden on molempien oltava suunniteltu yhdessä koko ympäristön kyberresilienssin varmistamiseksi. Dokumentaatio, mukaanlukien riskinarvioinnit ja riskien käsittelyt, on esitettävä luokituslaitokselle. Säännöissään Bureau Veritas vaatii myös, että Vessel Integrator nimetään ja esitellään luokituslaitokselle telakan toimesta. Vessel Integrator roolin on kuvattu valvovan uudisrakennuksen yleistä kyberturvallisuutta suunnitteluvaiheesta aina aluksen käyttöönottoon saakka, ja hänellä on valtuudet ja vastuu hyväksyä tai hylätä ehdotetut laitteet, yhteydet tai ohjelmistot riskinarvioinnin mukaisesti.

# Turvallisempi tulevaisuus laivanrakennusteollisuudessa

Laivanrakennusteollisuus on erittäin mielenkiintoisten aikojen edessä. Uskon, että nämä uudet vaatimukset tulevat vaatimaan paljon työtä monilta varustamoilta ja telakoilta, jotka eivät ehkä ole aiemmin kiinnittäneet kyberturvallisuuteen paljon huomiota, mutta uskon myös, että uudet vaatimukset ovat juuri sitä, mitä ala tarvitsee varmistaakseen alusten, matkustajien, miehistön ja lastin turvallisuuden tulevaisuudessa. Tähän mennessä tarkastelemani säännöt näyttävät myös hyvin järkeviltä ja luokituslaitoksetovat vastanneet hyvin kysymyksiin niistä. Odotan innolla kyberturvallisuuden edistymistä laivanrakennusteollisuudessa tulevaisuudessa. 

# Linkkejä lisälukemiseen:

## IMO and IACS

- **[IMO MSC-FAL.1/Circ.3](https://wwwcdn.imo.org/localresources/en/OurWork/Facilitation/Facilitation/MSC-FAL.1-Circ.3-Rev.1.pdf)** -- Guidelines on Maritime Cyber Risk Management (2017) - A circular issued by the International Maritime Organization providing guidelines for managing cyber risks in the maritime industry.
- **[IMO MSC.428\(98\)](https://wwwcdn.imo.org/localresources/en/OurWork/Security/Documents/Resolution%20MSC.428(98).pdf)** -- Maritime Cyber Risk Management on Safety Management Systems (2017) - A resolution adopted by the International Maritime Organization emphasizing the need to consider cyber risk management in conjunction with the objectives and functional requirements of the ISM Code, and encourages to ensure that safety management systems address cyber risks by January 1, 2021.
- **[The Guidelines on Cyber Security Onboard Ships](https://www.ics-shipping.org/wp-content/uploads/2021/02/2021-Cyber-Security-Guidelines.pdf)** (2021) -- BIMCO, Chamber of Shipping of America, Digital Containership Association, International Association of Dry Cargo Shipowners (INTERCARGO), InterManager, International Association of Independent Tanker Owners (INTERTANKO), International Chamber of Shipping (ICS), International Union of Marine Insurance (IUMI), Oil Companies International Marine Forum (OCIMF), Superyacht Builders Association (Sybass) and World Shipping Council (WSC)
- **[IACS UR E26](https://iacs.org.uk/publications/unified-requirements/ur-e/?page=2)** -- Cyber resilience of ships - A set of requirements for cyber security on board ships developed by the International Association of Classification Societies providing a set of minimum requirements for ship cyber resilience. Takes effect on January 1, 2024.
- **[IACS UR E27](https://iacs.org.uk/publications/unified-requirements/ur-e/?page=2)** -- Cyber resilience of on-board systems and equipment - A requirement for cyber security onboard ships developed by the International Association of Classification Societies stipulating the unified requirements for cyber resilience of on-board systems and equipment. Takes effect on January 1, 2024


## Classification Associations



- **Bureau Veritas:** [Rules on Cyber Security for the Classification of Marine Units, NR 659 DT R01, September 2020](https://erules.veristar.com/dy/data/bv/pdf/659-NR_2020-09.pdf)
- **Loyd’s Register:** [Cyber-enabled ships, Deploying information and communications technology in shipping – Lloyd’s Register’s approach to assurance, First edition, February 2016](https://maritime.lr.org/l/941163/2022-06-12/43qxz/941163/1655091981uu2kvibt/lr_guidance_note_cyber_enabled_ships_february_2016__3_.pdf)
- **Loyd’s Register:** [Cyber-enabled ships, ShipRight procedure assignment for cyber descriptive, notes for autonomous & remote access ships, A Lloyd’s Register guidance document, December 2016](https://maritime.lr.org/l/941163/2021-12-09/2pwb2/941163/1639061961zcaozhcz/mo_cyber_enabled_ships_shipright_procedure_v2.0_201712.pdf)
- **PRS PL:** [Cybersecurity Guidelines for Shipowners](https://www.prs.pl/uploads/cybersecurity_guidelines_on_implementation.pdf)
