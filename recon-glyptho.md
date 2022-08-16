**Hello,
This repo contains my recon methodology for Bug Bounty Programms**

1. Find the Suitable Targer and Scope of the target.

2. Now use automated tools for recon.
```
   RECONFTW,WAPITI,WPSCAN,
   https://github.com/j3ssie/Osmedeus
   https://github.com/Viralmaniar/BigBountyRecon gui recon
   https://github.com/hackerspider1/Recon-bugbounty ==>
   https://github.com/R0X4R/Garud
   https://github.com/gokulapap/Reconator
   https://github.com/knassar702/scant3r
   https://github.com/ninoseki/mihari
   https://github.com/1N3/Sn1per
   https://github.com/OWASP/Nettacker
   https://github.com/0xJin/awesome-bugbounty-builder
   https://github.com/chaitin/xray
   https://github.com/Dheerajmadhukar/karma_v2
   https://github.com/Huntinex/rauton
   https://github.com/m4ll0k/BBTz
   https://github.com/Ascotbe/Medusa
   https://github.com/chaitin/xray
   https://github.com/anmolksachan/TheTimeMachine
   https://github.com/zhzyker/vulmap
   https://github.com/riskscanner/riskscanner
   https://github.com/78778443/QingScan
   https://github.com/0x727/ShuiZe_0x727
   https://github.com/j3ssie/osmedeus
   https://github.com/Huntinex/rauton
   https://github.com/Dheerajmadhukar/karma_v2
   https://github.com/xerohackcom/webrecon
   https://github.com/yogeshojha/rengine
   https://github.com/robotshell/magicRecon
   https://github.com/c0dejump/HawkScan
   https://github.com/gokulapap/Reconator ==> GUI BASED RECON
   https://github.com/loecho-sec/All-in-XrayScan ==> ALL XXS,XXE,CMD,SQLI and more vuln scanner
```  
   
3. SUBDomain Enumaration tool:
```
   https://github.com/iamthefrogy/frogy
   https://github.com/boy-hack/ksubdomain
   https://github.com/edoardottt/scilla
   https://github.com/Findomain/Findomain
   https://spyse.com/tools/subdomain-finder
   https://github.com/guelfoweb/knock
   https://github.com/shmilylty/OneForAll
   http://tools.bugscaner.com/subdomain/
   http://tool.chinaz.com/subdomain/
   https://github.com/gwen001/github-subdomains
```   
   
4. Find Parameters for Domain and Subdomain from webarchieve
```
   https://github.com/devanshbatham/ParamSpider
   https://github.com/GerbenJavado/LinkFinder
   https://github.com/Sh1Yo/x8
   https://github.com/s0md3v/Arjun
```
   
5. SUBDomain Takeover check:
```
   https://github.com/r3curs1v3-pr0xy/sub404
   https://github.com/m4ll0k/takeover
   https://github.com/TheBinitGhimire/GH-Takeover
   https://github.com/TheBinitGhimire/NtHiM
   https://github.com/ethicalhackingplayground/SubNuke
```
```
6. Log4Shell Check:
   https://github.com/fullhunt/log4j-scan
   https://github.com/zhzyker/logmap
   https://github.com/trickest/log4j
   https://github.com/fox-it/log4j-finder
   https://github.com/wyzxxz/jndi_tool
   https://github.com/thecyberneh/Log4j-RCE-Exploiter
```   
   
7. CVELIST
```
   https://github.com/CVEProject/cvelist
   https://github.com/trickest/cve
   https://github.com/helloexp/0day
```  
   
8. Important Wordlists:
```
   Funny Fuzzing Wordlist
   https://github.com/koaj/ffw-content-discovery
   https://github.com/aels/subdirectories-discover
   https://github.com/emadshanab/WordLists-20111129
   https://github.com/six2dez/OneListForAll
   https://github.com/ayoubfathi/leaky-paths/blob/main/leaky-paths.txt
   https://github.com/p0dalirius/webapp-wordlists
```
   
9. API Endpoints & Objects
```
   https://gist.github.com/yassineaboukir/8e12adefbd505ef704674ad6ad48743d
   https://github.com/danielmiessler/SecLists
```
   
10.Nuclei Templates
```
   https://github.com/geeknik/the-nuclei-templates
   https://github.com/ethicalhackingplayground/erebus
   https://github.com/trickest/log4j
   https://github.com/0xAwali/Blind-SSRF
   https://github.com/NitinYadav00/My-Nuclei-Templates
   https://github.com/emadshanab/Nuclei-Templates-Collection
   https://github.com/sharathkramadas/k8s-nuclei-templates
   https://github.com/projectdiscovery/nuclei-templates
```

11. Web Cache Vulnerability Scanner (WCVS)
```
    https://github.com/glyptho/Web-Cache-Vulnerability-Scanner
    https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
```
    
12. A fast tool to scan CRLF vulnerability written in Go
```
    https://github.com/dwisiswant0/crlfuzz
```
   
13.HTTP Request smuggling tool
```
   https://github.com/danielthatcher/smuggles
   https://github.com/defparam/smuggler
   https://github.com/Sh1Yo/request_smuggler
```
   
14. Shiro RememberMe 1.2.4 Deserialization Vulnerability Graphical Detection Tool (Shiro-550)
```
    https://github.com/fupinglee/ShiroScan
```
  
15.Java RMI Vulnerability Scanner
```
   https://github.com/qtc-de/remote-method-guesser
```
   
16.Automatic SSRF fuzzer and exploitation tool
```
https://github.com/cyb3rd0g-cell/automation-bugBounty ==> SSRF ONELINER FROM WAYBACKURL
   https://github.com/swisskyrepo/SSRFmap
   https://github.com/0xAwali/Blind-SSRF
   https://github.com/ksharinarayanan/SSRFire
   https://github.com/abundov/mahost
   https://github.com/knassar702/lorsrf
   https://github.com/epinna/tplmap
   Check for Host-Header SSRF Attack on a single or multiple hosts
   https://github.com/abundov/mahost
   https://github.com/In3tinct/See-SURF
   https://github.com/daeken/httprebind
   echo "https://checkout.stripe.com/api/color?image_url=" | nuclei -t ssrf.yaml {https://github.com/NagliNagli/BountyTricks}
```
   
17.AUTOMATIC CHECK OPEN REDIRECT
```
   https://github.com/devanshbatham/OpenRedireX
   https://github.com/redcode-labs/UnChain
   https://github.com/r0075h3ll/Oralyzer
```
   
18. Hack Website Admin Panel
```
    https://github.com/glyptho/AdminHack
```
    
19. Secret Key Finder
```
    https://github.com/rsbarsania/secret_key_finder
    https://github.com/nsonaniya2010/SubDomainizer
    https://github.com/rsbarsania/secret_key_finder
```
    
    
  20.GOOGLE DORKS
 ```
    https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan
    https://github.com/dievus/msdorkdump
    https://github.com/APTeamOfficial/APSoft-Web-Scanner-v2
    https://github.com/daffainfo/AllAboutBugBounty/blob/master/Recon/Google%20Dorks.md
    https://github.com/mxrch/GHunt
    https://github.com/nerrorsec/GoogleDorker
    https://github.com/TebbaaX/Katana
    https://github.com/SKVNDR/FastDork
```
    
    
 21.SHODAN DORKS
```
    https://github.com/daffainfo/AllAboutBugBounty/blob/master/Recon/Shodan%20Dorks.md    
```

     
 22. Git Secret Find
```
     https://github.com/daffainfo/Git-Secret
     https://github.com/obheda12/GitDorker
     https://github.com/glyptho/gitGraber
     https://github.com/molly/gh-dork
     https://github.com/gwen001/github-regexp
     https://github.com/zricethezav/gitleaks
     https://github.com/awslabs/git-secrets
     https://github.com/BishopFox/GitGot
     https://github.com/UnkL4b/GitMiner
     https://github.com/daffainfo/Git-Secret
     https://github.com/daffainfo/AllAboutBugBounty/blob/master/Recon/Github%20Dorks.md
     https://github.com/techgaun/github-dorks
```     
     
23.  PUT Method Exploit
```
     https://github.com/devploit/put2win
```     
     
24.  BugBounty Tools
```
     https://forum.ywhack.com/bountytips.php?redteam
     https://github.com/riramar/Web-Attack-Cheat-Sheet#Wayback-Machine
     https://github.com/zPrototype/bugbounty_stuff
     https://github.com/edoardottt/lit-bb-hack-tools
     https://github.com/trimstray/the-book-of-secret-knowledge
```

25.   Directory bruteforce
```
      https://github.com/epi052/feroxbuster
```
      
26.Find XSS Automatically
```
   https://github.com/Encryptor-Sec/XSSearch
```

27.403 BYPASS
```
   https://github.com/devploit/dontgo403
   https://github.com/yunemse48/403bypasser
   https://github.com/Dheerajmadhukar/4-ZERO-3
   https://github.com/M4DM0e/DirDar
   https://github.com/lobuhi/byp4xx
```

28.osint search
```
   https://github.com/jivoi/awesome-osint
   https://github.com/KingOfBugbounty/KingOfBugBountyTips
```

29.Download .git directory
```
   https://github.com/internetwache/GitTools
```

30.Download .DS_STORE FIles
```
   https://github.com/lijiejie/ds_store_exp
   Read .DS_STORE Files
   https://w-e-b.site/
```
   
31.DECRYPT STRINGS
```
   https://github.com/Ciphey/Ciphey
```

32.SQLI INJECTION
```
   https://github.com/ArkAngeL43/sqlifinder
   https://github.com/MR-pentestGuy/Blind-sqli
   https://github.com/JohnTroony/Blisqy
   https://github.com/zeronine9/Blind_SPOT
```

33.FIND ORIGINAL IP BEHIND WAF
```
   https://github.com/christophetd/CloudFlair
   https://github.com/boy-hack/w8fuckcdn
   https://github.com/Startr4ck/findip
   https://github.com/Dheerajmadhukar/Lilly
   https://github.com/mrh0wl/Cloudmare
```

34.DOM XSS FINDER
```
   https://github.com/dwisiswant0/findom-xss
   https://github.com/swoops/eval_villain
```

35.S3 VIEWER GUI
```
   https://github.com/SharonBrizinov/s3viewer
   https://github.com/iamthefrogy/bucketbunny
   https://github.com/0xmoot/s3sec
   https://github.com/subzero987/S3-Recon/blob/main/S3-Recon.txt
```

36.LFI SCANNER
```
   https://github.com/mzfr/liffy
```

37.BLIND XSS TESTING
```
   https://github.com/emadshanab/Blind-xss-via-ffuf
```
   
38.BUG BOUNTY DORKS
```
   https://github.com/sushiwushi/bug-bounty-dorks
```

39.DIRECTORY BRUTEFORCE
```
   https://github.com/epi052/feroxbuster
```
   
40.FIND SENSITIVE FILES IN WAYBACKURLS
```
   https://github.com/Dheerajmadhukar/back-me-up
   https://github.com/remonsec/Pri0tx
   sudo mv otx /usr/bin/otx
   https://github.com/h33tlit/Jbin-website-secret-scraper
```
   
41.FIND HIDDEN ENDPOINTS INSIDE JAVASCRIPT FILES
```
   https://github.com/GerbenJavado/LinkFinder
   https://github.com/dwisiswant0/galer#installation
   https://github.com/0x240x23elu/JSScanner
   https://github.com/m4ll0k/SecretFinder
   https://github.com/Sachin-v3rma/Astra
```
   
   
42. Winddows PORT Scanner
```
    https://github.com/elddy/NimScan
```
    
    
43. Jenkins server pentest
```
    https://github.com/gquere/pwn_jenkins
```
    
    
44. FIND Github Subdomains
```
    https://github.com/gwen001/github-subdomains
```
    
    
    
45. Salesforce recon and Exploit Tool
```
    https://github.com/reconstation/sret
```
    
    
    
46. BURPSUITE SCANNERS
```

    https://github.com/dbrwsky/Nuclei-BurpExtension
    https://github.com/plenumlab/rce-finder
    https://github.com/plenumlab/Imposteserum-extension
    Burpsuite Graphql readable
    https://github.com/plenumlab/GQL-Helper
    Automatically identify deserialisation issues in Java and .NET
    https://github.com/nccgroup/freddy
    https://github.com/PortSwigger/http-request-smuggler
    https://github.com/akabe1/OAUTHScan
    https://github.com/SkewwG/BurpExtender
    https://github.com/projectdiscovery/nuclei-burp-plugin
```

    
47. XXE AUTOMATIC PAYLOAD EXPLOIT
```
    https://github.com/plenumlab/xmp-xxe
```
    
    
48. wappalyzer USE FOR BULK URLS:
```
    https://github.com/Zarcolio/2cmd
```

    
49. FIND SENSITIVE INFORMATION FROM ALIENWALT
```
    https://github.com/0xsheinn/otx
    https://github.com/remonsec/Pri0tx
```


50. GENERATE SPECIFIC WORDLIST FOR A DOMAIN
```
    https://github.com/th3hack3rwiz/Wordlist-Weaver
```
 
    
51. SETUP TOOLS AFTER KALI INSTALL
```
https://github.com/root-tanishq/setmykali/blob/main/setmykali.sh
```


52. Nagli Tips
```
    https://github.com/NagliNagli/BountyTricks
```
 
    
53. GitHub Pages Sub-domain Takeover Automation!
```
https://github.com/TheBinitGhimire/GH-Takeover
```


54. JIRA SERVER PENTEST AUTOMATION
```
    https://github.com/MayankPandey01/Jira-Lens
```
 
    
55.  HUNT WHILE YOU SLEEP
```
     https://github.com/iamthefrogy/nerdbug
```
     
     
56. SHORT SAME PARAMETERS WITH DIFFERENT VALUE
```
    https://github.com/s0md3v/uro
```
    
57. FIND DOM XSS
```
    https://github.com/edoardottt/lit-bb-hack-tools/tree/main/doomxss
```
    
    
58. FIND client-side prototype pollution vulnerability written in Rust.
```
    https://github.com/dwisiswant0/ppfuzz
    https://github.com/kosmosec/proto-find
```
    
    
59. Shiro<=1.2.4 deserialization, one-click detection tool
```
    https://github.com/sv3nbeast/ShiroScan
```
    
    
60. BULK SCAN TARGET WITH NMAP WITH DIFFERENT POPULAR TOOLS
```
    https://github.com/snovvcrash/DivideAndScan
```
    
    
61. USE SHODAN TO SCAN IP AND VULNERABILITY
```
    https://github.com/R0X4R/snetra
```
 
    
62. Download .git Directory
```
    https://github.com/WangYihang/GitHacker
```
 
    
63. EMAIL OSINT
```
    https://github.com/m4ll0k/Infoga
```
    

64. A Python based scanner uses shodan-internetdb to scan the IP.
```
    https://github.com/R0X4R/snetra
```
    
    
65.    FIND Nginx misconfigurations and vulnerabilities.
```
 https://github.com/stark0de/nginxpwner
 ```

66. DOWNLOAD .SVN FOLDER
```
    https://github.com/anantshri/svn-extractor
```
    
67. FIND HEADER BASED BLIND XSS USING XSSHUNTER PAYLOAD
```
    https://github.com/adrianscheff/pegaxss
```
    
68. FIND HARDCODE SECRETS IN ANDROID
```
    https://github.com/arijitdirghanji/Find-Hardcoded?s=09
```
    
69. ==> EXTERNAL SSRF AND BLIND SSRF EXPLOIT
```
    https://twitter.com/wugeej/status/1138639681543819264?t=CEIyGP15Oed50DRSYSP3ng
```
    
70. GENERATE UNDETECT WEBSHELL
```
    https://github.com/czz1233/GBByPass
```
    
71. FIND IPS OF A TARGET DOMAIN AND SCAN USING NUCLEI DIRECTLY
```
    https://github.com/asaotomo/FofaMap
```
    
72. REDIS RCE
```
    https://github.com/zyylhn/redis_rce
```
    
73. Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more
```
    https://github.com/edoardottt/cariddi
```
    
74. JShell - Get a JavaScript shell with XSS.
```
    https://github.com/s0md3v/JShell
    https://github.com/threedr3am/JSP-WebShells
    https://github.com/feihong-cs/Java-Rce-Echo
```
    
75. Injects php payloads into jpeg images
```
    https://github.com/dlegs/php-jpeg-injector
```
    
76. A cool python exploit to spoof your payload into another extension like pdf, docx, png, jpg, mp3, etc.
```
    https://github.com/vesperlol/Extension-Spoofer
```

77. A crawler that tests HTML forms for reflection
```
    https://github.com/garlic0x1/go-reflect
```
    
78. HaxUnit combines multiple active and passive subdomain enumeration tools and port scanning tools with vulnerability discovery tools.
```
    https://github.com/Bandit-HaxUnit/haxunit
```
    
79. NUCLEI ALTERNATIVE
```
    https://github.com/cckuailong/pocsploit
```
     
80. Jeeves SQLI Finder
```
    https://github.com/ferreiraklet/Jeeves
```
    
81. Find all vulnerabilities in apache server or websites running apache
```
    https://github.com/p0dalirius/ApacheTomcatScanner
```
