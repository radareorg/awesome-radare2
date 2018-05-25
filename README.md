# Awesome Radare2 [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome projects, articles and the other materials powered by Radare2.

## What is Radare2?

Radare is a portable reversing framework that can...

- Disassemble (and assemble for) many different architectures
- Debug with local native and remote debuggers (gdb, rap, r2pipe, winedbg, windbg, ...)
- Run on Linux, *BSD, Windows, OSX, Android, iOS, Solaris and Haiku
- Perform forensics on filesystems and data carving
- Be scripted in Python, Javascript, Go and more
- Visualize data structures of several file types
- Patch programs to uncover new features or fix vulnerabilities
- Use powerful analysis capabilities to speed up reversing
- Aid in software exploitation

More info [here](http://rada.re/).

### Table of Contents

- [Books](#books)
- [Videos](#videos)
   + [Recordings](#recordings)
   + [Asciinemas](#asciinemas)
   + [Conferences](#conferences)
- [Slides](#slides-and-workshops)   
- [Tutorials and Blogs](#tutorials-and-blogs)
- [Tools](#tools)
- [Scripts](#scripts)
- [Contributing](#contributing)


# Awesome Radare2 Materials

## Books

- [R2 "Book"](https://legacy.gitbook.com/book/radare/radare2book/details)
- [Radare2 Explorations](https://legacy.gitbook.com/book/monosource/radare2-explorations/details)
- [Radare2 wiki](http://r2wiki.readthedocs.io/en/latest/)

## Videos

### Recordings

- [Creating a keygen for FrogSek KGM#1](https://www.youtube.com/watch?v=4xGAwI10VNM) - by @binaryheadache
- [Radare2 - An Introduction with a simple CrackMe - Part 1](https://www.youtube.com/watch?v=8dXhrOEGHTY) - by @antojosep007
- [Introduction To Reverse Engineering With Radare2](https://www.youtube.com/watch?v=LAkYW5ixvhg)
- [Scripting radare2 with python for dynamic analysis - TUMCTF 2016 Zwiebel part 2](https://www.youtube.com/watch?v=y69uIxU0eI8)

### Asciinemas

- [metasploit x86/shikata_ga_nai decoder using r2pipe and ESIL](https://asciinema.org/a/26594)
- [Filter for string's searching (urls, emails)](https://asciinema.org/a/b429iwj4cx5ixpba4l01qxzmk)
- [Manual unpacking UPX on linux 64-bit](https://asciinema.org/a/bei8od5pxnihypp0j91o4ukj0)

### Conferences

- [r2con 2017](https://www.youtube.com/watch?v=URyd4bcV-Ik&list=PLjIhlLNy_Y9Oe-nfcPEpaki0_En5dhQ5S)
- [LinuxDays 2017 - Disassembling with radare2](https://www.youtube.com/watch?v=zhQ1GhlgCMY)
- [SUE 2017 - Reverse Engineering Embedded ARM Devices](https://www.youtube.com/watch?v=oXSx0Qo2Upk)
- [radare demystified (33c3)](https://www.youtube.com/watch?v=fnpBy3wWabA)
- [r2con 2016](https://www.youtube.com/watch?v=QVjrqlo5A9g&list=PLjIhlLNy_Y9O62rjwYD48pVER0EVh1-aU)
- [Reversing with Radare2 - OverDrive Conference](https://www.youtube.com/watch?v=GTreWP1lPzU)
- [Radare2 & frida hack-a-ton 2015](https://vimeo.com/151753106)
- [Radare from A to Z 2015](https://vimeo.com/151753230)
- [Reverse engineering embedded software using Radare2 - Linux.conf.au 2015](https://www.youtube.com/watch?v=R3sGlzXfEkU)
- [OggCamp - Shellcode - vext01](http://blip.tv/file/get/Oggcamp-ReversingShell888.mp4)

## Slides and Workshops

- [Radare2 cheat-sheet](https://github.com/zxgio/r2-cheatsheet)
- [r2m2 - radare2 + miasm2 = ♥](https://guedou.github.io/r2m2_talks/2016_r2con/slides.pdf)
- [Radare2 Workshop 2015 (Defcon)](https://github.com/maijin/workshop2015)
- [Emulating Code In Radare2](http://radare.org/get/lacon2k15-esil.pdf)
- [Radare from A to Z 2015](http://radare.org/get/RadareAZ-NN2015.pdf)
- [Radare2 Workshop 2015 (Hack.lu)](http://2015.hack.lu/archive/2015/radare2-workshop/)
- [Radare2 & frida hack-a-ton 2015](http://lolcathost.org/b/radare2-ncn2015-hack-a-ton.pdf)
- [radare2: evolution](http://rada.re/get/lacon2k11.pdf)
- [radare2: from forensics to bindiffing ](http://radare.org/get/rooted2011.pdf)

## Tutorials and Blogs

- [Linux Malware by @MalwareMustDie](https://imgur.com/r/LinuxMalware)
- [Radare2 - Using Emulation To Unpack Metasploit Encoders](https://blog.xpnsec.com/radare2-using-emulation-to-unpack-metasploit-encoders/) - by @_xpn_
- [Reverse engineering a Gameboy ROM with radare2](https://www.megabeets.net/reverse-engineering-a-gameboy-rom-with-radare2/) - by @megabeets_
- [radare2 as an alternative to gdb-peda](https://monosource.github.io/2016/10/26/radare2-peda/)
- [How to find offsets for v0rtex (by Siguza)](https://gist.github.com/uroboro/5b2b2b2aa1793132c4e91826ce844957)
- [Debugging a Forking Server with r2](https://blankhat.blogspot.ru/2018/01/debugging-forking-server-with-r2_1.html)
- [Defeating IOLI with radare2 in 2017](https://dustri.org/b/defeating-ioli-with-radare2-in-2017.html)
- [Using r2 to analyse Minidumps](http://radare.today/posts/minidump/)
- [Android malware analysis with Radare: Dissecting the Triada Trojan](https://www.nowsecure.com/blog/2016/11/21/android-malware-analysis-radare-triada-trojan/)
- [Solving game2 from the badge of Black Alps 2017 with radare2](https://dustri.org/b/solving-game2-from-the-badge-of-black-alps-2017-with-radare2.html)
- [ROPEmporium: Pivot 64-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/12/04/ropemporium-pivot-ctf-walkthrough2/)
- [ROPEmporium: Pivot 32-bit CTF Walkthrough With Radare2](http://radiofreerobotron.net/blog/2017/11/23/ropemporium-pivot-ctf-walkthrough/)
- [Reversing EVM bytecode with radare2](https://blog.positive.com/reversing-evm-bytecode-with-radare2-ab77247e5e53)
- [Radare2’s Visual Mode](https://moveax.me/radare2-visual-mode/)
- [Crackme0x03 Dissected with Radare2](https://moveax.me/crackme0x03/)
- [Crackme0x02 Dissected with Radare2](https://moveax.me/crackme0x02/)
- [Crackme0x01 Dissected with Radare2](https://moveax.me/crackme0x01/)
- [Debugging Using Radare2… and Windows!](https://medium.com/@jacob16682/debugging-using-radare2-and-windows-5e58677bf943) - by @jacob16682
- [Decrypting APT33’s Dropshot Malware with Radare2 and Cutter – Part 1](https://www.megabeets.net/decrypting-dropshot-with-radare2-and-cutter-part-1/) - by @megabeets_
- [A journey into Radare 2 – Part 2: Exploitation](https://www.megabeets.net/a-journey-into-radare-2-part-2/) - by @megabeets_
- [A journey into Radare 2 – Part 1: Simple crackme](https://www.megabeets.net/a-journey-into-radare-2-part-1/) - by @megabeets_
- [Reverse Engineering With Radare2](https://insinuator.net/tag/radare2/) - by @insinuator
- [Write-ups from RHME3 pre-qualifications at RADARE2 conference](https://www.riscure.com/blog/write-ups-rhme3-pre-qualifications-radare2-conference/)
- [Hackover CTF 2016 - tiny_backdoor writeup](http://karabut.com/hackover-ctf-2016-tiny_backdoor-writeup.html)
- [radare2 redux: Single-Step Debug a 64-bit Executable and Shared Object](http://davidjwalling.blogspot.ru/2016/10/radare2-redux-single-step-debug-64-bit.html)
- [Reversing and Exploiting Embedded Devices: The Software Stack (Part 1)](https://p16.praetorian.com/blog/reversing-and-exploiting-embedded-devices-part-1-the-software-stack)
- [Binary Bomb with Radare2](https://www.unlogic.co.uk/2016/04/12/binary-bomb-with-radare2-prelude/) - by @binaryheadache
- [crackserial_linux with radare2](https://www.unlogic.co.uk/2016/06/13/crackserial_linux-with-radare2/#crackserial_linux-with-radare2) - by @binaryheadache
- [Examining malware with r2](https://www.unlogic.co.uk/2017/06/28/examining-malware-with-r2/) - by @binaryheadache
- [Breaking Cerber strings obfuscation with Python and radare2](http://aassfxxx.infos.st/article26/breaking-cerber-strings-obfuscation-with-python-and-radare2) - by @aaSSfxxx
- [Radare2 of the Lost Magic Gadget](https://0xabe.io/howto/exploit/2016/03/30/Radare2-of-the-Lost-Magic-Gadget.html) - by @0xabe_io
- [Radare 2 in 0x1E minutes](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/) - by @superkojiman
- [Exploiting ezhp (pwn200) from PlaidCTF 2014 with radare2](https://dustri.org/b/exploiting-ezhp-pwn200-from-plaidctf-2014-with-radare2.html)
- [Baleful was a challenge relased in picoctf](http://lolcathost.org/b/BalefulRadare_EN_part_1of2.pdf)
- [At Gunpoint Hacklu 2014 With Radare2](https://crowell.github.io/blog/2014/11/23/at-gunpoint-hacklu-2014-with-radare2/) - by @crowell
- [Pwning With Radare2](https://crowell.github.io/blog/2014/11/23/pwning-with-radare2/) - by @crowell
- [Solving ‘heap’ from defcon 2014 qualifier with r2](https://www.securityartwork.es/2015/12/16/head-defcon-2/) - by @alvaro_fe
- [How to radare2 a fake openssh exploit](https://dustri.org/b/how-to-radare2-a-fake-openssh-exploit.html) - by jvoisin
- [Disassembling 6502 code with Radare – Part I](https://retro.moe/2015/11/18/disassembling-6502-code-with-radare-part-i/) - by @ricardoquesada
- [Disassembling 6502 code with Radare – Part II](https://retro.moe/2015/12/09/disassembling-6502-core-with-radare-part-ii/) - by @ricardoquesada
- [Unpacking shikata-ga-nai by scripting radare2](http://radare.today/posts/unpacking-shikata-ga-nai-by-scripting-radare2/)
- [This repository contains a collection of documents, scripts and utilities that will allow you to use IDA and R2](https://github.com/radare/radare2ida)
- [Raspberry PI hang instruction](https://www.nowsecure.com/blog/2015/08/16/raspberry-pi-hang-instruction/) - by @pancake
- [Solving avatao's "R3v3rs3 4"](https://github.com/sghctoma/writeups/blob/master/hacktivity2015-avatao/01-reverse4/01-reverse4.md) - by @sghctoma
- [Reverse Engineering With Radare2, Part 1](https://samsymons.com/blog/reverse-engineering-with-radare2-part-1/) - by @sam_symons
- [Simple crackme with Radare2](http://remchp.com/blog/?p=126) - by @futex90
- [Pwning With Radare2](http://crowell.github.io/blog/2014/11/23/pwning-with-radare2/) - by @crowell
- [Reversing the FBI malware's payload (shellcode) with radare2](https://www.reddit.com/r/ReverseEngineering/comments/2de2ud/reversing_the_fbi_malwares_payload_shellcode_with/) - by @MalwareMustDie
- [ROPping to Victory](https://jmpesp.me/rop-emporium-ret2win-with-radare-and-pwntools/)
- [ROPping to Victory - Part 2, split](https://jmpesp.me/ropping-to-victory-part-2-split/)

## Tools

- [Docker image encapsulates the reverse-engineering framework](https://hub.docker.com/r/remnux/radare2/)
- [Malfunction - Malware Analysis Tool using Function Level Fuzzy Hashing](https://github.com/Dynetics/Malfunction)
- [rarop - graphical ROP chain builder using radare2 and r2pipe](https://github.com/jpenalbae/rarop)
- [Radare2 and Frida better together](https://github.com/nowsecure/r2frida)
- [Android APK analyzer based on radare2](https://github.com/mhelwig/apk-anal)

## Scripts

- [helper radare2 script to analyze UEFI firmware modules](https://github.com/mytbk/radare-uefi)
- [ThinkPwn Scanner](https://github.com/Cr4sh/ThinkPwn/blob/master/scan_thinkpwn.py) - by @d_olex and @trufae
- [radare2-lldb integration](https://github.com/nowsecure/r2lldb)
- [create a YARA signature for the bytes of the current function](https://gist.github.com/cmatthewbrooks/ea38729ec5f69c8c7c966d3e37016020)
- [A radare2 Plugin to perform symbolic execution with a simple macro call (r2 + angr)](https://github.com/gast04/r4ge)
- [Just a simple radare2 Jupyter kernel](https://github.com/guedou/jupyter-radare2)
- [r2scapy - a radare2 plugin that decodes packets with Scapy](https://github.com/guedou/r2scapy)
- [A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table](https://github.com/danigargu/syms2elf)
- [radare2 plugin - converts asm to pseudo-C code (experimental)](https://github.com/wargio/r2dec-js)
- [A python script using radare2 for decrypt and patch the strings of GootKit malware](https://github.com/d00rt/gootkit_string_patcher)
- [Collection of scripts for radare2 for MIPS arch](https://github.com/mrmacete/r2scripts/)
- [Extract functions and opcodes with radare2](https://github.com/andrewaeva/strange-functions) - by @andrewaeva
- [r2-ropstats - a set of tools based on radare2 for analysis of ROP gadgets and payloads](https://github.com/shaded-enmity/r2-ropstats)
- [Patch kextd using radare2](https://github.com/Tyilo/kextd_patcher)
- [Python-r2pipe script that draws ascii and graphviz graphs of library dependencies](https://github.com/radare/radare2-r2pipe/blob/master/python/examples/libgraph.py)
- [Simple XOR DDOS strings deobfuscator](https://github.com/jpenalbae/r2-scripts/tree/master/ddos-xor-deobfuscator) - by @NighterMan
- [Decode multiple shellcodes encoded with msfencode](https://github.com/jpenalbae/r2-scripts/tree/master/msfdecoder) - by @NighterMan
- [Baleful CTF task plugins](https://github.com/radare/radare2-extras/tree/master/baleful)

## Contributing

[Please refer the guidelines at contributing.md for details](Contributing.md).
