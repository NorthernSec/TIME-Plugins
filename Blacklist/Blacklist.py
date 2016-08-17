#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Blacklist plug-in
#   Checks domains and IP addresses against several sources to see if
#   they are marked as "bad", and the reason why.
#
# Software is free software released under the "Original BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels
# Copyright (c) 2016  NorthernSec

from collections import defaultdict

from TIME.lib.Config import Configuration as conf
import TIME.lib.Plugin

class Blacklist(TIME.lib.Plugin.Plugin):
  SCAN_SSH      = "SSH Scanner"
  SCAN_HTTP     = "HTTP Scanner"
  SCAN_VNC      = "VNC Scanner"
  SCAN_POP3     = "POP3 Scanner"
  SCAN_IMAP     = "IMAP Scanner"
  SCAN_SMTP     = "SMTP Scanner"
  SCAN_FTP      = "FTP Scanner"
  KNOWN_C2      = "Known C&C"
  KNOWN_BOT     = "Known Bot"
  BRUTEFORCER   = "Bruteforcer"
  COMPROMISED   = "Compromised"
  MALICIOUS     = "Malicious Host"
  TOR_EXIT_NODE = "Tor exit Node"

  # Format:  (<file to check>,                                             <type of hit>,  <source>)
  sources = [('dragonresearchgroup.org/insight/sshpwauth.txt',                SCAN_SSH,      "Dragon Research"),
             ('dragonresearchgroup.org/insight/http-report.txt',              SCAN_HTTP,     "Dragon Research"),
             ('http://dragonresearchgroup.org/insight/vncprobe.txt',          SCAN_VNC,      "Dragon Research"),
             ('osint.bambenekconsulting.com/feeds/c2-masterlist.txt',         KNOWN_C2,      "Bambenek Consulting"),
             ('lists.blocklist.de/lists/21.txt',                              SCAN_FTP,      "Fail2Ban"),
             ('lists.blocklist.de/lists/22.txt',                              SCAN_SSH,      "Fail2Ban"),
             ('lists.blocklist.de/lists/25.txt',                              SCAN_SMTP,     "Fail2Ban"),
             ('lists.blocklist.de/lists/80.txt',                              SCAN_HTTP,     "Fail2Ban"),
             ('lists.blocklist.de/lists/110.txt',                             SCAN_POP3,     "Fail2Ban"),
             ('lists.blocklist.de/lists/143.txt',                             SCAN_IMAP,     "Fail2Ban"),
             ('lists.blocklist.de/lists/443.txt',                             SCAN_HTTP,     "Fail2Ban"),
             ('lists.blocklist.de/lists/993.txt',                             SCAN_IMAP,     "Fail2Ban"),
             ('lists.blocklist.de/lists/bots.txt',                            KNOWN_BOT,     "Fail2Ban"),
             ('lists.blocklist.de/lists/bruteforcelogin.txt',                 BRUTEFORCER,   "Fail2Ban"),
             ('rules.emergingthreats.net/blockrules/compromised-ips.txt',     COMPROMISED,   "Emerging Threats"),
             ('http://reputation.alienvault.com/reputation.data',             MALICIOUS,     "Alienvault"),
             ('torstatus.blutmagie.de/ip_list_exit.php/Tor_ip_list_EXIT.csv', TOR_EXIT_NODE, "Blut Magpie")]

  def __init__(self):
    self._refresh_sources()

  def _refresh_sources(self):
    for i, source in enumerate(self.sources):
      # Check if present, if so: drop
      if len(source) > 3: del source[3]
      # Fecht new version and append
      data = conf.getFile(source[0])
      if not data: data=""
      self.sources[i] = source + (data,)


  def clean(self):
    self._refresh_sources()

  def get_related_intel(self, orig_intel, intel_type):
    hits = defaultdict(list)
    cleaned = []
    if intel_type not in [conf.INTEL_DOMAIN, conf.INTEL_IP]:
      return []
    # Clean domain names
    if intel_type == conf.INTEL_DOMAIN: orig_intel.lstrip("www.")
    # Make list of hit types and source/hit
    for source in self.sources:
      if orig_intel in source[3]:
        # Add, but prevent duplicates
        if not source[2] in hits[source[1]]:
          hits[source[1]].append(source[2])
    # Now report the hits for the host
    for key in hits.keys():
      source = hits[key][0] # Default to first element, in case it's only one
      text   = None
      # Override if more sources report hit
      if len(hits[key]) > 1:
        source = "Multiple"
        text   = "# Reported by \n * " + "\n * ".join(hits[key])
      cleaned.append((key, source, conf.INTEL_TEXT, text))
    return cleaned
