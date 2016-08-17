#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# VirusTotal
#   Check data against VirusTotal, to fetch relevant information
#
# Software is free software released under the "Original BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels
# Copyright (c) 2016  NorthernSec

import json
import urllib.request as req
import urllib.parse   as pars

from TIME.lib.Config import Configuration as conf
import TIME.lib.Plugin

class VirusTotal(TIME.lib.Plugin.Plugin):
  def __init__(self, key=None):
    if not key: raise(Exception("No VirusTotal API key"))
    self.key    = key
    self.vt     = "https://www.virustotal.com/vtapi/v2/%s/report"
    self.types  = {conf.INTEL_IP:     "ip-address",
                   conf.INTEL_DOMAIN: "domain",
                   conf.INTEL_URL:    "url"}
    self.params = {conf.INTEL_IP:     "ip",
                   conf.INTEL_DOMAIN: "domain",
                   conf.INTEL_URL:    "resource"}

  def _get_report(self, orig_intel, intel_type):
    parameters = {self.params[intel_type]: orig_intel, 'apikey': self.key}
    url = '%s?%s' % (self.vt%self.types[intel_type], pars.urlencode(parameters))
    response = req.urlopen(url).read()
    if not response: return {}
    return json.loads(response.decode("utf"))

  def get_related_intel(self, orig_intel, intel_type):
    results = []
    if intel_type not in [conf.INTEL_DOMAIN, conf.INTEL_IP, conf.INTEL_URL]:
      return []
    data = self._get_report(orig_intel, intel_type)
    if data.get("country"): results.append((data.get("country"), "Country", conf.INTEL_TEXT, None))
    for d in data.get("resolutions", []):
      if d.get("ip_address"): results.append((d.get("ip_address"), "Resolved IP", conf.INTEL_IP, None))
      if d.get("hostname"):   results.append((d.get("hostname"), "Hostname", conf.INTEL_DOMAIN, None))
    for d in data.get("detected_urls", []):
      pass
    if data.get("url"):
      AV_Hits = []
      for scanner in data.get("scans", {}).keys():
        if data["scans"][scanner].get("detected"):
          AV_Hits.append(scanner)
      if len(AV_Hits) > 0:
        if len(AV_Hits) > 1:
          info = "#Detected by\n * "+" * ".join(AV_Hits)
          results.append(("Malicious Site", "Multiple", conf.INTEL_TEXT, info))
        else:
          results.append(("Malicious Site", AV_Hits[0], conf.INTEL_TEXT, None))
    return results
