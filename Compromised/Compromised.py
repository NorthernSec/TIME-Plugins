#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Compromised plug-in
#   Checks E-Mail addresses and accounts against lists to see if they 
#   have been compromised at any point.
#
# Software is free software released under the "Original BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels
# Copyright (c) 2016  NorthernSec

# Imports
import json

from TIME.lib.Config import Configuration as conf
import TIME.lib.Plugin
import TIME.lib.Toolkit as TK

class Compromised(TIME.lib.Plugin.Plugin):
  MULTIPLE = "Multiple"
  url_HaveIBeenPwned = "https://haveibeenpwned.com/api/v2/breachedaccount/%s"

  def __init__(self):
    functions = TK.getFunctions(self)
    # To add sources, just add them below, and create the functions following
    # the standard.
    self.checklist = {conf.INTEL_EMAIL: [x for x in functions if "_mail_" in x],
                      conf.INTEL_USER: }
    self.titles    = {conf.INTEL_EMAIL: "Compromised Email"}

  def get_related_intel(self, orig_intel, intel_type):
    results = []
    if intel_type not in self.checklist.keys():
      return []
    for key in self.checklist.keys():
      data = self._get_info_list(self.checklist[key], orig_intel)
      if data:
        info, source = data
        results.append((self.titles[key], source, conf.INTEL_TEXT, info))
    return results

  def _get_info_list(self, functlist, intel):
    hits = []
    for funct in functlist:
      data = getattr(self, funct)(intel)
      if data: hits.append(data)
    if len(hits) == 0:
      return None
    info = "\n".join(x[1] for x in hits)
    source = hits[0][0] if len(hits) == 1 else self.MULTIPLE
    return (info, source)

  def _mail_user_haveIBeenPwned(self, email):
    try:
      data = json.loads(conf.getFile(self.url_HaveIBeenPwned%email))
    except:
      return None
    info = "# Have I Been Pwned?"
    for breach in data:
      if breach.get("IsVerified", False):
        info +="\n * **%s** (%s) - %s"%(breach.get("Name", "?"), breach.get("Domain", "?"), breach.get("Description", "No description"))
    return ("HaveIBeenPwned?", info)
