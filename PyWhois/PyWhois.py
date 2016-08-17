#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# PyWhois plug-in
#   Checks domains and IP addresses against several sources to see if
#   they are marked as "bad", and the reason why.
#
# Software is free software released under the "Original BSD license"
#
# Copyright (c) 2016 	Pieter-Jan Moreels
# Copyright (c) 2016  NorthernSec

from ipwhois import IPWhois

from TIME.lib.Config import Configuration as conf
import TIME.lib.Plugin

class PyWhois(TIME.lib.Plugin.Plugin):

  def get_related_intel(self, orig_intel, intel_type):
    results = []
    if intel_type not in [conf.INTEL_DOMAIN, conf.INTEL_IP]:
      return []
    if intel_type == conf.INTEL_DOMAIN:
      print("PyWhois: To be implemented")
      return []
    elif intel_type == conf.INTEL_IP:
      whois_info = IPWhois(orig_intel).lookup_rdap()
      if whois_info:
        whois = {}
        info         = "#Aditional Info\n"
        whois["ASN"]           = whois_info.get("asn")
        whois["Registrar"]     = whois_info.get("asn_registry")
        whois["Registry date"] = whois_info.get("asn_date")
        whois["Start range"]   = whois_info.get("network", {}).get("start_address")
        whois["End range"]     = whois_info.get("network", {}).get("end_address")
        whois["Handle"]        = whois_info.get("network", {}).get("handle")
        whois["Country"]       = whois_info.get("asn_country_code")
        contacts = []
        for obj in [whois_info["objects"][x] for x in whois_info.get("objects", {}).keys()]:
          part = "\n * * **%s** (%s)"%(obj.get("name", "Unknown"), ", ".join(obj.get("roles", ["unknown"])))
          mail = ", ".join([x["value"] for x in obj.get("email", [])])
          for m in mail.split(", "):
            info = "**%s** (%s)"%(obj.get("name", "Unknown"),  ", ".join(obj.get("roles", ["unknown"])))
            results.append((m, "E-Mail", conf.INTEL_EMAIL, info))
          if mail: part += "<br />%s"%mail
          contacts.append(part)
        for key in sorted(whois):
          if whois[key]: info += (" * **%s** - %s\n"%(key, whois[key]))
        if len(contacts) != 0:
          info += (" * **Contacts**")
          for entety in contacts: info += (entety)
        if whois["ASN"]: results.append((whois["ASN"], "ASN", conf.INTEL_ASN, info))
        if whois["Country"]: results.append((whois["Country"], "Country", conf.INTEL_TEXT, None))
    return results
