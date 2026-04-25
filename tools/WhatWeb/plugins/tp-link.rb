##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# https://morningstarsecurity.com/research/whatweb
#
# This plugin is tested on a TP-Link TD-W9970 Router
##
Plugin.define do
  name "TP-Link"
  authors [
    "John de Kroon <john.de.kroon@cyberant.com>", # 2025‑10‑18
  ]
  version "0.1"
  description "Detects TP‑Link routers."
  website "https://www.tp-link.com/"

  matches [
    {
      :regexp => /<label id="copyright">Copyright &copy; \d{4} TP-LINK Technologies Co., Ltd\. All rights reserved\.\s*<\/label>/,
      :model => /var\s+modelName\s*=\s*"([^"]+)";/
    }
  ]
end
