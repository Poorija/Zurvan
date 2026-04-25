##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# https://morningstarsecurity.com/research/whatweb
##
Plugin.define do
  name "Cisco-Meraki"
  authors [
    "John de Kroon <john.de.kroon@cyberant.com>",   # 2025-10-16
  ]
  version "0.1"
  description "This plugin identifies Cisco Meraki – cloud‑managed IT platform"

  # Matches #
  matches [
    # Detect Meraki via the logo image in the HTML body
    { :string => "Meraki",
      :regexp => /<img id="header_logo" src="images\/meraki-logo\.png" width="120">/ },
  ]

end
