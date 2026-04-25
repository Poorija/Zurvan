##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# https://morningstarsecurity.com/research/whatweb
##
Plugin.define do
  name "Ubiquiti UISP Router"
  authors [
    "John de Kroon <john.de.kroon@cyberant.com>", # 2025-10-18
  ]
  version "0.1"
  description "Ubiquiti UISP router – detected via its web UI title or the public device API (/api/v1.0/public/device)."
  website "https://ui.com/"

  # Dorks #
  dorks [
    'intitle:"UISP Router"'
  ]

  # Matches #
  matches [
    # Detect the standard web‑UI page title
    {
      :text => "<title>UISP Router</title>"
    },

    # Detect the public device API JSON
    {
      :url      => "/api/v1.0/public/device",
      :search   => "body",
      :model    => /"model"\s*:\s*"UISP-R"/,
    }
  ]
end
