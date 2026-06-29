# Package

version       = "0.1.1"
author        = "Takeyoshi Kikuchi"
description   = "Generate nftables rules from a small awall-compatible firewall configuration subset."
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
bin           = @["awall_nft"]


# Dependencies

requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "sunny >= 0.1.10"
#requires "pretty >= 0.2.1"
requires "argparse >= 4.0.2"
