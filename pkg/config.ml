#!/usr/bin/env ocaml
#directory "pkg"
#use "topkg-ext.ml"

module Config = struct
  include Config_default

  let vars =
    [ "NAME", "argon2";
      "VERSION", "0.1";
      "MAINTAINER", "Louis Roché <louis@louisroche.net>"; ]
end
