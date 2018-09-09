#!/usr/bin/env ocaml
#use "topfind";;
#require "topkg"
open Topkg

let () =
  Pkg.describe
    ~change_logs:[] (*bad!*)
    ~licenses:[] (*bad!*)
    "argon2" @@ fun c ->
  Ok [
    Pkg.lib ~exts:Exts.module_library "src/argon2";
    Pkg.doc "examples/examples.ml";
  ]
