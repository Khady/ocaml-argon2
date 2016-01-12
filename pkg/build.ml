#!/usr/bin/env ocaml
#directory "pkg";;
#use "topkg.ml";;
#use "config.ml";;

let () =
  Vars.subst ~skip:Config.subst_skip ~vars:Config.vars ~dir:"." >>& fun () ->
  Pkg.describe "argon2" ~builder:(`OCamlbuild []) [
    Pkg.lib "pkg/META";
    Pkg.lib ~exts:Exts.module_library "src/argon2";
    Pkg.doc "examples/examples.ml";
  ]
