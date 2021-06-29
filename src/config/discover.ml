module C = Configurator.V1

(* Backported from OCaml 4.10.0 *)
let concat_map f l =
  let rec aux f acc = function
    | [] -> List.rev acc
    | x :: l ->
        let xs = f x in
        aux f (List.rev_append xs acc) l
  in
  aux f [] l

let () =
  C.main ~name:"argon2" (fun c ->
      let default : C.Pkg_config.package_conf =
        { libs = [ "-largon2" ]; cflags = [] }
      in
      let conf =
        match C.Pkg_config.get c with
        | None -> default
        | Some pc -> (
            match C.Pkg_config.query pc ~package:"libargon2" with
            | None -> default
            | Some deps -> deps)
      in

      concat_map (fun flag -> [ "-cclib"; flag ]) conf.libs
      |> C.Flags.write_sexp "flags.sexp")
