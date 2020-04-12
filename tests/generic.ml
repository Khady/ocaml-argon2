open Argon2
open Printf

let kind () =
  printf "===== kind =====\n";
  [ D; I; ID ]
  |> List.map (show_kind `Upper)
  |> List.iter (printf "show_kind upper: %s\n");
  [ D; I; ID ]
  |> List.map (show_kind `Lower)
  |> List.iter (printf "show_kind lower: %s\n");
  ()

let show_kind = show_kind `Upper

let hash_len = 32

let t_cost = 2

let m_cost = 65536

let parallelism = 1

let salt = "0000000000000000"

let salt_len = String.length salt

let pwd = "password"

let gen kind =
  let msg fmt = Printf.ksprintf (Printf.printf "%s: %s" (show_kind kind)) fmt in

  let encoded_len =
    encoded_len ~t_cost ~m_cost ~parallelism ~salt_len ~hash_len ~kind
  in
  match
    hash ~t_cost ~m_cost ~parallelism ~pwd ~salt ~kind ~hash_len ~encoded_len
      ~version:VERSION_NUMBER
  with
  | Result.Ok (hash, encoded) -> (
      msg "hash:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      printf "\n";
      msg "encoded:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) encoded;
      printf "\n";
      match verify ~encoded ~pwd ~kind with
      | Result.Ok _ -> msg "verify OK\n"
      | Result.Error e ->
          msg "Error while computing verify: %s\n" (ErrorCodes.message e) )
  | Result.Error e ->
      msg "Error while computing hash: %s\n" (ErrorCodes.message e)

let () =
  kind ();
  gen I;
  gen ID;
  gen D;
  ()
