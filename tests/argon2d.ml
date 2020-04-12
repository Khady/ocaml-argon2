open Argon2
open Printf

let hash_len = 32

let t_cost = 2

let m_cost = 65536

let parallelism = 1

let salt = "0000000000000000"

let salt_len = String.length salt

let pwd = "password"

let hash_raw () =
  match D.hash_raw ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len with
  | Result.Ok hash ->
      printf "argon2d hash:";
      D.hash_to_string hash
      |> String.iter (fun c -> Printf.printf "%02x" (Char.code c));
      printf "\n"
  | Result.Error e ->
      printf "Error while computing hash with argon2d_hash_raw: %s\n"
        (ErrorCodes.message e)

let () =
  hash_raw ();
  ()
