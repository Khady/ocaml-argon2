open Argon2

let () =
  let hash_len = 32 in
  let encoded_len = 128 in
  begin match I.hash_raw 2 65536 1 "password" "0000000000000000" hash_len with
    | Result.Ok hash ->
      Printf.printf "argon2i hash:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      Printf.printf "\n";
    | Result.Error e ->
      Printf.printf "Error while computing hash with argon2i_hash_raw: %s\n"
        (Argon2_ErrorCodes.show e)
  end;
  begin match D.hash_raw 2 65536 1 "password" "0000000000000000" hash_len with
    | Result.Ok hash ->
      Printf.printf "argon2d hash:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      Printf.printf "\n";
    | Result.Error e ->
      Printf.printf "Error while computing hash with argon2d_hash_raw: %s\n"
        (Argon2_ErrorCodes.show e)
  end;
  begin match hash 2 65536 1 "password" "0000000000000000" Argon2_type.Argon2_d hash_len encoded_len with
    | Result.Ok (hash, encoded) ->
      Printf.printf "hash argon2d:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      Printf.printf "\n";
      Printf.printf "encoded argon2d:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) encoded;
      Printf.printf "\n";
      begin
        match verify encoded "password" Argon2_type.Argon2_d with
        | Result.Ok _ -> Printf.printf "verify OK\n"
        | Result.Error e ->
          Printf.printf "Error while computing verify: %s\n"
            (Argon2_ErrorCodes.show e)
      end;
    | Result.Error e ->
      Printf.printf "Error while computing hash: %s\n"
        (Argon2_ErrorCodes.show e)
  end;
