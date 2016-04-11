open Argon2

let () =
  let hash_len = 32 in
  let t_cost = 2 in
  let m_cost = 65536 in
  let parallelism = 1 in
  let salt = "0000000000000000" in
  let salt_len = String.length salt in
  let password = "password" in
  let encoded_len = encoded_len t_cost m_cost parallelism salt_len hash_len in
  begin match I.hash_raw t_cost m_cost parallelism password salt hash_len with
    | Result.Ok hash ->
      Printf.printf "argon2i hash:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      Printf.printf "\n";
    | Result.Error e ->
      Printf.printf "Error while computing hash with argon2i_hash_raw: %s\n"
        (Argon2_ErrorCodes.message e)
  end;
  begin match D.hash_raw t_cost m_cost parallelism password salt hash_len with
    | Result.Ok hash ->
      Printf.printf "argon2d hash:\n";
      String.iter (fun c -> Printf.printf "%02x" (Char.code c)) hash;
      Printf.printf "\n";
    | Result.Error e ->
      Printf.printf "Error while computing hash with argon2d_hash_raw: %s\n"
        (Argon2_ErrorCodes.message e)
  end;
  begin
    match hash t_cost m_cost parallelism password salt
            Argon2_type.Argon2_d hash_len encoded_len
            Argon2_version.ARGON2_VERSION_NUMBER
    with
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
            (Argon2_ErrorCodes.message e)
      end;
    | Result.Error e ->
      Printf.printf "Error while computing hash: %s\n"
        (Argon2_ErrorCodes.message e)
  end;
