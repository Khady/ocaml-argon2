open Ctypes
open Foreign

module Kind = struct
  type t = D | I | ID

  let read = function
    | 0 -> D
    | 1 -> I
    | 2 -> ID
    | _ as e -> invalid_arg (Printf.sprintf "%d is not a valid argon2_type" e)

  let write = function D -> 0 | I -> 1 | ID -> 2

  let t = view int ~read ~write

  let argon2_type2string =
    foreign "argon2_type2string"
      (t (* type *) @-> int (* uppercase *) @-> returning string)

  let show (case : [ `Upper | `Lower ]) t =
    let case = match case with `Upper -> 1 | `Lower -> 0 in
    argon2_type2string t case
end

type kind = Kind.t = D | I | ID

let show_kind = Kind.show

module Version = struct
  type t = VERSION_10 | VERSION_13 | VERSION_NUMBER

  let read = function
    | 0x10 -> VERSION_10
    | 0x13 -> VERSION_13
    | _ as e ->
        invalid_arg (Printf.sprintf "%d is not a valid argon2_version" e)

  let write = function
    | VERSION_10 -> 0x10
    | VERSION_13 -> 0x13
    | VERSION_NUMBER -> 0x13

  let t = view int ~read ~write
end

type version = Version.t = VERSION_10 | VERSION_13 | VERSION_NUMBER

module ErrorCodes = struct
  type t =
    | OK
    | OUTPUT_PTR_NULL
    | OUTPUT_TOO_SHORT
    | OUTPUT_TOO_LONG
    | PWD_TOO_SHORT
    | PWD_TOO_LONG
    | SALT_TOO_SHORT
    | SALT_TOO_LONG
    | AD_TOO_SHORT
    | AD_TOO_LONG
    | SECRET_TOO_SHORT
    | SECRET_TOO_LONG
    | TIME_TOO_SMALL
    | TIME_TOO_LARGE
    | MEMORY_TOO_LITTLE
    | MEMORY_TOO_MUCH
    | LANES_TOO_FEW
    | LANES_TOO_MANY
    | PWD_PTR_MISMATCH
    | SALT_PTR_MISMATCH
    | SECRET_PTR_MISMATCH
    | AD_PTR_MISMATCH
    | MEMORY_ALLOCATION_ERROR
    | FREE_MEMORY_CBK_NULL
    | ALLOCATE_MEMORY_CBK_NULL
    | INCORRECT_PARAMETER
    | INCORRECT_TYPE
    | OUT_PTR_MISMATCH
    | THREADS_TOO_FEW
    | THREADS_TOO_MANY
    | MISSING_ARGS
    | ENCODING_FAIL
    | DECODING_FAIL
    | THREAD_FAIL
    | DECODING_LENGTH_FAIL
    | VERIFY_MISMATCH
    | Other of int

  let read = function
    | -0 -> OK
    | -1 -> OUTPUT_PTR_NULL
    | -2 -> OUTPUT_TOO_SHORT
    | -3 -> OUTPUT_TOO_LONG
    | -4 -> PWD_TOO_SHORT
    | -5 -> PWD_TOO_LONG
    | -6 -> SALT_TOO_SHORT
    | -7 -> SALT_TOO_LONG
    | -8 -> AD_TOO_SHORT
    | -9 -> AD_TOO_LONG
    | -10 -> SECRET_TOO_SHORT
    | -11 -> SECRET_TOO_LONG
    | -12 -> TIME_TOO_SMALL
    | -13 -> TIME_TOO_LARGE
    | -14 -> MEMORY_TOO_LITTLE
    | -15 -> MEMORY_TOO_MUCH
    | -16 -> LANES_TOO_FEW
    | -17 -> LANES_TOO_MANY
    | -18 -> PWD_PTR_MISMATCH
    | -19 -> SALT_PTR_MISMATCH
    | -20 -> SECRET_PTR_MISMATCH
    | -21 -> AD_PTR_MISMATCH
    | -22 -> MEMORY_ALLOCATION_ERROR
    | -23 -> FREE_MEMORY_CBK_NULL
    | -24 -> ALLOCATE_MEMORY_CBK_NULL
    | -25 -> INCORRECT_PARAMETER
    | -26 -> INCORRECT_TYPE
    | -27 -> OUT_PTR_MISMATCH
    | -28 -> THREADS_TOO_FEW
    | -29 -> THREADS_TOO_MANY
    | -30 -> MISSING_ARGS
    | -31 -> ENCODING_FAIL
    | -32 -> DECODING_FAIL
    | -33 -> THREAD_FAIL
    | -34 -> DECODING_LENGTH_FAIL
    | -35 -> VERIFY_MISMATCH
    | _ as other -> Other other

  let write = function
    | OK -> 0
    | OUTPUT_PTR_NULL -> -1
    | OUTPUT_TOO_SHORT -> -2
    | OUTPUT_TOO_LONG -> -3
    | PWD_TOO_SHORT -> -4
    | PWD_TOO_LONG -> -5
    | SALT_TOO_SHORT -> -6
    | SALT_TOO_LONG -> -7
    | AD_TOO_SHORT -> -8
    | AD_TOO_LONG -> -9
    | SECRET_TOO_SHORT -> -10
    | SECRET_TOO_LONG -> -11
    | TIME_TOO_SMALL -> -12
    | TIME_TOO_LARGE -> -13
    | MEMORY_TOO_LITTLE -> -14
    | MEMORY_TOO_MUCH -> -15
    | LANES_TOO_FEW -> -16
    | LANES_TOO_MANY -> -17
    | PWD_PTR_MISMATCH -> -18
    | SALT_PTR_MISMATCH -> -19
    | SECRET_PTR_MISMATCH -> -20
    | AD_PTR_MISMATCH -> -21
    | MEMORY_ALLOCATION_ERROR -> -22
    | FREE_MEMORY_CBK_NULL -> -23
    | ALLOCATE_MEMORY_CBK_NULL -> -24
    | INCORRECT_PARAMETER -> -25
    | INCORRECT_TYPE -> -26
    | OUT_PTR_MISMATCH -> -27
    | THREADS_TOO_FEW -> -28
    | THREADS_TOO_MANY -> -19
    | MISSING_ARGS -> -30
    | ENCODING_FAIL -> -31
    | DECODING_FAIL -> -32
    | THREAD_FAIL -> -33
    | DECODING_LENGTH_FAIL -> -34
    | VERIFY_MISMATCH -> -35
    | Other o -> o

  let t = view int ~read ~write

  let argon2_error_message =
    foreign "argon2_error_message" (t @-> returning string)

  let message error_code = argon2_error_message error_code
end

let hash_encoded fun_name =
  foreign fun_name
    (uint32_t (* t_cost *) @-> uint32_t (* m_cost *)
    @-> uint32_t (* parallelism *) @-> string
    (* pwd *) @-> size_t (* pwdlen *)
    @-> string (* salt *) @-> size_t
    (* saltlen *) @-> size_t (* hashlen *)
    @-> ptr char (* encoded *) @-> size_t (* encodedlen *)
    @-> returning ErrorCodes.t)

let hash_raw fun_name =
  foreign fun_name
    (uint32_t (* t_cost *) @-> uint32_t (* m_cost *)
    @-> uint32_t (* parallelism *) @-> string
    (* pwd *) @-> size_t (* pwdlen *)
    @-> string (* salt *) @-> size_t
    (* saltlen *) @-> ptr void (* hash *)
    @-> size_t (* hashlen *) @-> returning ErrorCodes.t)

let argon2i_hash_encoded = hash_encoded "argon2i_hash_encoded"

let argon2i_hash_raw = hash_raw "argon2i_hash_raw"

let argon2d_hash_encoded = hash_encoded "argon2d_hash_encoded"

let argon2d_hash_raw = hash_raw "argon2d_hash_raw"

let argon2id_hash_encoded = hash_encoded "argon2id_hash_encoded"

let argon2id_hash_raw = hash_raw "argon2id_hash_raw"

let argon2_hash =
  foreign "argon2_hash"
    (uint32_t (* t_cost *) @-> uint32_t (* m_cost *)
    @-> uint32_t (* parallelism *) @-> string
    (* pwd *) @-> size_t (* pwdlen *)
    @-> string (* salt *) @-> size_t
    (* saltlen *) @-> ptr void (* hash *)
    @-> size_t (* hashlen *) @-> ptr char (* encoded *)
    @-> size_t (* encodedlen *) @-> Kind.t (* type *)
    @-> Version.t (* version *) @-> returning ErrorCodes.t)

let verify fun_name =
  foreign fun_name
    (string (* encoded *) @-> string
    (* pwd *) @-> size_t (* pwdlen *)
    @-> returning ErrorCodes.t)

let argon2i_verify = verify "argon2i_verify"

let argon2d_verify = verify "argon2d_verify"

let argon2id_verify = verify "argon2d_verify"

let argon2_verify =
  foreign "argon2_verify"
    (string (* encoded *) @-> string
    (* pwd *) @-> size_t (* pwdlen *)
    @-> Kind.t (* type *) @-> returning ErrorCodes.t)

let argon2_encodedlen =
  foreign "argon2_encodedlen"
    (uint32_t (* t_cost *) @-> uint32_t (* m_cost *)
    @-> uint32_t (* parallelism *) @-> uint32_t (* saltlen *)
    @-> uint32_t (* hashlen *) @-> Kind.t
    (* type *) @-> returning size_t)

let hash_encoded hash_fun ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len
    ~encoded_len =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  let encoded = allocate_n char ~count:encoded_len in
  let s_encoded_len = Unsigned.Size_t.of_int encoded_len in

  match
    hash_fun u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len
      s_hash_len encoded s_encoded_len
  with
  | ErrorCodes.OK ->
      let encoded = string_from_ptr encoded ~length:(encoded_len - 1) in
      Result.Ok encoded
  | e -> Result.Error e

let hash_raw hash_fun ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let hash = allocate_n char ~count:hash_len |> to_voidp in
  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  match
    hash_fun u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len hash
      s_hash_len
  with
  | ErrorCodes.OK ->
      let hash = string_from_ptr (from_voidp char hash) ~length:hash_len in
      Result.Ok hash
  | e -> Result.Error e

let verify verify_fun ~encoded ~pwd =
  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  match verify_fun encoded pwd s_pwd_len with
  | ErrorCodes.OK -> Result.Ok true
  | e -> Result.Error e

module type HashBindings = sig
  val hash_raw :
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    string ->
    Unsigned.size_t ->
    string ->
    Unsigned.size_t ->
    unit Ctypes_static.ptr ->
    Unsigned.size_t ->
    ErrorCodes.t

  val hash_encoded :
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    Unsigned.uint32 ->
    string ->
    Unsigned.size_t ->
    string ->
    Unsigned.size_t ->
    Unsigned.size_t ->
    char Ctypes_static.ptr ->
    Unsigned.size_t ->
    ErrorCodes.t

  val verify : string -> string -> Unsigned.size_t -> ErrorCodes.t
end

module type HashFunctions = sig
  type hash

  type encoded

  val hash_raw :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    (hash, ErrorCodes.t) Result.result

  val hash_encoded :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    encoded_len:int ->
    (encoded, ErrorCodes.t) Result.result

  val verify :
    encoded:encoded -> pwd:string -> (bool, ErrorCodes.t) Result.result

  val hash_to_string : hash -> string

  val encoded_to_string : encoded -> string
end

module MakeInternal (H : HashBindings) : HashFunctions = struct
  type hash = string

  type encoded = string

  let hash_to_string h = h

  let encoded_to_string e = e

  let hash_raw = hash_raw H.hash_raw

  let hash_encoded = hash_encoded H.hash_encoded

  let verify = verify H.verify
end

module I = MakeInternal (struct
  let hash_raw = argon2i_hash_raw

  let hash_encoded = argon2i_hash_encoded

  let verify = argon2i_verify
end)

module D = MakeInternal (struct
  let hash_raw = argon2d_hash_raw

  let hash_encoded = argon2d_hash_encoded

  let verify = argon2d_verify
end)

module ID = MakeInternal (struct
  let hash_raw = argon2id_hash_raw

  let hash_encoded = argon2id_hash_encoded

  let verify = argon2id_verify
end)

type hash = string

type encoded = string

let hash ~t_cost ~m_cost ~parallelism ~pwd ~salt ~kind ~hash_len ~encoded_len
    ~version =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let hash = allocate_n char ~count:hash_len |> to_voidp in
  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  let encoded = allocate_n char ~count:encoded_len in
  let s_encoded_len = Unsigned.Size_t.of_int encoded_len in

  let res =
    argon2_hash u_t_cost u_m_cost u_parallelism pwd s_pwd_len salt s_salt_len
      hash s_hash_len encoded s_encoded_len kind version
  in
  match res with
  | ErrorCodes.OK ->
      let hash = string_from_ptr (from_voidp char hash) ~length:hash_len in
      let encoded = string_from_ptr encoded ~length:(encoded_len - 1) in
      Result.Ok (hash, encoded)
  | _ as e -> Result.Error e

let verify ~encoded ~pwd ~kind =
  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  match argon2_verify encoded pwd s_pwd_len kind with
  | ErrorCodes.OK -> Result.Ok true
  | e -> Result.Error e

let encoded_len ~t_cost ~m_cost ~parallelism ~salt_len ~hash_len ~kind =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in
  let u_salt_len = Unsigned.UInt32.of_int salt_len in
  let u_hash_len = Unsigned.UInt32.of_int hash_len in
  let len =
    argon2_encodedlen u_t_cost u_m_cost u_parallelism u_salt_len u_hash_len kind
  in
  Unsigned.Size_t.to_int len
