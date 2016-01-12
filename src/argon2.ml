open Ctypes
open Foreign

module Argon2_type = struct
  type c = int

  type t =
    | Argon2_d
    | Argon2_i

  let read = function
    | 0 -> Argon2_d
    | 1 -> Argon2_i
    | _ as e ->
      raise (Invalid_argument (Printf.sprintf "%d is not a valid argon2_type" e))

  let write = function
    | Argon2_d -> 0
    | Argon2_i -> 1

  let t = view int ~read ~write
end

module Argon2_ErrorCodes = struct
  type c = int

  type t =
    | ARGON2_OK
    | ARGON2_OUTPUT_PTR_NULL
    | ARGON2_OUTPUT_TOO_SHORT
    | ARGON2_OUTPUT_TOO_LONG
    | ARGON2_PWD_TOO_SHORT
    | ARGON2_PWD_TOO_LONG
    | ARGON2_SALT_TOO_SHORT
    | ARGON2_SALT_TOO_LONG
    | ARGON2_AD_TOO_SHORT
    | ARGON2_AD_TOO_LONG
    | ARGON2_SECRET_TOO_SHORT
    | ARGON2_SECRET_TOO_LONG
    | ARGON2_TIME_TOO_SMALL
    | ARGON2_TIME_TOO_LARGE
    | ARGON2_MEMORY_TOO_LITTLE
    | ARGON2_MEMORY_TOO_MUCH
    | ARGON2_LANES_TOO_FEW
    | ARGON2_LANES_TOO_MANY
    | ARGON2_PWD_PTR_MISMATCH
    | ARGON2_SALT_PTR_MISMATCH
    | ARGON2_SECRET_PTR_MISMATCH
    | ARGON2_AD_PTR_MISMATCH
    | ARGON2_MEMORY_ALLOCATION_ERROR
    | ARGON2_FREE_MEMORY_CBK_NULL
    | ARGON2_ALLOCATE_MEMORY_CBK_NULL
    | ARGON2_INCORRECT_PARAMETER
    | ARGON2_INCORRECT_TYPE
    | ARGON2_OUT_PTR_MISMATCH
    | ARGON2_THREADS_TOO_FEW
    | ARGON2_THREADS_TOO_MANY
    | ARGON2_MISSING_ARGS
    | ARGON2_ENCODING_FAIL
    | ARGON2_DECODING_FAIL
    | Other of int
    [@@deriving show]

  let read = function
    | 0 -> ARGON2_OK
    | 1 -> ARGON2_OUTPUT_PTR_NULL
    | 2 -> ARGON2_OUTPUT_TOO_SHORT
    | 3 -> ARGON2_OUTPUT_TOO_LONG
    | 4 -> ARGON2_PWD_TOO_SHORT
    | 5 -> ARGON2_PWD_TOO_LONG
    | 6 -> ARGON2_SALT_TOO_SHORT
    | 7 -> ARGON2_SALT_TOO_LONG
    | 8 -> ARGON2_AD_TOO_SHORT
    | 9 -> ARGON2_AD_TOO_LONG
    | 10 -> ARGON2_SECRET_TOO_SHORT
    | 11 -> ARGON2_SECRET_TOO_LONG
    | 12 -> ARGON2_TIME_TOO_SMALL
    | 13 -> ARGON2_TIME_TOO_LARGE
    | 14 -> ARGON2_MEMORY_TOO_LITTLE
    | 15 -> ARGON2_MEMORY_TOO_MUCH
    | 16 -> ARGON2_LANES_TOO_FEW
    | 17 -> ARGON2_LANES_TOO_MANY
    | 18 -> ARGON2_PWD_PTR_MISMATCH
    | 19 -> ARGON2_SALT_PTR_MISMATCH
    | 20 -> ARGON2_SECRET_PTR_MISMATCH
    | 21 -> ARGON2_AD_PTR_MISMATCH
    | 22 -> ARGON2_MEMORY_ALLOCATION_ERROR
    | 23 -> ARGON2_FREE_MEMORY_CBK_NULL
    | 24 -> ARGON2_ALLOCATE_MEMORY_CBK_NULL
    | 25 -> ARGON2_INCORRECT_PARAMETER
    | 26 -> ARGON2_INCORRECT_TYPE
    | 27 -> ARGON2_OUT_PTR_MISMATCH
    | 28 -> ARGON2_THREADS_TOO_FEW
    | 29 -> ARGON2_THREADS_TOO_MANY
    | 30 -> ARGON2_MISSING_ARGS
    | 31 -> ARGON2_ENCODING_FAIL
    | 32 -> ARGON2_DECODING_FAIL
    | _ as other -> Other other

  let write = function
    | ARGON2_OK -> 0
    | ARGON2_OUTPUT_PTR_NULL -> 1
    | ARGON2_OUTPUT_TOO_SHORT -> 2
    | ARGON2_OUTPUT_TOO_LONG -> 3
    | ARGON2_PWD_TOO_SHORT -> 4
    | ARGON2_PWD_TOO_LONG -> 5
    | ARGON2_SALT_TOO_SHORT -> 6
    | ARGON2_SALT_TOO_LONG -> 7
    | ARGON2_AD_TOO_SHORT -> 8
    | ARGON2_AD_TOO_LONG -> 9
    | ARGON2_SECRET_TOO_SHORT -> 10
    | ARGON2_SECRET_TOO_LONG -> 11
    | ARGON2_TIME_TOO_SMALL -> 12
    | ARGON2_TIME_TOO_LARGE -> 13
    | ARGON2_MEMORY_TOO_LITTLE -> 14
    | ARGON2_MEMORY_TOO_MUCH -> 15
    | ARGON2_LANES_TOO_FEW -> 16
    | ARGON2_LANES_TOO_MANY -> 17
    | ARGON2_PWD_PTR_MISMATCH -> 18
    | ARGON2_SALT_PTR_MISMATCH -> 19
    | ARGON2_SECRET_PTR_MISMATCH -> 20
    | ARGON2_AD_PTR_MISMATCH -> 21
    | ARGON2_MEMORY_ALLOCATION_ERROR -> 22
    | ARGON2_FREE_MEMORY_CBK_NULL -> 23
    | ARGON2_ALLOCATE_MEMORY_CBK_NULL -> 24
    | ARGON2_INCORRECT_PARAMETER -> 25
    | ARGON2_INCORRECT_TYPE -> 26
    | ARGON2_OUT_PTR_MISMATCH -> 27
    | ARGON2_THREADS_TOO_FEW -> 28
    | ARGON2_THREADS_TOO_MANY -> 19
    | ARGON2_MISSING_ARGS -> 30
    | ARGON2_ENCODING_FAIL -> 31
    | ARGON2_DECODING_FAIL -> 32
    | Other o -> o

  let t = view int ~read ~write
end

let argon2_lib = Dl.dlopen
  ~filename:"libargon2.so"
  ~flags:[Dl.RTLD_NOW; Dl.RTLD_GLOBAL]

let argon2i_hash_encoded =
  foreign ~from:argon2_lib "argon2i_hash_encoded"
    (uint32_t                   (* t_cost *)
     @-> uint32_t               (* m_cost *)
     @-> uint32_t               (* parallelism *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> string                 (* salt *)
     @-> size_t                 (* saltlen *)
     @-> size_t                 (* hashlen *)
     @-> ptr char               (* encoded *)
     @-> size_t                 (* encodedlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2i_hash_raw =
  foreign ~from:argon2_lib "argon2i_hash_raw"
    (uint32_t                   (* t_cost *)
     @-> uint32_t               (* m_cost *)
     @-> uint32_t               (* parallelism *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> string                 (* salt *)
     @-> size_t                 (* saltlen *)
     @-> ptr void               (* hash *)
     @-> size_t                 (* hashlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2d_hash_encoded =
  foreign ~from:argon2_lib "argon2d_hash_encoded"
    (uint32_t                   (* t_cost *)
     @-> uint32_t               (* m_cost *)
     @-> uint32_t               (* parallelism *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> string                 (* salt *)
     @-> size_t                 (* saltlen *)
     @-> size_t                 (* hashlen *)
     @-> ptr char               (* encoded *)
     @-> size_t                 (* encodedlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2d_hash_raw =
  foreign ~from:argon2_lib "argon2d_hash_raw"
    (uint32_t                   (* t_cost *)
     @-> uint32_t               (* m_cost *)
     @-> uint32_t               (* parallelism *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> string                 (* salt *)
     @-> size_t                 (* saltlen *)
     @-> ptr void               (* hash *)
     @-> size_t                 (* hashlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2_hash =
  foreign ~from:argon2_lib "argon2_hash"
    (uint32_t                   (* t_cost *)
     @-> uint32_t               (* m_cost *)
     @-> uint32_t               (* parallelism *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> string                 (* salt *)
     @-> size_t                 (* saltlen *)
     @-> ptr void               (* hash *)
     @-> size_t                 (* hashlen *)
     @-> ptr char               (* encoded *)
     @-> size_t                 (* encodedlen *)
     @-> Argon2_type.t          (* type *)
     @-> returning Argon2_ErrorCodes.t)

let argon2i_verify =
  foreign ~from:argon2_lib "argon2i_verify"
    (string                     (* encoded *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2d_verify =
  foreign ~from:argon2_lib "argon2d_verify"
    (string                     (* encoded *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> returning Argon2_ErrorCodes.t)

let argon2_verify =
  foreign ~from:argon2_lib "argon2_verify"
    (string                     (* encoded *)
     @-> string                 (* pwd *)
     @-> size_t                 (* pwdlen *)
     @-> Argon2_type.t          (* type *)
     @-> returning Argon2_ErrorCodes.t)

type hash = string
type encoded = string

let hash_encoded hash_fun
    ~t_cost ~m_cost ~parallelism ~pwd ~salt ~hash_len ~encoded_len =
  let u_t_cost = Unsigned.UInt32.of_int t_cost in
  let u_m_cost = Unsigned.UInt32.of_int m_cost in
  let u_parallelism = Unsigned.UInt32.of_int parallelism in

  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  let s_salt_len = Unsigned.Size_t.of_int @@ String.length salt in

  let s_hash_len = Unsigned.Size_t.of_int hash_len in

  let encoded = allocate_n char ~count:encoded_len in
  let s_encoded_len = Unsigned.Size_t.of_int encoded_len in

  match
    hash_fun
      u_t_cost
      u_m_cost
      u_parallelism
      pwd s_pwd_len
      salt s_salt_len
      s_hash_len
      encoded s_encoded_len
  with
  | Argon2_ErrorCodes.ARGON2_OK ->
    let encoded = string_from_ptr encoded encoded_len in
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
    hash_fun
      u_t_cost
      u_m_cost
      u_parallelism
      pwd s_pwd_len
      salt s_salt_len
      hash s_hash_len
  with
  | Argon2_ErrorCodes.ARGON2_OK ->
    let hash = string_from_ptr (from_voidp char hash) hash_len in
    Result.Ok hash
  | e -> Result.Error e

let hash ~t_cost ~m_cost ~parallelism ~pwd ~salt ~typ ~hash_len ~encoded_len =
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
    argon2_hash
      u_t_cost
      u_m_cost
      u_parallelism
      pwd s_pwd_len
      salt s_salt_len
      hash s_hash_len
      encoded s_encoded_len
      typ
  in
  match res with
  | Argon2_ErrorCodes.ARGON2_OK ->
    let hash = string_from_ptr (from_voidp char hash) hash_len in
    let encoded = string_from_ptr encoded encoded_len in
    Result.Ok (hash, encoded)
  | _ as e -> Result.Error e

let verify ~encoded ~pwd ~typ =
  let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
  match argon2_verify encoded pwd s_pwd_len typ with
  | Argon2_ErrorCodes.ARGON2_OK -> Result.Ok true
  | e -> Result.Error e

module I = struct
  let hash_raw = hash_raw argon2i_hash_raw

  let hash_encoded = hash_encoded argon2i_hash_encoded

  let verify ~encoded ~pwd =
    let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
    match argon2i_verify encoded pwd s_pwd_len with
    | Argon2_ErrorCodes.ARGON2_OK -> Result.Ok true
    | e -> Result.Error e
end

module D = struct
  let hash_raw = hash_raw argon2d_hash_raw

  let hash_encoded = hash_encoded argon2d_hash_encoded

  let verify ~encoded ~pwd =
    let s_pwd_len = Unsigned.Size_t.of_int @@ String.length pwd in
    match argon2d_verify encoded pwd s_pwd_len with
    | Argon2_ErrorCodes.ARGON2_OK -> Result.Ok true
    | e -> Result.Error e
end
