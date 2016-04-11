(** Ocaml bindings to Argon2. *)

module Argon2_type: sig
  type t =
    | Argon2_d
    | Argon2_i
end

module Argon2_version: sig
  type t =
    | ARGON2_VERSION_10
    | ARGON2_VERSION_13
    | ARGON2_VERSION_NUMBER
end

module Argon2_ErrorCodes: sig
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
    | ARGON2_THREAD_FAIL
    | ARGON2_DECODING_LENGTH_FAIL
    | ARGON2_VERIFY_MISMATCH
    | Other of int

  (** Get the associated error message for given error code. *)
  val message :
    t ->
    string
end

type hash = string
type encoded = string

module I : sig

  (** Hashes a password with Argon2i, producing a raw hash. *)
  val hash_raw :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    (hash, Argon2_ErrorCodes.t) Result.result

  (** Hashes a password with Argon2i, producing an encoded hash. *)
  val hash_encoded :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    encoded_len:int ->
    (encoded, Argon2_ErrorCodes.t) Result.result

  (** Verifies a password against an encoded string. *)
  val verify :
    encoded:encoded ->
    pwd:string ->
    (bool, Argon2_ErrorCodes.t) Result.result
end

module D : sig

  (** Hashes a password with Argon2d, producing a raw hash. *)
  val hash_raw :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    (hash, Argon2_ErrorCodes.t) Result.result

  (** Hashes a password with Argon2d, producing an encoded hash. *)
  val hash_encoded :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    encoded_len:int ->
    (encoded, Argon2_ErrorCodes.t) Result.result

  (** Verifies a password against an encoded string. *)
  val verify :
    encoded:encoded ->
    pwd:string ->
    (bool, Argon2_ErrorCodes.t) Result.result
end

(** Generic function underlying the above ones. *)
val hash :
  t_cost:int ->
  m_cost:int ->
  parallelism:int ->
  pwd:string ->
  salt:string ->
  typ:Argon2_type.t ->
  hash_len:int ->               (* TODO: must be int option *)
  encoded_len:int ->            (* TODO: must be int option *)
  version:Argon2_version.t ->
  ((hash * encoded), Argon2_ErrorCodes.t) Result.result

(** Verifies a password against an encoded string. *)
val verify :
  encoded:encoded ->
  pwd:string ->
  typ:Argon2_type.t ->
  (bool, Argon2_ErrorCodes.t) Result.result

(** Returns the encoded hash length for the given input parameters. *)
val encoded_len :
  t_cost:int ->
  m_cost:int ->
  parallelism:int ->
  salt_len:int ->
  hash_len:int ->
  int
