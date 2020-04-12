(** Ocaml bindings to Argon2. *)

module ErrorCodes : sig
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

  val message : t -> string
  (** Get the associated error message for given error code. *)
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
  (** Hashes a password with Argon2i, producing a raw hash. *)

  val hash_encoded :
    t_cost:int ->
    m_cost:int ->
    parallelism:int ->
    pwd:string ->
    salt:string ->
    hash_len:int ->
    encoded_len:int ->
    (encoded, ErrorCodes.t) Result.result
  (** Hashes a password with Argon2i, producing an encoded hash. *)

  val verify :
    encoded:encoded -> pwd:string -> (bool, ErrorCodes.t) Result.result
  (** Verifies a password against an encoded string. *)

  val hash_to_string : hash -> string
  (** Converts a raw hash value to a string. *)

  val encoded_to_string : encoded -> string
  (** Converts an encoded hash to a string. *)
end

(** Bindings to Argon2i. *)
module I : HashFunctions

(** Bindings to Argon2d. *)
module D : HashFunctions

type hash = string

type encoded = string

type kind = D | I

type version =
  | VERSION_10
  | VERSION_13
  | VERSION_NUMBER  (** Currently an alias for [VERSION_13] *)

val hash :
  t_cost:int ->
  m_cost:int ->
  parallelism:int ->
  pwd:string ->
  salt:string ->
  kind:kind ->
  hash_len:int ->
  (* TODO: must be int option *)
  encoded_len:int ->
  (* TODO: must be int option *)
  version:version ->
  (hash * encoded, ErrorCodes.t) Result.result
(** Generic function underlying the above ones. *)

val verify :
  encoded:encoded ->
  pwd:string ->
  kind:kind ->
  (bool, ErrorCodes.t) Result.result
(** Verifies a password against an encoded string. *)

val encoded_len :
  t_cost:int ->
  m_cost:int ->
  parallelism:int ->
  salt_len:int ->
  hash_len:int ->
  int
(** Returns the encoded hash length for the given input parameters. *)
