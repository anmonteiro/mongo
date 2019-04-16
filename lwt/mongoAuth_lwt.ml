(* TODO: each auth function should return a result of (unit, string) *)
open Lwt.Infix

type auth =
  [ `NoAuth
  | `Plain of string * string
  | `MongoCR of string * string
  | `SCRAM_SHA_1 of string * string
  | `SCRAM_SHA_256 of string * string
  ]

let parse_payload payload_str =
  let parts = String.split_on_char ',' payload_str in
  List.fold_left (fun acc part ->
      match String.split_on_char '=' part with
      | k::v::xs -> (k,v ^ (String.make (List.length xs) '='))::acc
      | _ -> failwith (Printf.sprintf "split should have at least 2 parts: %s" part)
    ) [] parts

let hi data salt iterations mode dk_len =
  Pbkdf.pbkdf2
    ~prf:mode
    ~salt
    ~password:(Cstruct.of_string data)
    ~count:iterations
    ~dk_len

let hmac key text =
  Cstruct.of_string text
  |> Nocrypto.Hash.SHA1.hmac ~key
  |> Cstruct.to_string

let h mode text =
  let module H = (val Nocrypto.Hash.module_of mode) in
  Cstruct.of_string text
  |> H.digest

let xor a b =
  Nocrypto.Uncommon.Cs.xor (Cstruct.of_string a) (Cstruct.of_string b)
  |> Nocrypto.Base64.encode
  |> Cstruct.to_string

let create_query bson =
  MongoRequest.create_query ("admin","$cmd") (MongoUtils.cur_timestamp (), 0l, 0l, 1l)
    (bson, Bson.empty)

(* https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst#id3 *)
let auth_plain channel_pool username password =
  let bson = Bson.empty
             |> Bson.add_element "saslStart" (Bson.create_int32 1l)
             |> Bson.add_element "mechanism" (Bson.create_string "PLAIN")
             |> Bson.add_element "payload" (Bson.create_user_binary (Printf.sprintf "\x00%s\x00%s" username password))
             |> Bson.add_element "autoAuthorize" (Bson.create_int32 1l)

  in
  let req = create_query bson in
  MongoSend_lwt.send_with_reply channel_pool req >>= fun _r ->
  Lwt.return_unit

(* https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst#conversation *)
let auth_mongo_cr channel_pool username password =
  let bson = Bson.empty
             |> Bson.add_element "getNonce" (Bson.create_int32 1l)
  in
  let req = create_query bson in
  MongoSend_lwt.send_with_reply channel_pool req >>= fun r ->
  let nonce = MongoReply.get_document_list r |> List.hd |> Bson.get_element "nonce" |> Bson.get_string in
  let password_digest = Printf.sprintf "%s:mongo:%s" username password |> Digest.string |> Digest.to_hex in
  let key = Printf.sprintf "%s%s%s" nonce username password_digest  |> Digest.string |> Digest.to_hex in
  let auth_bson = Bson.empty
                  |> Bson.add_element "authenticate" (Bson.create_int32 1l)
                  |> Bson.add_element "nonce" (Bson.create_string nonce)
                  |> Bson.add_element "user" (Bson.create_string username)
                  |> Bson.add_element "key" (Bson.create_string key)
  in
  let auth_req = create_query auth_bson in
  MongoSend_lwt.send_with_reply channel_pool auth_req >>= fun _r ->
  Lwt.return_unit

(* TODO: use nocrypto.lwt *)
(* https://github.com/mongodb/specifications/blob/master/source/auth/auth.rst#scram-sha-1 *)
(**
 * The client Proof:
 * AuthMessage     := client-first-message-bare + "," + server-first-message + "," + client-final-message-without-proof
 * SaltedPassword  := Hi(Normalize(password), salt, i)
 * ClientKey       := HMAC(SaltedPassword, "Client Key")
 * ServerKey       := HMAC(SaltedPassword, "Server Key")
 * StoredKey       := H(ClientKey)
 * ClientSignature := HMAC(StoredKey, AuthMessage)
 * ClientProof     := ClientKey XOR ClientSignature
 * ServerSignature := HMAC(ServerKey, AuthMessage)
*)
let auth_scram channel_pool mode username password =
  (* TODO: make secure, look into NoCrypto.RNG *)
  let nonce = "foo" in
  let first_bare = Printf.sprintf "n=%s,r=%s" username nonce in
  let (mechanism, dk_len) = match mode with
    | `SHA1 -> "SCRAM-SHA-1", 20
    | `SHA256 -> "SCRAM-SHA-256", 32
    | #Nocrypto.Hash.hash -> failwith "Not supported"
  in
  let bson = Bson.empty
             |> Bson.add_element "saslStart" (Bson.create_int32 1l)
             |> Bson.add_element "mechanism" (Bson.create_string mechanism)
             |> Bson.add_element "payload" (Bson.create_user_binary (Printf.sprintf "n,,%s" first_bare))
             |> Bson.add_element "autoAuthorize" (Bson.create_int32 1l)
  in
  let req = create_query bson in
  MongoSend_lwt.send_with_reply channel_pool req >>= fun r ->
  let bson_res = MongoReply.get_document_list r |> List.hd in
  let conversation_id = bson_res |> Bson.get_element "conversationId" in
  let res_payload = bson_res |> Bson.get_element "payload" |> Bson.get_generic_binary in
  let parsed_payload = parse_payload res_payload in
  let iterations = int_of_string (List.assoc "i" parsed_payload) in
  let salt = List.assoc "s" parsed_payload in
  let rnonce = List.assoc "r" parsed_payload in
  let without_proof = Printf.sprintf "c=biws,r=%s" rnonce in
  let password_digest = match mode with
    | `SHA1 -> Printf.sprintf "%s:mongo:%s" username password |> Digest.string |> Digest.to_hex
    | `SHA256 -> password
    | #Nocrypto.Hash.hash -> failwith "Not supported"
  in
  let salt = match Nocrypto.Base64.decode (Cstruct.of_string salt) with
    | None -> assert false
    | Some x -> x
  in
  let salted_password = hi password_digest salt iterations mode (Int32.of_int dk_len) in
  let client_key = hmac salted_password "Client Key" in
  let stored_key = h mode client_key in
  let auth_message = String.concat "," [first_bare; res_payload; without_proof]
  in
  let client_signature = hmac stored_key auth_message in
  let client_proof = Printf.sprintf "p=%s" (xor client_key client_signature) in
  let client_final = String.concat "," [without_proof; client_proof] in
  let bson = Bson.empty
             |> Bson.add_element "saslContinue" (Bson.create_int32 1l)
             |> Bson.add_element "conversationId" conversation_id
             |> Bson.add_element "payload" (Bson.create_user_binary client_final)
  in
  let cmd = MongoRequest.create_query ("admin","$cmd") (MongoUtils.cur_timestamp (), 0l, 0l, 1l)
      (bson, Bson.empty) in
  MongoSend_lwt.send_with_reply channel_pool cmd >>= fun r ->
  let bson_res = MongoReply.get_document_list r |> List.hd in
  let conversation_id = bson_res |> Bson.get_element "conversationId" in
  let final_bson = Bson.empty
                   |> Bson.add_element "saslContinue" (Bson.create_int32 1l)
                   |> Bson.add_element "conversationId" conversation_id
                   |> Bson.add_element "payload" (Bson.create_user_binary "")
  in
  let cmd = MongoRequest.create_query ("admin","$cmd") (MongoUtils.cur_timestamp (), 0l, 0l, 1l)
      (final_bson, Bson.empty) in
  MongoSend_lwt.send_with_reply channel_pool cmd >>= fun _r ->
  Lwt.return_unit

let authenticate auth channel_pool =
  match auth with
  | `NoAuth -> Lwt.return_unit
  | `Plain (username, password) -> auth_plain channel_pool username password
  | `MongoCR (username, password) -> auth_mongo_cr channel_pool username password
  | `SCRAM_SHA_1 (username, password) -> auth_scram channel_pool `SHA1 username password
  | `SCRAM_SHA_256 (username, password) -> auth_scram channel_pool `SHA256 username password
