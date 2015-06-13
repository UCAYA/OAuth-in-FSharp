namespace OAuth.Core

module Authentication =
    open System
    open System.Text
    open OAuth.Utilities
    open OAuth.Types
    open OAuth.Core.Base
    open System.Security.Cryptography;
        
        
    [<CompiledName("GenerateNonce")>]
    let inline generateNonce () = DateTime.Now.Ticks.ToString ()

    [<CompiledName("GenerateTimeStamp")>]
    let generateTimeStamp () =
        ((DateTime.UtcNow - DateTime (1970, 1, 1, 0, 0, 0, 0)).TotalSeconds
         |> Convert.ToInt64).ToString ()

    
    [<CompiledName("GenerateSignature")>]
    let generateSignature (encoder : string -> string) (algorithmType:OAuth.Types.HashAlgorithm ) (secret:Secret) (baseString : string) =

        match algorithmType with
            | PLAINTEXT -> baseString |> encoder
            | _ ->  
                    let signHMACSHA1 (bytes:byte array) =
                        let keysParam = match secret with
                                            | SecretKeyList listOfKeys -> listOfKeys 
                                            | _ -> [ "" ]
                                        |> concatSecretKeys |> Encoding.ASCII.GetBytes

                        use algorithm = new System.Security.Cryptography.HMACSHA1 (keysParam)
                        algorithm.ComputeHash(bytes)

                    let signRSASHA1 (bytes:byte array) =
                        let certificate = match secret with
                                                   | Certificate c -> c
                                                   | _ -> raise(Exception( "expect a certificate secret"))

                        let crypto = certificate.PrivateKey :?> RSACryptoServiceProvider
                        use sha1 = new SHA1Managed()

                        let signHash bytes = crypto.SignHash(bytes, CryptoConfig.MapNameToOID("SHA1"))
                        sha1.ComputeHash(bytes)
                          |> signHash

                    let computeSignature = 
                        match algorithmType with
                        | HMACSHA1 -> signHMACSHA1
                        | RSASHA1 -> signRSASHA1
                        | _ -> raise(Exception("Hash not supported at this point"))
                            
                    baseString
                        |> Encoding.ASCII.GetBytes
                        |> computeSignature
                        |> Convert.ToBase64String
                        |> encoder


    [<CompiledName("GenerateSignatureWithHMACSHA1")>]
    let inline generateSignatureWithHMACSHA1 encoder secretKeys baseString = generateSignature encoder OAuth.Types.HMACSHA1 secretKeys baseString
     
    [<CompiledName("GenerateSignatureWithPLAINTEXT")>]
    let inline generateSignatureWithPLAINTEXT encoder secretKeys baseString = generateSignature encoder PLAINTEXT secretKeys baseString
    
    [<CompiledName("GenerateSignatureWithRSASHA1")>]
    let inline generateSignatureWithRSASHA1 encoder secretKeys baseString = generateSignature encoder RSASHA1 secretKeys baseString

    [<CompiledName("AssembleBaseString")>]
    let assembleBaseString requirement keyValues =
        let (Requirement (encoding, targetUrl, httpMethod)) = requirement
        let encoder = urlEncode encoding
        let sanitizedUrl = targetUrl |> encoder
        let sorKeyValues = List.sortBy (fun (KeyValue (key, value)) -> key)
        let meth = getHttpMethodString httpMethod
        let arrangedParams = keyValues
                            |> sorKeyValues
                            |> toParameter encoder
                            |> encoder
        meth + "&" + sanitizedUrl + "&" + arrangedParams

    [<CompiledName("MakeStringPairForGenerateHeader")>]
    let makeStringPairForGenerateHeader useFor =
        let consumerInfo = match useFor with
                            | ForRequestToken (consumerInfo) -> consumerInfo
                            | ForAccessToken (consumerInfo, _, _) -> consumerInfo
                            | ForWebService (consumerInfo, _, _) -> consumerInfo
        let hash = match consumerInfo.hash with
                    | Some HashAlgorithm.HMACSHA1 -> "HMAC-SHA1"
                    | Some HashAlgorithm.RSASHA1 -> "RSA-SHA1"
                    | _ -> raise(Exception("Hash not supported"))

        let keyValues = [("oauth_nonce", generateNonce ());
                        ("oauth_signature_method", hash);
                        ("oauth_timestamp", generateTimeStamp ())]

        match useFor with
        | ForRequestToken (consumerInfo) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::keyValues
        | ForAccessToken (consumerInfo, requestInfo, pinCode) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::
            ("oauth_token", requestInfo.requestToken)::
            ("oauth_verifier", pinCode)::
            keyValues
        | ForWebService (consumerInfo, accessInfo, _) ->
            ("oauth_consumer_key", consumerInfo.consumerKey)::
            ("oauth_token", accessInfo.accessToken)::
            keyValues


    let concatSecrets = function
        | (SecretKey k1, SecretKey k2) -> SecretKeyList [ k1; k2 ]
        | (SecretKeyList list1, SecretKey k2) -> SecretKeyList (list1 @ [k2])
        | (SecretKey k1, SecretKeyList list2) -> SecretKeyList (k1::list2)
        | (SecretKeyList list1, SecretKeyList list2) -> SecretKeyList (list1 @ list2)
        | (Certificate cert1, _) -> Certificate cert1
        | _ -> raise(Exception("Concat types not supported"))

    
    let oauthKeyValues requirement useFor =
        let (Requirement (encoding, _, _)) = requirement
        let encoder = urlEncode encoding
        let keyValuePair = useFor
                        |> makeStringPairForGenerateHeader
                        |> List.map (fun (key, value) -> (key, encoder value))
        let baseString = match useFor with
                            | ForWebService (_, _, kvs) -> kvs
                            | _ -> []
                            |> List.append (toKeyValue keyValuePair)
                            |> assembleBaseString requirement
        let (secret, hash) =
            match useFor with
            | ForRequestToken (consumerInfo) -> (consumerInfo.consumerSecret, consumerInfo.hash)
            | ForAccessToken (consumerInfo, requestInfo, pinCode) -> (concatSecrets (consumerInfo.consumerSecret, requestInfo.requestSecret), consumerInfo.hash)
            | ForWebService (consumerInfo, accessInfo, _) -> (concatSecrets (consumerInfo.consumerSecret, accessInfo.accessSecret), consumerInfo.hash)

        let selectedHash = match hash with
                              | Some h -> h
                              | None -> HashAlgorithm.HMACSHA1

        let signature = generateSignature encoder selectedHash secret baseString
     
        ("oauth_signature", signature) :: keyValuePair
        |> toKeyValue

    [<CompiledName("GenerateAuthorizationHeader")>]
    let generateAuthorizationHeader requirement useFor =
        let oParamsWithSignature = oauthKeyValues requirement useFor
                                    |> headerParameter
        "OAuth " + oParamsWithSignature

    [<CompiledName("GenerateAuthorizationHeaderForRequestToken")>]
    let generateAuthorizationHeaderForRequestToken requirement consumerInfo =
        generateAuthorizationHeader requirement (ForRequestToken consumerInfo)

    [<CompiledName("GenerateAuthorizationHeaderForAccessToken")>]
    let generateAuthorizationHeaderForAccessToken requirement consumerInfo requestInfo pinCode =
        generateAuthorizationHeader requirement (ForAccessToken (consumerInfo, requestInfo, pinCode))

    [<CompiledName("GenerateAuthorizationHeaderForWebService")>]
    let generateAuthorizationHeaderForWebService requirement consumerInfo accessInfo param =
        generateAuthorizationHeader requirement (ForWebService (consumerInfo, accessInfo, param))

    [<CompiledName("GenerateAuthorizationUrlParameterForWebService")>]
    let generateAuthorizationUrlParameterForWebService requirement consumerInfo accessInfo param =
        let (Requirement (_, url, _)) = requirement

        let oParamsWithSignature = oauthKeyValues requirement (ForWebService (consumerInfo, accessInfo, param))
                                    |> urlParameter
        
        if url.Contains("?") then
            url + "&" + oParamsWithSignature
        else
            url + "?" + oParamsWithSignature
