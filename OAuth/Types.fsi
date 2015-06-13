namespace OAuth.Types

open System.Security.Cryptography.X509Certificates

/// <summary>A key-value parameter.</summary>
type ParameterKeyValue = | KeyValue of string * string

/// <summary>A hash algorithm which is HMAC-SHA1, PLAINTEXT or RSA-SHA1.</summary>
type HashAlgorithm =
    | HMACSHA1
    | PLAINTEXT
    | RSASHA1

/// <summary>An HTTP method, GET or POST.</summary>
type HttpMethod =
    | GET
    | POST

type Secret = 
    SecretKey of string
    | SecretKeyList of string list
    | Certificate of X509Certificate2

/// <summary>A consumer key and a consumer secret.
/// These key and secret are used in getting every tokens and using OAuth API.</summary>
type ConsumerInfo =
    { consumerKey : string;
    consumerSecret : Secret;
    hash : HashAlgorithm option }

/// <summary>A request token and a request secret.
/// These key and secret are used in getting the access token.</summary>
type RequestInfo =
    { requestToken : string;
    requestSecret : Secret }

/// <summary>An access token and an access secret.
/// These key and secret are used in using OAuth API.</summary>
type AccessInfo =
    { accessToken : string;
    accessSecret : Secret }

/// <summary>A pack of parameter which uses in our APIs.</summary>
type UseFor =
    | ForRequestToken of ConsumerInfo
    | ForAccessToken of ConsumerInfo * RequestInfo * string
    | ForWebService of ConsumerInfo * AccessInfo * ParameterKeyValue list

/// <summary>A pack of parameter for HTTP actions.</summary>
type HttpRequirement = | Requirement of System.Text.Encoding * string * HttpMethod