namespace OAuth.Types

open System.Security.Cryptography.X509Certificates

type ParameterKeyValue = KeyValue of string * string

type HashAlgorithm = HMACSHA1 | PLAINTEXT | RSASHA1

type HttpMethod = GET | POST

type Secret = 
    SecretKey of string
    | SecretKeyList of string list
    | Certificate of X509Certificate2

type ConsumerInfo = { consumerKey : string; consumerSecret : Secret ; hash : HashAlgorithm option }
type RequestInfo = { requestToken : string; requestSecret : Secret }
type AccessInfo = { accessToken : string; accessSecret : Secret }

type UseFor = ForRequestToken of ConsumerInfo
            | ForAccessToken of ConsumerInfo * RequestInfo * string
            | ForWebService of ConsumerInfo * AccessInfo * ParameterKeyValue list

type HttpRequirement = Requirement of System.Text.Encoding * string * HttpMethod