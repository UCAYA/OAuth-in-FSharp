namespace OAuth

module API =
    open System.Text
    open System.Collections.Specialized
    open OAuth.Types
    open OAuth.Utilities
    open OAuth.Core.Base
    open OAuth.Core.Authentication
    open OAuth.ExtendedWebClient
    open Microsoft.FSharp.Control

    [<CompiledName("AsyncAPIBase")>]
    let asyncAPIBase requirement header parameter =
        async {
            let (Requirement (encoding, targetUrl, httpMethod)) = requirement
            let wc = new System.Net.WebClient ()
            let url = System.Uri (targetUrl)
            let meth = httpMethod
            let! result =
                wc.Headers.Add ("Authorization", header)
                let rec setPostParameter keyValue (param : NameValueCollection) =
                    match keyValue with
                    | kv::kvs ->
                        let encoder = urlEncode encoding
                        let (KeyValue (key, value)) = kv
                        param.Add (encoder key, encoder value)
                        setPostParameter kvs param
                    | _ -> param
                let param = setPostParameter parameter (NameValueCollection())
                wc.QueryString <- param
                if httpMethod.Equals("GET") 
                    then wc.AsyncDownloadString url
                    else wc.AsyncUploadString url meth ""
            return result
        } |> Async.RunSynchronously

    [<CompiledName("GetRequestToken")>]
    let getRequestToken requirement consumerInfo parameter =
        let header = generateAuthorizationHeaderForRequestToken requirement consumerInfo
        asyncAPIBase requirement header parameter

    [<CompiledName("GetAccessToken")>]
    let getAccessToken requirement consumerInfo requestInfo pinCode parameter =
        let header = generateAuthorizationHeaderForAccessToken requirement consumerInfo requestInfo pinCode
        asyncAPIBase requirement header parameter

    [<CompiledName("UseWebService")>]
    let useWebService requirement consumerInfo accessInfo parameter =
        let header = generateAuthorizationHeaderForWebService requirement consumerInfo accessInfo parameter
        asyncAPIBase requirement header parameter

    [<CompiledName("SignUrl")>]
    let signUrl requirement consumerInfo accessInfo parameter =
        generateAuthorizationUrlParameterForWebService requirement consumerInfo accessInfo parameter
