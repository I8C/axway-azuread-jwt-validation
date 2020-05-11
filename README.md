# Introduction

This project contains logic used in the Axway API Gateway to allow for the validation of JWT Tokens issued by Azure AD.


# Getting Started

To use the policy, import the policy xml file in an existing Axway API Gateway project using the File > Import > Import configuration fragment option.
The policy will be created under Policies > _common > requestPolicy > SecurityTypes > ValidateAzureADJwtToken.
additionally, a cache will be added to the api gateway caches called kps_security_validateazureadjwttoken. The settings of this cache can be modified using your preference.


# Using the policy

The policy can be plugged into an existing flow, or it can be added as an inbound security policy.
The policy will return a "true" value if it able to validate the JWT Token in the request, and it will return a "false" value if encounters an issue validating the Token. If the policy is able to find a JWT token, but is unable to validate it, an additional attribute called "error.code" is set to "accessdenied" indicating that an invalid token was provided.

# Implementation details
The policy assumes that a http request is received which contains an auhorization header as follows:

```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyIsImtpZCI6IjdfWnVmMXR2a3dMeFlhSFMzcTZsVWpVWUlHdyJ9.eyJhdWQiOiJiMTRhNzUwNS05NmU5LTQ5MjctOTFlOC0wNjAxZDBmYzljYWEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYTE1ZDY5Mi1lOWM3LTQ0NjAtYTc0My0yOWYyOTU2ZmQ0MjkvIiwiaWF0IjoxNTM2Mjc1MTI0LCJuYmYiOjE1MzYyNzUxMjQsImV4cCI6MTUzNjI3OTAyNCwiYWlvIjoiQVhRQWkvOElBQUFBcXhzdUIrUjREMnJGUXFPRVRPNFlkWGJMRDlrWjh4ZlhhZGVBTTBRMk5rTlQ1aXpmZzN1d2JXU1hodVNTajZVVDVoeTJENldxQXBCNWpLQTZaZ1o5ay9TVTI3dVY5Y2V0WGZMT3RwTnR0Z2s1RGNCdGsrTExzdHovSmcrZ1lSbXY5YlVVNFhscGhUYzZDODZKbWoxRkN3PT0iLCJhbXIiOlsicnNhIl0sImVtYWlsIjoiYWJlbGlAbWljcm9zb2Z0LmNvbSIsImZhbWlseV9uYW1lIjoiTGluY29sbiIsImdpdmVuX25hbWUiOiJBYmUiLCJpZHAiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83MmY5ODhiZi04NmYxLTQxYWYtOTFhYi0yZDdjZDAxMWRiNDcvIiwiaXBhZGRyIjoiMTMxLjEwNy4yMjIuMjIiLCJuYW1lIjoiYWJlbGkiLCJub25jZSI6IjEyMzUyMyIsIm9pZCI6IjA1ODMzYjZiLWFhMWQtNDJkNC05ZWMwLTFiMmJiOTE5NDQzOCIsInJoIjoiSSIsInN1YiI6IjVfSjlyU3NzOC1qdnRfSWN1NnVlUk5MOHhYYjhMRjRGc2dfS29vQzJSSlEiLCJ0aWQiOiJmYTE1ZDY5Mi1lOWM3LTQ0NjAtYTc0My0yOWYyOTU2ZmQ0MjkiLCJ1bmlxdWVfbmFtZSI6IkFiZUxpQG1pY3Jvc29mdC5jb20iLCJ1dGkiOiJMeGVfNDZHcVRrT3BHU2ZUbG40RUFBIiwidmVyIjoiMS4wIn0=.UJQrCA6qn2bXq57qzGX_-D3HcPHqBMOKDPx4su1yKRLNErVD8xkxJLNLVRdASHqEcpyDctbdHccu6DPpkq5f0ibcaQFhejQNcABidJCTz0Bb2AbdUCTqAzdt9pdgQvMBnVH1xk3SCM6d4BbT4BkLLj10ZLasX7vRknaSjE_C5DI7Fg4WrZPwOhII1dB0HEZ_qpNaYXEiy-o94UJ94zCr07GgrqMsfYQqFR7kn-mn68AjvLcgwSfZvyR_yIK75S_K37vC3QryQ7cNoafDe9upql_6pB2ybMVlgWPs_DmbJ8g0om-sPlwyn74Cc1tW3ze-Xptw_2uVdPgWyqfuWAfq6Q
```

Which decodes into a jwt token as follows:
```
{
  "typ": "JWT",
  "alg": "RS256",
  "x5t": "7_Zuf1tvkwLxYaHS3q6lUjUYIGw",
  "kid": "7_Zuf1tvkwLxYaHS3q6lUjUYIGw"
}.{
  "aud": "b14a7505-96e9-4927-91e8-0601d0fc9caa",
  "iss": "https://sts.windows.net/fa15d692-e9c7-4460-a743-29f2956fd429/",
  "iat": 1536275124,
  "nbf": 1536275124,
  "exp": 1536279024,
  "aio": "AXQAi/8IAAAAqxsuB+R4D2rFQqOETO4YdXbLD9kZ8xfXadeAM0Q2NkNT5izfg3uwbWSXhuSSj6UT5hy2D6WqApB5jKA6ZgZ9k/SU27uV9cetXfLOtpNttgk5DcBtk+LLstz/Jg+gYRmv9bUU4XlphTc6C86Jmj1FCw==",
  "amr": [
    "rsa"
  ],
  "email": "abeli@microsoft.com",
  "family_name": "Lincoln",
  "given_name": "Abe",
  "idp": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
  "ipaddr": "131.107.222.22",
  "name": "abeli",
  "nonce": "123523",
  "oid": "05833b6b-aa1d-42d4-9ec0-1b2bb9194438",
  "rh": "I",
  "sub": "5_J9rSss8-jvt_Icu6ueRNL8xXb8LF4Fsg_KooC2RJQ",
  "tid": "fa15d692-e9c7-4460-a743-29f2956fd429",
  "unique_name": "AbeLi@microsoft.com",
  "uti": "Lxe_46GqTkOpGSfTln4EAA",
  "ver": "1.0"
}.[Signature]
```

In order to validate this token, we will be using the JWT Validate filter available in the API Gateway. This filter will require us to provide the JWT Token (request.jwt), as well as the key used to validate the token (request.jwk) as follows:

![Jwt Verify](./Images/JWTVerify.png)

In order to extract the JWT token for this filter, we just need to extract the content of the Authorization header from the incoming request and remove the “Bearer” text at the beginning of this header.
This can be done as follows:

![extract JWT](./Images/extractJWT.png)


As shown in the picture, we first use the “retrieve from HTTP header” filter to extract the authorization header, then we validate that it is not an empty string using the “compare attribute” filter, and finally we remove the Bearer text at the start using a simple String replace. The output of this filter can be directly provided to the above “JWT validate” filter.
Since we now have the JWT token, we just need to fetch the JWK required to validate it. Azure AD has [a public api available](https://login.microsoftonline.com/common/.well-known/openid-configuration) which allows anyone to look up the correct certificate in order to validate JWT tokens generated by them. 
The API returns the following json:

```
{
	"token_endpoint": "https://login.microsoftonline.com/common/oauth2/token",
	"token_endpoint_auth_methods_supported": [
		"client_secret_post",
		"private_key_jwt",
		"client_secret_basic"
	],
	"jwks_uri": "https://login.microsoftonline.com/common/discovery/keys",
	"response_modes_supported": [
		"query",
		"fragment",
		"form_post"
	],
	"subject_types_supported": [
		"pairwise"
	],
	"id_token_signing_alg_values_supported": [
		"RS256"
	],
	"response_types_supported": [
		"code",
		"id_token",
		"code id_token",
		"token id_token",
		"token"
	],
	"scopes_supported": [
		"openid"
	],
	"issuer": "https://sts.windows.net/{tenantid}/",
	"microsoft_multi_refresh_token": true,
	"authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/authorize",
	"http_logout_supported": true,
	"frontchannel_logout_supported": true,
	"end_session_endpoint": "https://login.microsoftonline.com/common/oauth2/logout",
	"claims_supported": [
		"sub",
		"iss",
		"cloud_instance_name",
		"cloud_instance_host_name",
		"cloud_graph_host_name",
		"msgraph_host",
		"aud",
		"exp",
		"iat",
		"auth_time",
		"acr",
		"amr",
		"nonce",
		"email",
		"given_name",
		"family_name",
		"nickname"
	],
	"check_session_iframe": "https://login.microsoftonline.com/common/oauth2/checksession",
	"userinfo_endpoint": "https://login.microsoftonline.com/common/openid/userinfo",
	"tenant_region_scope": null,
	"cloud_instance_name": "microsoftonline.com",
	"cloud_graph_host_name": "graph.windows.net",
	"msgraph_host": "graph.microsoft.com",
	"rbac_url": "https://pas.windows.net"
}
```

In this JSON the only field we’re interested in is the “jwks_uri” field which will tell us where we can fetch the current validation keys. If we call this url we will receive a json as follows:

```
{
	"keys": [
		{
			"kty": "RSA",
			"use": "sig",
			"kid": "CtTuhMJmD5M7DLdzD2v2x3QKSRY",
			"x5t": "CtTuhMJmD5M7DLdzD2v2x3QKSRY",
			"n": "18uZ3P3IgOySlnOsxeIN5WUKzvlm6evPDMFbmXPtTF0GMe7tD2JPfai2UGn74s7AFwqxWO5DQZRu6VfQUux8uMR4J7nxm1Kf__7pVEVJJyDuL5a8PARRYQtH68w-0IZxcFOkgsSdhtIzPQ2jj4mmRzWXIwh8M_8pJ6qiOjvjF9bhEq0CC_f27BnljPaFn8hxY69pCoxenWWqFcsUhFZvCMthhRubAbBilDr74KaXS5xCgySBhPzwekD9_NdCUuCsdqavd4T-VWnbplbB8YsC-R00FptBFKuTyT9zoGZjWZilQVmj7v3k8jXqYB2nWKgTAfwjmiyKz78FHkaE-nCIDw",
			"e": "AQAB",
			"x5c": [				"MIIDBTCCAe2gAwIBAgIQXVogj9BAf49IpuOSIvztNDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDMxNzAwMDAwMFoXDTI1MDMxNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANfLmdz9yIDskpZzrMXiDeVlCs75ZunrzwzBW5lz7UxdBjHu7Q9iT32otlBp++LOwBcKsVjuQ0GUbulX0FLsfLjEeCe58ZtSn//+6VRFSScg7i+WvDwEUWELR+vMPtCGcXBTpILEnYbSMz0No4+Jpkc1lyMIfDP/KSeqojo74xfW4RKtAgv39uwZ5Yz2hZ/IcWOvaQqMXp1lqhXLFIRWbwjLYYUbmwGwYpQ6++Cml0ucQoMkgYT88HpA/fzXQlLgrHamr3eE/lVp26ZWwfGLAvkdNBabQRSrk8k/c6BmY1mYpUFZo+795PI16mAdp1ioEwH8I5osis+/BR5GhPpwiA8CAwEAAaMhMB8wHQYDVR0OBBYEFF8MDGklOGhGNVJvsHHRCaqtzexcMA0GCSqGSIb3DQEBCwUAA4IBAQCKkegw/mdpCVl1lOpgU4G9RT+1gtcPqZK9kpimuDggSJju6KUQlOCi5/lIH5DCzpjFdmG17TjWVBNve5kowmrhLzovY0Ykk7+6hYTBK8dNNSmd4SK7zY++0aDIuOzHP2Cur+kgFC0gez50tPzotLDtMmp40gknXuzltwJfezNSw3gLgljDsGGcDIXK3qLSYh44qSuRGwulcN2EJUZBI9tIxoODpaWHIN8+z2uZvf8JBYFjA3+n9FRQn51X16CTcjq4QRTbNVpgVuQuyaYnEtx0ZnDvguB3RjGSPIXTRBkLl2x7e8/6uAZ6tchw8rhcOtPsFgJuoJokGjvcUSR/6Eqd"
			]
		},
		{
			"kty": "RSA",
			"use": "sig",
			"kid": "SsZsBNhZcF3Q9S4trpQBTByNRRI",
			"x5t": "SsZsBNhZcF3Q9S4trpQBTByNRRI",
			"n": "uHPewhg4WC3eLVPkEFlj7RDtaKYWXCI5G-LPVzsMKOuIu7qQQbeytIA6P6HT9_iIRt8zNQvuw4P9vbNjgUCpI6vfZGsjk3XuCVoB_bAIhvuBcQh9ePH2yEwS5reR-NrG1PsqzobnZZuigKCoDmuOb_UDx1DiVyNCbMBlEG7UzTQwLf5NP6HaRHx027URJeZvPAWY7zjHlSOuKoS_d1yUveaBFIgZqPWLCg44ck4gvik45HsNVWT9zYfT74dvUSSrMSR-SHFT7Hy1XjbVXpHJHNNAXpPoGoWXTuc0BxMsB4cqjfJqoftFGOG4x32vEzakArLPxAKwGvkvu0jToAyvSQ",
			"e": "AQAB",
			"x5c": [				"MIIDBTCCAe2gAwIBAgIQWHw7h/Ysh6hPcXpnrJ0N8DANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDQyNzAwMDAwMFoXDTI1MDQyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALhz3sIYOFgt3i1T5BBZY+0Q7WimFlwiORviz1c7DCjriLu6kEG3srSAOj+h0/f4iEbfMzUL7sOD/b2zY4FAqSOr32RrI5N17glaAf2wCIb7gXEIfXjx9shMEua3kfjaxtT7Ks6G52WbooCgqA5rjm/1A8dQ4lcjQmzAZRBu1M00MC3+TT+h2kR8dNu1ESXmbzwFmO84x5UjriqEv3dclL3mgRSIGaj1iwoOOHJOIL4pOOR7DVVk/c2H0++Hb1EkqzEkfkhxU+x8tV421V6RyRzTQF6T6BqFl07nNAcTLAeHKo3yaqH7RRjhuMd9rxM2pAKyz8QCsBr5L7tI06AMr0kCAwEAAaMhMB8wHQYDVR0OBBYEFOI7M+DDFMlP7Ac3aomPnWo1QL1SMA0GCSqGSIb3DQEBCwUAA4IBAQBv+8rBiDY8sZDBoUDYwFQM74QjqCmgNQfv5B0Vjwg20HinERjQeH24uAWzyhWN9++FmeY4zcRXDY5UNmB0nJz7UGlprA9s7voQ0Lkyiud0DO072RPBg38LmmrqoBsLb3MB9MZ2CGBaHftUHfpdTvrgmXSP0IJn7mCUq27g+hFk7n/MLbN1k8JswEODIgdMRvGqN+mnrPKkviWmcVAZccsWfcmS1pKwXqICTKzd6WmVdz+cL7ZSd9I2X0pY4oRwauoE2bS95vrXljCYgLArI3XB2QcnglDDBRYu3Z3aIJb26PTIyhkVKT7xaXhXl4OgrbmQon9/O61G2dzpjzzBPqNP"
			]
		},
		{
			"kty": "RSA",
			"use": "sig",
			"kid": "M6pX7RHoraLsprfJeRCjSxuURhc",
			"x5t": "M6pX7RHoraLsprfJeRCjSxuURhc",
			"n": "xHScZMPo8FifoDcrgncWQ7mGJtiKhrsho0-uFPXg-OdnRKYudTD7-Bq1MDjcqWRf3IfDVjFJixQS61M7wm9wALDj--lLuJJ9jDUAWTA3xWvQLbiBM-gqU0sj4mc2lWm6nPfqlyYeWtQcSC0sYkLlayNgX4noKDaXivhVOp7bwGXq77MRzeL4-9qrRYKjuzHfZL7kNBCsqO185P0NI2Jtmw-EsqYsrCaHsfNRGRrTvUHUq3hWa859kK_5uNd7TeY2ZEwKVD8ezCmSfR59ZzyxTtuPpkCSHS9OtUvS3mqTYit73qcvprjl3R8hpjXLb8oftfpWr3hFRdpxrwuoQEO4QQ",
			"e": "AQAB",
			"x5c": [
	"MIIC8TCCAdmgAwIBAgIQfEWlTVc1uINEc9RBi6qHMjANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTgxMDE0MDAwMDAwWhcNMjAxMDE0MDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEdJxkw+jwWJ+gNyuCdxZDuYYm2IqGuyGjT64U9eD452dEpi51MPv4GrUwONypZF/ch8NWMUmLFBLrUzvCb3AAsOP76Uu4kn2MNQBZMDfFa9AtuIEz6CpTSyPiZzaVabqc9+qXJh5a1BxILSxiQuVrI2BfiegoNpeK+FU6ntvAZervsxHN4vj72qtFgqO7Md9kvuQ0EKyo7Xzk/Q0jYm2bD4SypiysJoex81EZGtO9QdSreFZrzn2Qr/m413tN5jZkTApUPx7MKZJ9Hn1nPLFO24+mQJIdL061S9LeapNiK3vepy+muOXdHyGmNctvyh+1+laveEVF2nGvC6hAQ7hBAgMBAAGjITAfMB0GA1UdDgQWBBQ5TKadw06O0cvXrQbXW0Nb3M3h/DANBgkqhkiG9w0BAQsFAAOCAQEAI48JaFtwOFcYS/3pfS5+7cINrafXAKTL+/+he4q+RMx4TCu/L1dl9zS5W1BeJNO2GUznfI+b5KndrxdlB6qJIDf6TRHh6EqfA18oJP5NOiKhU4pgkF2UMUw4kjxaZ5fQrSoD9omjfHAFNjradnHA7GOAoF4iotvXDWDBWx9K4XNZHWvD11Td66zTg5IaEQDIZ+f8WS6nn/98nAVMDtR9zW7Te5h9kGJGfe6WiHVaGRPpBvqC4iypGHjbRwANwofZvmp5wP08hY1CsnKY5tfP+E2k/iAQgKKa6QoxXToYvP7rsSkglak8N5g/+FJGnq4wP6cOzgZpjdPMwaVt5432GA=="
			]
		}
	]
}
```

This json is known as a JSON Web Key or JWK and can generally be used to validate JWT Tokens. 
The way to extract this data in API Gateway can be seen here:

![Fetch JWK](./Images/FetchJWK.png)

In later versions of Axway API Gateway this key can directly be provided to the JWT Validate filter, however in the version of 7.5.2 of the Axway Api Gateway, there is not yet support for JWK’s with multiple keys being provided to the JSON validate, hence some additional logic is required.

In order to extract the correct key from the jwk we need to extract the KID of the key that was used to sign the JWT Token. We can do this by extracting the Header information from the previously obtained JWT Token. In order to correctly decrypt the JWT token we add some padding at the end of the string. This is required as it is not always included in the JWT token but can result in errors when decoding the JWT header using one of the base64 decode scripts in the scripts library. Finally, the result is cast to a json body so the kid can be extracted using the “JSON Path” filter. 

![extract KID](./Images/extractKID.png)

Now that we have the kid of the request, we can use this information to remove the unneeded keys from the previously obtained JWK, extract all the information we need from the correct certificate. And create the JWK in the correct format as required by the JWT Validate filter.

![format JWK](./Images/formatJWK.png)

Now that we have our JWK we can start validating JWT Tokens that were signed using this key. However, since this is a key that rarely changes, we should add some optimizations to our flow to avoid us from having to generate this key every time. A good way to do this is to cache the JWK we just created using the available caching features in Api Gateway. Caching in api gateway happens using 3 filters. First a unique key is created using the “Create Key” filter. Secondly the “Is Cached?” filter is used to check the cache for the existing record. If it exists, this value is inserted in an attribute. Otherwise it returns false. If no value can be found, we go and fetch the value, and store the value in the cache using the “Cache Attribute filter”. With this added step we can bring all of this together in the following policy:

![Full Policy](./Images/FullPolicy.png)







