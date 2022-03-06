[※ 이 링크를 해석하여 공부하였습니다.](https://www.oauth.com/oauth2-servers/the-resource-server/)

`Resource Server`는 OAuth2.0의 용어입니다.  
Resource Server는 Application이 Access Token을 얻은 후 인증된 요청을 처리하는 역할을 합니다.

규모가 큰 웹 서비스의 경우 다수의 Resource Server를 보유하고 있는 경우가 많습니다. 
예를 들어 Google Service 같은 경우 많은 Resource Server를 가지고 있죠. 
예를 들어 Google Cloud Platform, Google Map, Google Drive, Youtube, Google+ 등등.

각각의 Resource Server는 독립적이지만 같은 Authorization Server를 공유하고 있습니다.

그보다 작은 서비스의 경우 대부분 하나의 Resource Server를 가지고 있습니다. 
그리고 이런 경우 Authorization Server와 Resource Server를 하나의 프로젝트로 빌드합니다.

이제 Resource Server의 책임에 대하여 알아보겠습니다.

### Access Token 검증
Resource Server는 HTTP header인 `Authorization`을 포함하고 있는 request를 Application으로부터
받습니다. 여기서 Authorization은 access token 값을 담고 있습니다.
Resource Server는 이 요청을 처리할지 말지 access token을 검증하는 것으로 알아냅니다. 
그리고 이 access token으로부터 user 정보를 찾아낼 수 있습니다.

만약 token을 database에 저장하여 관리한다면, token 검증하는 것은 DB안에 token table에서 해당 token이 
있는지 확인하는 과정을 수행하게 됩니다.

_잠깐보류_  
이외의 다른 방법으로는 [Token Introspection](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/) 을 사용하는 것입니다.


### Scope 검증
Resource Server는 access token에 포함되어 있는 scope 목록들을 알고 있어야합니다. 
server는 요청하고 있는 행위를 처리하는데 필요한 scope이 access token에서 포함하고 있지 않다면 
해당 Request를 허용하지 않아야할 책임이 있습니다.

참고로, Auth 2.0 스펙에서는 어떤 Scope도 정의해주지 않았습니다. 
Scope 목록은 각자의 Service에 맞게 정해야하는 문제입니다.

### 만료된 토큰
당신의 Service에서 짧은 수명주기의 access token과 그보다 긴 수명주기의 refresh token을 사용하고 있다면,
만료된 token 값을 포함하고 있는 Request로 요청했을 때 적절한 Error Response를 반환해줘야합니다.

아래 예시처럼 WWW-Authenticate Header를 포함하고 있는 HTTP 401 응답을 반환해줘야합니다.
당신의 API가 보통 JSON 응답형태로 처리되고 있다면, JSON body에 같은 error 정보를 지정하여 반환할 수 있습니다.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
                  error_description="The access token expired"
Content-type: application/json
 
{
  "error": "invalid_token",
  "error_description": "The access token expired"
}
```

Client에게 access token이 만료되었고, 
refresh token을 사용해서 새 access token을 발급받아야한다는 정보를 알려줄 수 있습니다.

### Error Code와 인증되지 않은 접근
access token이 요청된 자원의 접근 권한을 포함하고 있지 않는 경우나 request에 access token이 없을 때,
server는 `WWW-Authenticate header`를 포함한 HTTP 401 응답을 반환해야합니다.

최소한의 `WWW-Authenticate header`에 bearer토큰이 필수라는 것을 가리키는 문자열 `Bearer`가 포함되어야합니다. 
header에 이외의 추가적인 정보(예를 들면 `realm`, `scope`과 같은)도 포함할 수 있습니다.

- realm: [이곳을 참조. 공부가 더 필요함.](https://datatracker.ietf.org/doc/html/rfc2617)
- scope: Resource Server가 resource에 접근하는데 필요한 scope의 목록을 나타내는 것이고, 유저로부터 적절한 scope을 요청할 수 있습니다. 

response에 발생하는 error 종류에 따른 적절한 error 값 또한 포함되어야 합니다.

- `invalid_request` (HTTP 400) - 요청에 파라미터가 없거나 형식에 맞지 않은 파라미터가 포함되어 있을 경우 발생
- `invalid_token` (HTTP 401) - access token이 만료되었거나, 폐기되었거나, 형식에 맞지 않거나, 그 외의 이유들로 유효하지 않는 토큰일 경우 발생. client는 새로운 access token을 발급받아 다시 요청을 시도해야함.
- `insufficient_scope` (HTTP 403) - 해당 요청을 처리하는데 필수적인 scope이 아닐 경우 발생

예시: 
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="example",
                  scope="delete",
                  error="insufficient_scope"
```