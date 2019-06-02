# oauth2_sidecar

This is a side car that acts as a proxy to manage OAuth2 Authentication.
The side car will send you back the connected ClientID in the request headers ie:
"Clientid":["amine.bizid@fake.com"]

## Walkthrough

- Create a config.yaml file as follow:

```yaml
env:
  target_url: { usl of your final container ie http://127.0.0.1/5080}
  port: {side car port to be exposed}
  well_known_url: {your issuer well known url}
  client_id: {your client id}
  redirect_uri: http://{url}:{port}/signin-oidc
  audience: {audience}
  scopes: {space separated scopes}
  session_key: {Use a long secret to protect the cookies}
  logLevel: {error, info or debug}
```

- Update your deployment by upating sample/chart/templates/dep.yaml as follow:

```yaml
spec:
  containers:
  - name: {Name of your container}
    image: {your docker image}
    ports:
    - containerPort: {the exposed port of your image}
```

- Deploy using helm

```bash
cd sample
kubectl create ns side
helm upgrade --namespace side --values config.yaml  --install side chart
```

## Building

`make`

## Running

`./bin/oauth2_sidecar`

## MIT License

Copyright (c) 2019 Amine BIZID

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

