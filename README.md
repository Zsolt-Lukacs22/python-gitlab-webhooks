# Python Gitlab Webhooks

Simple Python WSGI application to handle Gitlab webhooks.

This work is based on [Carlos Jenkins's project](https://github.com/carlos-jenkins/python-github-webhooks), it will most probably behave the same (or as close as lazy humanly possible) to his.

> [!NOTE] 
> This work doesn't aim to be used by a large audience, but more like an internal fork for private use where I did not find any other usable alternative.

## Usage

- Build with `docker build . -t python-gitlab-webhooks`,
- Example run as `docker run --name python-gitlab-webhooks -p 443:443 -d python-gitlab-webhooks:latest python webhooks.py -p 443 --cert /app/cert.pem --certkey /app/key.pem`,
- Add the relevant hooks under the `hooks` folder.

> [!TIP]
> Any other usage basically follows Carlos' work, except the fact that you need to rely on the GitLab API payload.