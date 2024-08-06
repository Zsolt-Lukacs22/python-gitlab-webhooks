# -*- coding: utf-8 -*-
#
# Copyright (C) 2014, 2015, 2016 Carlos Jenkins <carlos@jenkins.co.cr>
# Modifications added by Zsolt Lukacs <owner of this repository> to convert the implementation with GitLab support.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import logging

import argparse
from json import loads, dumps
from subprocess import Popen, PIPE
from tempfile import mkstemp
from os import access, X_OK, remove, fdopen
from os.path import isfile, abspath, normpath, dirname, join, basename

from flask import Flask, request, abort

logging.basicConfig(level=logging.DEBUG)


application = Flask(__name__)


# setup CLI arguments
argumentParser = argparse.ArgumentParser(
    description="Gitlab Webhook handler to ease up things.", prog="webhooks"
)

argumentParser.add_argument(
    "-p",
    "--port",
    default=5000,
    type=int,
    help="the port number on which the webhooks should be exposed",
)
argumentParser.add_argument(
    "--cert", default=None, help="the path to the SSL certificate"
)
argumentParser.add_argument(
    "--certkey",
    default=None,
    help="the path to the private key file of the SSL certificate",
)
argumentParser.add_argument("--debug", default=True, action="store_true")

cliArguments = argumentParser.parse_args()
logging.info("Received CLI arguments:\n{}".format(dumps(vars(cliArguments), indent=4)))

path = normpath(abspath(dirname(__file__)))

# Load config
with open(join(path, "config.json"), "r") as cfg:
    config = loads(cfg.read())


def _verify_token(received_token: str) -> bool:
    acceptable_token = config["token"]
    return acceptable_token == received_token


@application.route("/", methods=["POST"])
def index():  # NOSONAR
    hooks = config.get("hooks_path", join(path, "hooks"))

    if "X-Gitlab-Token" not in request.headers or not _verify_token(
        request.headers["X-Gitlab-Token"]
    ):
        abort(401)

    # Gather data
    try:
        payload = request.get_json()
    except Exception:
        logging.exception("Request parsing failed")
        abort(400)

    event = payload["object_kind"]

    # Determining the branch is tricky, as it only appears for certain event
    # types an at different levels
    branch = None
    try:
        # Case 1: a merge_request object is involved
        if event in ["merge_request"]:
            # This is the TARGET branch for the pull-request, not the source
            # branch
            branch = payload["object_attributes"]["target_branch"]
        # Case 2: a push object is involved
        elif event in ["push"]:
            # Push events provide a full Git ref in 'ref'
            branch = payload["ref"].split("/", 2)[2]
    except KeyError:
        # If the payload structure isn't what we expect, we'll live without
        # the branch name
        logging.warning("We will miss branch as the structure was unexpected")

    # Most of the relevant events (like merge requests, commits, tags, issues, comments, etc.) share this key
    name = payload["repository"]["name"] if "repository" in payload else None

    meta = {"name": name, "branch": branch, "event": event}
    logging.info("Metadata:\n{}".format(dumps(meta, indent=4)))

    # Possible hooks
    scripts = []
    if branch and name:
        scripts.append(join(hooks, "{event}-{name}-{branch}".format(**meta)))
    if name:
        scripts.append(join(hooks, "{event}-{name}".format(**meta)))
    scripts.append(join(hooks, "{event}".format(**meta)))
    scripts.append(join(hooks, "all"))

    # Check permissions
    scripts = [s for s in scripts if isfile(s) and access(s, X_OK)]
    if not scripts:
        return dumps({"status": "nop"})

    # Save payload to temporal file
    osfd, tmpfile = mkstemp()
    with fdopen(osfd, "w") as pf:
        pf.write(dumps(payload))

    # Run scripts
    ran = {}
    for s in scripts:
        proc = Popen([s, tmpfile, event], stdout=PIPE, stderr=PIPE)
        stdout, stderr = proc.communicate()

        ran[basename(s)] = {
            "returncode": proc.returncode,
            "stdout": stdout.decode("utf-8"),
            "stderr": stderr.decode("utf-8"),
        }

        # Log errors if a hook failed
        if proc.returncode != 0:
            logging.error(
                "Invocation of external hook failed: {} : {} \n{}".format(
                    s, proc.returncode, stderr
                )
            )

    # Remove temporal file
    remove(tmpfile)

    info = config.get("return_scripts_info", False)
    if not info:
        return dumps({"status": "done"})

    output = dumps(ran, sort_keys=True, indent=4)
    logging.info(output)
    return output


if __name__ == "__main__":
    application.run(
        debug=cliArguments.debug,
        host="0.0.0.0",
        port=cliArguments.port,
        ssl_context=(cliArguments.cert, cliArguments.certkey)
        if cliArguments.certkey
        else None,
    )
