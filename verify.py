#!/usr/bin/env python3
from base64 import b64encode
from pathlib import Path
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from contrastverify import ContrastVerifyAction
from contrastverify.helpers.input_output_helpers import InputHelper, OutputHelper


def validate_inputs(output_helper: OutputHelper):
    """Populate configuration object or set step to failed if required inputs are not set."""
    errors = []
    config = {}

    apiKey = InputHelper.get_input("API_KEY")
    if apiKey and apiKey != "":
        config["API_KEY"] = apiKey
    else:
        errors.append("apiKey")

    orgId = InputHelper.get_input("ORG_ID")
    if orgId and orgId != "":
        config["ORG_ID"] = orgId
    else:
        errors.append("orgId")

    authorization = InputHelper.get_input("AUTH_HEADER")
    username = InputHelper.get_input("USER_NAME")
    service_key = InputHelper.get_input("SERVICE_KEY")

    if authorization and authorization != "":
        config["AUTHORIZATION"] = authorization
    elif (username and username != "") and (service_key and service_key != ""):
        config["AUTHORIZATION"] = str(
            b64encode(bytes(f"{username}:{service_key}", "UTF-8")), "UTF-8"
        )
    else:
        errors.append("authHeader or (userName and serviceKey)")

    app_id = InputHelper.get_input("APP_ID")
    app_name = InputHelper.get_input("APP_NAME")
    if app_id and app_id != "":
        config["APP_ID"] = app_id
    elif app_name and app_name != "":
        config["APP_NAME"] = app_name
    else:
        errors.append("appId or appName")

    url = (
        InputHelper.get_input("API_URL")
        or "https://app.contrastsecurity.com/Contrast/api/ng/"
    )
    if not url.startswith("https://") and not url.startswith("http://"):
        errors.append("apiUrl (must start with http:// or https://)")

    job_start_time = InputHelper.get_input("JOB_START_TIME")
    if job_start_time is not None and job_start_time != "":
        try:
            config["JOB_START_TIME"] = int(job_start_time)
        except ValueError:
            errors.append("jobStartTime (must be a number)")

    if len(errors) != 0:
        output_helper.error(
            f'Missing required inputs: {", ".join(errors)}, please see documentation for correct usage.'
        )
        output_helper.set_failed("Missing required inputs")

    url_parts = urlparse(url)
    if url_parts.path != "/Contrast/api/ng/":
        url = f"{url_parts.scheme}://{url_parts.netloc}/Contrast/api/ng/"
    config["BASE_URL"] = f"{url}{config['ORG_ID']}/"
    output_helper.debug(f'Base URL: {config["BASE_URL"]}')

    severities = InputHelper.get_input("SEVERITIES") or "CRITICAL,HIGH"
    config["SEVERITIES"] = InputHelper.get_included_severities(severities)

    fail_threshold = InputHelper.get_input("FAIL_THRESHOLD") or 0
    config["FAIL_THRESHOLD"] = int(fail_threshold)

    config["BUILD_NUMBER"] = InputHelper.get_input("BUILD_NUMBER")

    return config


def load_certs(output_helper: OutputHelper) -> Union[Path,bool,None]:
    certs_to_add = InputHelper.get_input("CA_FILE")
    if not certs_to_add:
        return None
    # handle ignore Certs
    if certs_to_add.upper() == "FALSE":
        # type: ignore  
        return False

    import pathlib

    from certifi import where as default_certs_path

    output_file = (
        pathlib.Path(default_certs_path()).parent / "contrast_verify_ca_file.pem"
    )
    with open(output_file, "w") as certs:
        certs.write(certs_to_add)

    output_helper.info(f"Wrote ca_cert(s) to {output_file}")

    return output_file


if __name__ == "__main__":
    output_helper = OutputHelper()
    config = validate_inputs(output_helper)
    # type: ignore  
    cert_file = load_certs(output_helper)

    action = ContrastVerifyAction(
        config.get("APP_ID"),
        config.get("APP_NAME"),
        config["BASE_URL"],
        config["BUILD_NUMBER"],
        config["API_KEY"],
        config["AUTHORIZATION"],
        config["FAIL_THRESHOLD"],
        config.get("JOB_START_TIME"),
        config["SEVERITIES"],
        output_helper,
        cert_file,
    )
    action.validate_connection()
    action.validate_organization()
    action.determine_application_id()
    action.verify_application()
