#! /usr/bin/env python

"""This module is responsible for loading the configuration variables."""

import importlib.util
import os


def load_config(path):
    spec = importlib.util.spec_from_file_location("config", path)
    if spec:
        config = importlib.util.module_from_spec(spec)
        if spec.loader:
            spec.loader.exec_module(config)
    return config


conf = None
try:
    conf = load_config(
        os.environ.get("VulnTrain_CONFIG", "vulntrain/config/conf_sample.py")
    )
except Exception as exc:
    raise Exception("No configuration file provided.") from exc
finally:
    if not conf:
        raise Exception("No configuration file provided.")

try:
    valkey_host = conf.valkey_host
    valkey_port = conf.valkey_port
except AttributeError as e:
    raise Exception(f"Missing configuration variable: {e}")

try:
    hf_token = conf.hf_token
except Exception:
    hf_token = ""
