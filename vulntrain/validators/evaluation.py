import argparse
from collections import defaultdict
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import json
import os
import re


def extract_cwe_label(pred_id, id2cwe):
    raw = id2cwe.get(str(pred_id))
    if raw:
        return f"CWE-{raw}"
    return f"Unknown({pred_id})"


from transformers import AutoConfig


def load_id2cwe(model_dir):
    try:
        config = AutoConfig.from_pretrained(model_dir)
        id2label = config.id2label
        if not id2label:
            print(f"[WARNING] No id2label found in config for {model_dir}")
            return {}
        return {str(k): v for k, v in id2label.items()}
    except Exception as e:
        print(f"[ERROR] Failed to load config for {model_dir}: {e}")
        return {}


def predict(model_dir, texts, output_file=None):
    print(f"\n[INFO] Loading model from: {model_dir}")
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir)
    model.eval()

    id2cwe = load_id2cwe(model_dir)

    inputs = tokenizer(
        texts, padding=True, truncation=True, max_length=512, return_tensors="pt"
    )
    with torch.no_grad():
        outputs = model(**inputs)
        predictions = torch.argmax(outputs.logits, dim=-1)

    results = []
    for i, pred_id in enumerate(predictions.tolist()):
        label = extract_cwe_label(pred_id, id2cwe)
        results.append((i, model_dir, label))  # We just return the data, don't print

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate multiple CWE classification models."
    )
    parser.add_argument(
        "--model-dirs",
        nargs="+",
        required=True,
        help="List of local directories containing fine-tuned models (or Hub model IDs).",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default="results.txt",
        help="Output file to store predictions",
    )

    args = parser.parse_args()

    # Sample vulnerability descriptions
    vuln_summaries = [
        # 664
        "In crypt.c of remote-login-service, the cryptographic algorithm used to cache usernames and passwords is insecure. An attacker could use this vulnerability to recover usernames and passwords from the file. This issue affects version 1.0.0-0ubuntu3 and prior versions.",
        "Nanopb is a small code-size Protocol Buffers implementation in ansi C. In Nanopb before versions 0.3.9.8 and 0.4.5, decoding a specifically formed message can cause invalid `free()` or `realloc()` calls if the message type contains an `oneof` field, and the `oneof` directly contains both a pointer field and a non-pointer field. If the message data first contains the non-pointer field and then the pointer field, the data of the non-pointer field is incorrectly treated as if it was a pointer value. Such message data rarely occurs in normal messages, but it is a concern when untrusted data is parsed. This has been fixed in versions 0.3.9.8 and 0.4.5. See referenced GitHub Security Advisory for more information including workarounds.",
        # 710
        "A vulnerability in pam_modules of SUSE Linux Enterprise allows attackers to log into accounts that should have been disabled. Affected releases are SUSE Linux Enterprise: versions prior to 12.",
        "ImageMagick is free and open-source software used for editing and manipulating digital images. Prior to versions 6.9.13-27 and 7.1.2-1, there is undefined behavior (function-type-mismatch) in splay tree cloning callback. This results in a deterministic abort under UBSan (DoS in sanitizer builds), with no crash in a non-sanitized build. This issue has been patched in versions 6.9.13-27 and 7.1.2-1.",
        # 657
        "A buffer overflow, as described in CVE-2020-8927, exists in the embedded Brotli library.  Versions of IO::Compress::Brotli prior to 0.007 included a version of the brotli library prior to version 1.0.8, where an attacker controlling the input length of a one-shot decompression request to a script can trigger a crash, which happens when copying over chunks of data larger than 2 GiB. It is recommended to update your IO::Compress::Brotli module to 0.007 or later. If one cannot update, we recommend to use the streaming API as opposed to the one-shot API, and impose chunk size limits.",
        "An authenticated attacker can leverage an exposed “box” object to read and write arbitrary files from disk, provided those files can be parsed as yaml or JSON. This issue was resolved in the Managed and SaaS deployments on February 1, 2023, and in version 23.2.1 of the Self-Managed version of InsightCloudSec. ",
        # 707
        "In Patient Information Center iX (PICiX) Versions C.02, C.03, PerformanceBridge Focal Point Version A.01, the product receives input that is expected to be well-formed (i.e., to comply with a certain syntax) but it does not validate or incorrectly validates that the input complies with the syntax, causing the certificate enrollment service to crash. It does not impact monitoring but prevents new devices from enrolling.",
        "The Essential WP Real Estate plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on the cl_delete_listing_func() function in all versions up to, and including, 1.1.3. This makes it possible for unauthenticated attackers to delete arbitrary pages and posts.",
        # 684
        "The module pandora-doomsday infects other modules. It's since been unpublished from the registry.",
        "base-x is a base encoder and decoder of any given alphabet using bitcoin style leading zero compression. Versions 4.0.0, 5.0.0, and all prior to 3.0.11, are vulnerable to attackers potentially deceiving users into sending funds to an unintended address. This issue has been patched in versions 3.0.11, 4.0.1, and 5.0.1.",
        # 74
        "A vulnerability, which was classified as problematic, was found in Subscribe to Comments Plugin up to 2.0.7 on WordPress. This affects an unknown part of the file subscribe-to-comments.php. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 2.0.8 is able to address this issue. The identifier of the patch is 9683bdf462fcac2f32b33be98f0b96497fbd1bb6. It is recommended to upgrade the affected component. The identifier VDB-222321 was assigned to this vulnerability.",
        "math.js before 3.17.0 had an issue where private properties such as a constructor could be replaced by using unicode characters when creating an object.",
        # 829
        "In Eclipse Theia versions up to and including 0.16.0, in the notification messages there is no HTML escaping, so Javascript code can run.",
        "Teltonika’s Remote Management System versions prior to 4.10.0 have a feature allowing users to access managed devices’ local secure shell (SSH)/web management services over the cloud proxy. A user can request a web proxy and obtain a URL in the Remote Management System cloud subdomain. This URL could be shared with others without Remote Management System authentication . An attacker could exploit this vulnerability to create a malicious webpage that uses a trusted and certified domain. An attacker could initiate a reverse shell when a victim connects to the malicious webpage, achieving remote code execution on the victim device.",
        # 284
        "Bypassing password security vulnerability in McAfee Application and Change Control (MACC) 7.0.1 and 6.2.0 allows authenticated users to perform arbitrary command execution via a command-line utility.",
        "Privilege Escalation vulnerability in Microsoft Windows client (McTray.exe) in McAfee VirusScan Enterprise (VSE) 8.8 prior to Patch 13 allows local users to spawn unrelated processes with elevated privileges via the system administrator granting McTray.exe elevated privileges (by default it runs with the current user's privileges).",
        # 693
        "Piwigo is image gallery software written in PHP. When a criteria is not met on a host, piwigo defaults to using mt_rand in order to generate password reset tokens. mt_rand output can be predicted after recovering the seed used to generate it. This allows an unauthenticated attacker to take over an account providing they know an administrators email address in order to be able to request password reset.",
        "Python's elementtree C accelerator failed to initialise Expat's hash salt during initialization. This could make it easy to conduct denial of service attacks against Expat by constructing an XML document that would cause pathological hash collisions in Expat's internal data structures, consuming large amounts CPU and RAM. The vulnerability exists in Python versions 3.7.0, 3.6.0 through 3.6.6, 3.5.0 through 3.5.6, 3.4.0 through 3.4.9, 2.7.0 through 2.7.15.",
        # 697
        "Envoy is a cloud-native edge/middle/service proxy. Prior to versions 1.34.1, 1.33.3, 1.32.6, and 1.31.8, Envoy's URI template matcher incorrectly excludes the `*` character from a set of valid characters in the URI path. As a result URI path containing the `*` character will not match a URI template expressions. This can result in bypass of RBAC rules when configured using the `uri_template` permissions. This vulnerability is fixed in Envoy versions v1.34.1, v1.33.3, v1.32.6, v1.31.8. As a workaround, configure additional RBAC permissions using `url_path` with `safe_regex` expression.",
        "A flaw was found in all versions of Keycloak before 10.0.0, where the NodeJS adapter did not support the verify-token-audience. This flaw results in some users having access to sensitive information outside of their permissions.",
        # 706
        "On desktop, Ubuntu UI Toolkit's StateSaver would serialise data on tmp/ files which an attacker could use to expose potentially sensitive data. StateSaver would also open files without the O_EXCL flag. An attacker could exploit this to launch a symlink attack, though this is partially mitigated by symlink and hardlink restrictions in Ubuntu. Fixed in 1.1.1188+14.10.20140813.4-0ubuntu1.",
        "A privilege escalation vulnerability was found in nagios 4.2.x that occurs in daemon-init.in when creating necessary files and insecurely changing the ownership afterwards. It's possible for the local attacker to create symbolic links before the files are to be created and possibly escalating the privileges with the ownership change.",
        # 595
        "hestiacp is vulnerable to Use of Wrong Operator in String Comparison",
        "A vulnerability was found in phpRedisAdmin up to 1.16.1. It has been classified as problematic. This affects the function authHttpDigest of the file includes/login.inc.php. The manipulation of the argument response leads to use of wrong operator in string comparison. Upgrading to version 1.16.2 is able to address this issue. The name of the patch is 31aa7661e6db6f4dffbf9a635817832a0a11c7d9. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216267."
        # 436
        "Node.js: All versions prior to Node.js 6.15.0 and 8.14.0: HTTP request splitting: If Node.js can be convinced to use unsanitized user-provided Unicode data for the `path` option of an HTTP request, then data can be provided which will trigger a second, unexpected, and user-defined HTTP request to made to the same server.",
        "A vulnerability classified as critical was found in mhuertos phpLDAPadmin up to 665dbc2690ebeb5392d38f1fece0a654225a0b38. Affected by this vulnerability is the function makeHttpRequest of the file htdocs/js/ajax_functions.js. The manipulation leads to http request smuggling. The attack can be launched remotely. This product does not use versioning. This is why information about affected and unaffected releases are unavailable. The patch is named dd6e9583a2eb2ca085583765e8a63df5904cb036. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-270523.",
        # 138
        "This affects Spring Data JPA in versions up to and including 2.1.6, 2.0.14 and 1.11.20. ExampleMatcher using ExampleMatcher.StringMatcher.STARTING, ExampleMatcher.StringMatcher.ENDING or ExampleMatcher.StringMatcher.CONTAINING could return more results than anticipated when a maliciously crafted example value is supplied.",
        "It's possible to craft Lost Password requests with wildcards in the Token value, which allows attacker to retrieve valid Token(s), generated by users which already requested new passwords. This issue affects: ((OTRS)) Community Edition 5.0.41 and prior versions, 6.0.26 and prior versions. OTRS: 7.0.15 and prior versions.",
        # 703
        "An Improper Handling of Missing Values vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an adjacent, unauthenticated attacker to cause a dcpfe process core and thereby a Denial of Service (DoS). Continued receipt of these specific frames will cause a sustained Denial of Service condition. This issue occurs when a specific malformed ethernet frame is received. This issue affects Juniper Networks Junos OS on QFX10000 Series, PTX1000 Series Series: All versions prior to 19.4R3-S10; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S6; 20.3 versions prior to 20.3R3-S6; 20.4 versions prior to 20.4R3-S5; 21.1 versions prior to 21.1R3-S4; 21.2 versions prior to 21.2R3-S3; 21.3 versions prior to 21.3R3-S3; 21.4 versions prior to 21.4R3-S1; 22.1 versions prior to 22.1R2-S1, 22.1R3; 22.2 versions prior to 22.2R1-S2, 22.2R2.",
        "GVCP dissector crash in Wireshark 4.2.0, 4.0.0 to 4.0.11, and 3.6.0 to 3.6.19 allows denial of service via packet injection or crafted capture file",
        # 754
        "A vulnerability was found in ICEPAY REST-API-NET 0.9. It has been declared as problematic. Affected by this vulnerability is the function RestClient of the file Classes/RestClient.cs of the component Checksum Validation. The manipulation leads to improper validation of integrity check value. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. Upgrading to version 1.0 is able to address this issue. The patch is named 61f6b8758e5c971abff5f901cfa9f231052b775f. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-222847.",
        "An Improper Validation of Integrity Check Value issue was discovered in PHOENIX CONTACT mGuard firmware versions 7.2 to 8.6.0. mGuard devices rely on internal checksums for verification of the internal integrity of the update packages. Verification may not always be performed correctly, allowing an attacker to modify firmware update packages.",
        # 691
        "A vulnerability classified as problematic was found in phpkobo Ajax Poll Script 3.18. Affected by this vulnerability is an unknown functionality of the file ajax-poll.php of the component Poll Handler. The manipulation leads to improper enforcement of a single, unique action. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-240949 was assigned to this vulnerability.",
        "A vulnerability classified as problematic has been found in Thecosy IceCMS 2.0.1. Affected is an unknown function of the file /WebArticle/articles/ of the component Like Handler. The manipulation leads to improper enforcement of a single, unique action. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-246438 is the identifier assigned to this vulnerability.",
        # 285
        "Brocade Fabric OS versions before 8.2.3e2, versions 9.0.0 through 9.2.0c, and 9.2.1 through 9.2.1a can capture the SFTP/FTP server password used for a firmware download operation initiated by SANnav or through WebEM in a weblinker core dump that is later captured via supportsave.",
        "The TeleMessage service through 2025-05-05 is based on a JSP application in which the heap content is roughly equivalent to a core dump in which a password previously sent over HTTP would be included in this dump, as exploited in the wild in May 2025.",
        # 1071
        "The following code attempts to synchronize on an object, but does not execute anything in the synchronized block. This does not actually accomplish anything and may be a sign that a programmer is wrestling with synchronization but has not yet achieved the result they intend.",
        "Empty code blocks can occur in the bodies of conditionals, function or method definitions, exception handlers, etc.  While an empty code block might be intentional, it might also indicate incomplete implementation, accidental code deletion, unexpected macro expansion, etc.  For some programming languages and constructs, an empty block might be allowed by the syntax, but the lack of any behavior within the block might violate a convention or API in such a way that it is an error.",
        # 913
        "ToUI is a Python package for creating user interfaces (websites and desktop apps) from HTML. ToUI is using Flask-Caching (SimpleCache) to store user variables. Websites that use `Website.user_vars` property. It affects versions 2.0.1 to 2.4.0. This issue has been patched in version 2.4.1.",
        "Authenticated Gaia users can inject code or commands by global variables through special HTTP requests. A Security fix that mitigates this vulnerability is available.",
        # 682
        "FreeRDP prior to version 2.0.0-rc4 contains an Integer Truncation that leads to a Heap-Based Buffer Overflow in function update_read_bitmap_update() and results in a memory corruption and probably even a remote code execution.",
        "Avira Free Antivirus 15.0.1907.1514 is prone to a local privilege escalation through the execution of kernel code from a restricted user.",
        # 94
        "A remote PHP code execution vulnerability exists in InstantCMS version 1.6 and earlier due to unsafe use of eval() within the search view handler. Specifically, user-supplied input passed via the look parameter is concatenated into a PHP expression and executed without proper sanitation. A remote attacker can exploit this flaw by sending a crafted HTTP GET request with a base64-encoded payload in the Cmd header, resulting in arbitrary PHP code execution within the context of the web server.",
        "PHP-Charts v1.0 contains a PHP code execution vulnerability in wizard/url.php, where user-supplied GET parameter names are passed directly to eval() without sanitization. A remote attacker can exploit this flaw by crafting a request that injects arbitrary PHP code, resulting in command execution under the web server's context. The vulnerability allows unauthenticated attackers to execute system-level commands via base64-encoded payloads embedded in parameter names, leading to full compromise of the host system.",
        # 862
        "A vulnerability in open build service allows remote attackers to upload arbitrary RPM files. Affected releases are SUSE open build service prior to 2.1.16.",
        "The controller of the Open Build Service API prior to version 2.4.4 is missing a write permission check, allowing an authenticated attacker to add or remove user roles from packages and/or project meta data.",
        # 435
        "Compiler removal of buffer clearing in sli_cryptoacc_transparent_key_agreement in Silicon Labs Gecko Platform SDK v4.2.1 and earlier results in key material duplication to RAM.",
        "Compiler removal of buffer clearing in sli_se_driver_mac_compute in Silicon Labs Gecko Platform SDK v4.2.1 and earlier results in key material duplication to RAM.",
        # 131
        "The FPC (Flexible PIC Concentrator) of Juniper Networks Junos OS and Junos OS Evolved may restart after processing a specific IPv4 packet. Only packets destined to the device itself, successfully reaching the RE through existing edge and control plane filtering, will be able to cause the FPC restart. When this issue occurs, all traffic via the FPC will be dropped. By continuously sending this specific IPv4 packet, an attacker can repeatedly crash the FPC, causing an extended Denial of Service (DoS) condition. This issue can only occur when processing a specific IPv4 packet. IPv6 packets cannot trigger this issue. This issue affects: Juniper Networks Junos OS on MX Series with MPC10E or MPC11E and PTX10001: 19.2 versions prior to 19.2R1-S4, 19.2R2; 19.3 versions prior to 19.3R2-S2, 19.3R3; 19.4 versions prior to 19.4R1-S1, 19.4R2. Juniper Networks Junos OS Evolved on on QFX5220, and PTX10003 series: 19.2-EVO versions; 19.3-EVO versions; 19.4-EVO versions prior to 19.4R2-EVO. This issue does not affect Junos OS versions prior to 19.2R1. This issue does not affect Junos OS Evolved versions prior to 19.2R1-EVO.",
        "curl before version 7.61.1 is vulnerable to a buffer overrun in the NTLM authentication code. The internal function Curl_ntlm_core_mk_nt_hash multiplies the length of the password by two (SUM) to figure out how large temporary storage area to allocate from the heap. The length value is then subsequently used to iterate over the password and generate output into the allocated storage buffer. On systems with a 32 bit size_t, the math to calculate SUM triggers an integer overflow when the password length exceeds 2GB (2^31 bytes). This integer overflow usually causes a very small buffer to actually get allocated instead of the intended very huge one, making the use of that buffer end up in a heap buffer overflow. (This bug is almost identical to CVE-2017-8816.)",
        # 1025
        "Multiple Cisco products are affected by a vulnerability in the rate filtering feature of the Snort detection engine that could allow an unauthenticated, remote attacker to bypass a configured rate limiting filter. This vulnerability is due to an incorrect connection count comparison. An attacker could exploit this vulnerability by sending traffic through an affected device at a rate that exceeds a configured rate filter. A successful exploit could allow the attacker to successfully bypass the rate filter. This could allow unintended traffic to enter the network protected by the affected device.",
        "Misskey is an open source, federated social media platform. The patch for CVE-2024-52591 did not sufficiently validate the relation between the `id` and `url` fields of ActivityPub objects. An attacker can forge an object where they claim authority in the `url` field even if the specific ActivityPub object type require authority in the `id` field. Version 2025.2.1 addresses the issue.",
    ]

    grouped_results = defaultdict(list)

    for model_dir in args.model_dirs:
        results = predict(model_dir, vuln_summaries)
        for idx, model, label in results:
            grouped_results[idx].append((model, label))

    with open(args.output_file, "w") as f:
        for idx in sorted(grouped_results):
            description = vuln_summaries[idx].strip().replace("\n", " ")
            f.write(f'Example {idx + 1}: "{description}"\n')
            for model, label in grouped_results[idx]:
                f.write(f"  Model: {model}\n")
                f.write(f"  Predicted CWE: {label}\n")
            f.write("\n")


if __name__ == "__main__":
    main()
