import os
import re
import uuid
from pathlib import Path

import numpy as np
import pandas as pd


SOURCE_TYPES = [
    "intune", "edr", "av", "dlp", "bigfix", "cmdb", "zscaler", "hr", "extra"
]

FILENAME_KEYWORDS = {
    "intune": ["intune"],
    "edr": ["edr", "defender", "endpoint"],
    "av": ["av", "antivirus", "anti-virus", "securityintel"],
    "dlp": ["dlp", "forcepoint"],
    "bigfix": ["bigfix"],
    "cmdb": ["cmdb", "servicenow"],
    "zscaler": ["zscaler", "zcc"],
    "hr": ["hr", "employee", "employees", "user", "users", "employee_master"],
}

# These are the application-specific columns used by the supplied
# processing logic for date/version/identity extraction.
TOOL_META_COLS = {
    "intune": {
        "date": ["lastSyncDateTime"],
        "ver": ["osVersion", "Version"]
    },
    "edr": {
        "date": ["LastSeen"],
        "ver": ["OSVersion", "Version", "Agent Version"]
    },
    "av": {
        "date": ["LastSeen", "SignatureUpdateTime"],
        "ver": [
            "SecurityIntelVersion",
            "AV Version",
            "Antivirus Version",
            "Version",
            "Product Version"
        ]
    },
    "dlp": {
        "date": ["Last Update"],
        "ver": ["Client Installation Version", "Version", "DLP Version"]
    },
    "bigfix": {
        "date": ["Last Report Time"],
        "ver": ["Version", "Agent Version"]
    },
    "cmdb": {
        "date": ["Last Seen Connected to ZIA", "Registration TimeStamp"],
        "ver": ["Version"]
    },
    "zscaler": {
        "date": ["Last Seen Connected to ZIA"],
        "ver": [
            "Zscaler Client Connector Version",
            "Version",
            "ZCC Version"
        ]
    },
}

HR_FIELDS = [
    "Title", "Department", "Company", "Employee number", "HOD",
    "HOD User ID", "HOD Email", "HOD Department", "HOF",
    "HOF User ID", "HOF Email", "HOF Department", "Manager",
    "Manager User ID", "Manager Email", "Manager Department"
]

ENTITY_SEQ_MAP = {
    "NSEIL": 1, "NCL": 2, "NDAL": 3, "NIL": 3, "NSEICC": 4,
    "NSEIX": 4, "NAL": 5, "NASL": 6, "NSRAL": 7,
    "NSIL": 8, "NSEF": 9
}

HEADERS = {
    "bigfix": [
        "Computer Name", "Serial No", "New_Bitlocker  Status", "Zscaler Agent",
        "ForcePoint DLP", "User Name", "Full User Name", "Device Type",
        "Location", "IP Address", "OS", "Last Report Time", "Ageing",
        "Ageing state", "Bigfix Online State", "Encryption State", "Entity",
        "Sequence no", "Asset Status", "Operational status", "Add Remark",
        "Intune Status", "Intune Remark", "EDR Status", "EDR Remark",
        "AV Status", "AV Remark", "Bitlocker Status", "Bitlocker Remark",
        "DLP Status", "DLP Remark", "CMDB Status", "CMDB Remark",
        "Zscaler Status", "Zscaler Remark", "Name", "Email", "User ID",
        "Title", "Department", "Company", "Employee number", "HOD",
        "HOD User ID", "HOD Email", "HOD Department", "HOF", "HOF User ID",
        "HOF Email", "HOF Department", "Manager", "Manager User ID",
        "Manager Email", "Manager Department", "Compliance Status", "Action"
    ],
    "intune": [
        "deviceName", "operatingSystem", "osVersion", "serialNumber",
        "userPrincipalName", "complianceState", "deviceEnrollmentType",
        "enrolledDateTime", "lastSyncDateTime", "Ageing", "Ageing state",
        "Bigfix Status", "Bigfix Remark", "CMDB Status", "CMDB Remark", "RITM"
    ],
    "edr": [
        "DeviceName", "LastSeen", "OSPlatform", "OSVersion",
        "OnboardingStatus", "HealthStatus", "Ageing", "Ageing state",
        "Bigfix Status", "Bigfix Remark", "CMDB Status", "CMDB Remark",
        "Intune Status", "Intune Remark", "RITM", "Hostname"
    ],
    "av": [
        "DeviceName", "OS", "OSPlatform", "OSVersion", "AVMode",
        "SecurityIntelVersion", "LastSeen", "SignatureUpdateTime",
        "Ageing", "Ageing state", "Bigfix Status", "Bigfix Remark",
        "CMDB Status", "CMDB Remark", "Intune Status", "Intune Remark",
        "RITM", "Hostname"
    ],
    "dlp": [
        "Hostname", "IP Address", "Logged-in Users", "Version",
        "Last Update", "Profile Name", "Synced", "Discovery Status",
        "Ageing", "Ageing state", "Bigfix Status", "Bigfix Remark",
        "CMDB Status", "CMDB Remark", "Intune Status", "Intune Remark", "RITM"
    ],
    "cmdb": [
        "Name", "IP Address", "OEM Serial No.", "Entity", "Sequence no",
        "Asset Status", "Operational status", "Add Remark", "Updated",
        "Updated by", "Operating System", "Asset Owner", "Asset Type",
        "Comments", "Created", "Created by", "Location", "Department",
        "Name.1", "Active", "User ID", "Email", "Manager", "Active.1",
        "User ID.1", "Email.1", "Manager.1", "Active.2", "User ID.2",
        "Email.2", "Manager.2", "Active.3", "User ID.3", "Email.3",
        "Name.2", "Intune Status", "EDR Status", "AV Status",
        "Bitlocker Status", "DLP Status", "Bigfix Status", "Zscaler Status",
        "Compliance Status", "Action"
    ],
    "zscaler": [
        "User", "Device type", "Device model", "External Device ID", "UDID",
        "UDID Sr No", "Mac Address", "Company Name", "OS Version",
        "Zscaler Client Connector Version", "Zscaler Digital Experience Version",
        "Policy Name", "Last Seen Connected to ZIA",
        "Last Seen Connected to ZIA date", "Today", "Ageing", "Ageing state",
        "VPN State", "Device State", "Owner", "Hostname", "Manufacturer",
        "Config Download Count", "Registration TimeStamp",
        "Last Deregistration TimeStamp", "Config Download TimeStamp",
        "Last Seen with Client Connector Active", "Device Hardware Fingerprint",
        "Tunnel Version", "Log TS", "Log Ack TS", "Log Url", "ZCC Revert Status",
        "Device Trust Level", "Zscaler Data Protection Version",
        "Active Tunnel SDK version", "Imprivata User", "SerialNumber",
        "Installation Type", "Last Seen Connected to ZPA", "Entity",
        "Asset Status", "Operational status", "Add Remark", "Bigfix Status",
        "Bigfix Remark", "CMDB Status", "CMDB Remark", "Intune Status",
        "Intune Remark", "Ref RITM"
    ]
}


def normalize_text(value):
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def clean_hostname(name):
    if pd.isna(name) or str(name).strip() == "":
        return np.nan
    return str(name).split(".")[0].strip().upper()


def clean_name(name):
    """Removes bracketed text and standardizes spacing."""
    if pd.isna(name) or not name:
        return ""
    n_str = str(name)
    n_str = re.sub(r"\(.*?\)", "", n_str)
    return n_str.strip().lower()


def clean_user_id(uid):
    """Strips domain prefixes like NDALROOT\\ or NDALROOT/."""
    if uid is None or pd.isna(uid):
        return ""
    uid_str = str(uid).strip()
    if uid_str.lower() == "nan":
        return ""
    if "\\" in uid_str:
        return uid_str.split("\\")[-1]
    if "/" in uid_str:
        return uid_str.split("/")[-1]
    return uid_str


def load_data(file_path):
    if not file_path:
        return pd.DataFrame()

    path = str(file_path).lower()

    if path.endswith(".csv"):
        try:
            return pd.read_csv(file_path, dtype=str)
        except UnicodeDecodeError:
            return pd.read_csv(file_path, encoding="latin1", dtype=str)

    if path.endswith(".xlsx"):
        return pd.read_excel(file_path)

    return pd.DataFrame()


def find_col(df, expected_names):
    """Case/space/punctuation-insensitive column matching."""
    columns = {normalize_text(c): c for c in df.columns}

    for name in expected_names:
        key = normalize_text(name)
        if key in columns:
            return columns[key]

    return None


def get_val(column, row_dict):
    if not column:
        return ""
    val = row_dict.get(column)
    return "" if val is None or pd.isna(val) else str(val).strip()


def format_date(date_str):
    if not date_str:
        return None
    try:
        d = pd.to_datetime(date_str, errors="coerce")
        if pd.notna(d):
            return d.strftime("%d-%m-%Y")
    except Exception:
        pass
    return str(date_str)[:10]


def calculate_ageing(date_str):
    if date_str is None or pd.isna(date_str) or not date_str:
        return np.nan

    try:
        d = pd.to_datetime(date_str, errors="coerce")
        if pd.notna(d):
            if getattr(d, "tz", None) is not None:
                d = d.tz_localize(None)
            return (pd.Timestamp.now().normalize() - d.normalize()).days
    except Exception:
        pass

    return np.nan


def normalize_entity(ent):
    if not ent or str(ent).strip() == "":
        return "NSEIL"

    e = str(ent).strip().lower()

    mapping = {
        "ncl": "NCL", "nseil": "NSEIL", "nasl": "NASL",
        "nsef": "NSEF", "nse foundation": "NSEF", "nse": "NSEF",
        "nsil": "NSIL", "nal": "NAL", "nal vendor": "NAL",
        "nseicc": "NSEICC", "nseix": "NSEIX", "nseix vendor": "NSEIX",
        "ndal": "NDAL", "ndal vendor": "NDAL",
        "nil": "NIL", "nil vendor": "NIL",
        "nsral": "NSRAL", "nsral vendor": "NSRAL"
    }

    mapped = mapping.get(e)
    if mapped:
        return mapped

    for k, v in mapping.items():
        if k in e:
            return v

    return "NSEIL"


def filename_detect_source(filename):
    """
    Filename detection has priority, as requested.
    A UUID is used for storage so duplicate original filenames never overwrite.
    """
    stem = Path(filename).stem.lower()
    matches = []

    for source, keywords in FILENAME_KEYWORDS.items():
        for keyword in keywords:
            if keyword in stem:
                matches.append((len(keyword), source))

    if not matches:
        return None

    matches.sort(reverse=True)
    return matches[0][1]


def detect_source_by_columns(df):
    """Fallback classification when the filename has no application name."""
    cols = {normalize_text(c) for c in df.columns}

    signatures = {
        "intune": [
            "devicename", "operatingsystem", "osversion",
            "serialnumber", "userprincipalname"
        ],
        "edr": [
            "devicename", "lastseen", "osplatform",
            "onboardingstatus", "healthstatus"
        ],
        "av": [
            "devicename", "avmode", "securityintelversion", "lastseen"
        ],
        "dlp": [
            "hostname", "ipaddress", "loggedinusers",
            "profilename", "discoverystatus"
        ],
        "bigfix": [
            "computername", "serialno", "lastreporttime",
            "newbitlockerstatus"
        ],
        "cmdb": [
            "oemserialno", "assetstatus", "operationalstatus",
            "updatedby", "assetowner"
        ],
        "zscaler": [
            "hostname", "udid", "zscalerclientconnectorversion",
            "lastseenconnectedtozia"
        ],
        "hr": [
            "employeenumber", "title", "department", "hod", "manager"
        ]
    }

    scores = {
        source: len(cols.intersection(signature))
        for source, signature in signatures.items()
    }

    best = max(scores, key=lambda source: scores[source])

    return best if scores[best] >= 2 else "extra"


def detect_source(filename, df):
    source = filename_detect_source(filename)
    if source:
        return source, "filename"
    return detect_source_by_columns(df), "columns"


def version_key(value):
    """
    Numeric semantic-ish comparison.
    4.10 is correctly greater than 4.9.
    """
    if value is None or pd.isna(value):
        return ()

    text = str(value).strip()
    match = re.search(r"\d+(?:\.\d+)+(?:\.\d+)*|\d+", text)

    if not match:
        return ()

    return tuple(int(x) for x in re.findall(r"\d+", match.group(0)))


def version_sort_key(value):
    return (version_key(value), str(value).lower())


def version_is_below(actual_version, minimum_version):
    if not minimum_version:
        return False

    actual = version_key(actual_version)
    minimum = version_key(minimum_version)

    if not actual:
        return True

    if not minimum:
        return False

    length = max(len(actual), len(minimum))
    actual = actual + (0,) * (length - len(actual))
    minimum = minimum + (0,) * (length - len(minimum))

    return actual < minimum


def extract_application_versions(df, source):
    """
    Reads every known version column for an application.
    Multiple files assigned to the same application are aggregated later.
    """
    if source not in TOOL_META_COLS:
        return []

    versions = []

    for expected in TOOL_META_COLS[source].get("ver", []):
        column = find_col(df, [expected])
        if not column:
            continue

        for value in df[column].dropna().astype(str):
            value = value.strip()
            if value and value.lower() not in {"nan", "none", "null"}:
                versions.append(value)

    return sorted(set(versions), key=version_sort_key)


def save_uploaded_files(files, upload_folder):
    """
    Each upload is stored with a unique name. Duplicate original names
    are therefore safe.
    """
    job_id = uuid.uuid4().hex
    job_dir = os.path.join(upload_folder, job_id)
    os.makedirs(job_dir, exist_ok=True)

    saved = []

    for index, file in enumerate(files):
        original_name = os.path.basename(file.filename or "").strip()
        if not original_name:
            continue

        extension = Path(original_name).suffix.lower()
        if extension not in {".csv", ".xlsx"}:
            continue

        stored_name = f"{index:03d}_{uuid.uuid4().hex}{extension}"
        path = os.path.join(job_dir, stored_name)
        file.save(path)

        saved.append({
            "id": uuid.uuid4().hex,
            "original_name": original_name,
            "stored_name": stored_name,
            "path": path
        })

    return job_id, saved


def inspect_files(saved_files):
    inspected = []

    for item in saved_files:
        try:
            df = load_data(item["path"])

            if df.empty:
                detected_source = "extra"
                detection_method = "empty"
                versions = []
            else:
                detected_source, detection_method = detect_source(
                    item["original_name"], df
                )
                versions = extract_application_versions(
                    df, detected_source
                )

            inspected.append({
                **item,
                "detected_source": detected_source,
                "detection_method": detection_method,
                "rows": len(df),
                "columns": len(df.columns),
                "versions": versions,
                "error": None
            })

        except Exception as exc:
            inspected.append({
                **item,
                "detected_source": "extra",
                "detection_method": "error",
                "rows": 0,
                "columns": 0,
                "versions": [],
                "error": str(exc)
            })

    return inspected


def build_version_catalog(inspected, assignments=None):
    """
    Builds the version list from the files' current assignments.
    If assignments are supplied after the review screen, the catalog
    reflects the user's final source selection.
    """
    catalog = {source: [] for source in SOURCE_TYPES}

    for item in inspected:
        source = (
            assignments.get(item["id"], item["detected_source"])
            if assignments
            else item["detected_source"]
        )

        if source not in catalog:
            source = "extra"

        # Re-read using the selected source because the user may have
        # changed the automatic application selection.
        try:
            df = load_data(item["path"])
            versions = extract_application_versions(df, source)
        except Exception:
            versions = item.get("versions", [])

        for version in versions:
            if version not in catalog[source]:
                catalog[source].append(version)

    for source in catalog:
        catalog[source].sort(key=version_sort_key)

    return catalog


def choose_data_frames(inspected, assignments):
    data_frames = {
        "intune": pd.DataFrame(),
        "edr": pd.DataFrame(),
        "av": pd.DataFrame(),
        "dlp": pd.DataFrame(),
        "bigfix": pd.DataFrame(),
        "cmdb": pd.DataFrame(),
        "zscaler": pd.DataFrame()
    }

    extra_dfs = []

    for item in inspected:
        source = assignments.get(
            item["id"],
            item["detected_source"]
        )

        df = load_data(item["path"])
        if df.empty:
            continue

        if source in data_frames:
            if data_frames[source].empty:
                data_frames[source] = df.copy()
            else:
                data_frames[source] = pd.concat(
                    [data_frames[source], df],
                    ignore_index=True,
                    sort=False
                )
        else:
            extra_dfs.append(df)

    return data_frames, extra_dfs


def build_registry(data_frames, extra_dfs):
    """
    This is the core two-pass registry logic from the supplied script:
    1. Build host -> serial mapping.
    2. Resolve each source row to a global serial/host key.
    3. Build tool presence, user and entity data.
    4. Perform inverted HR matching.
    """
    host_to_serial = {}

    all_dfs = {
        **data_frames,
        **{f"extra_{i}": df for i, df in enumerate(extra_dfs)}
    }

    for tool_name, df in all_dfs.items():
        if df.empty:
            continue

        c_host = find_col(
            df,
            ["Computer Name", "deviceName", "DeviceName", "Hostname", "Name"]
        )
        c_serial = find_col(
            df,
            ["Serial No", "SerialNumber", "serialNumber", "OEM Serial No."]
        )

        df["Clean_Host"] = (
            df[c_host].apply(clean_hostname)
            if c_host
            else np.nan
        )

        def extract_serial(row):
            s = get_val(c_serial, row)

            if tool_name == "cmdb":
                udid_col = find_col(df, ["UDID"])
                if udid_col:
                    u = get_val(udid_col, row)
                    if u and ":" in u:
                        s = u.split(":")[0].strip()
                    elif u:
                        s = u.strip()

            if s and str(s).lower() not in ["nan", ""]:
                return str(s).upper()

            return np.nan

        df["Raw_Serial"] = df.apply(
            extract_serial,
            axis=1
        )

        for _, row in df.dropna(
            subset=["Raw_Serial", "Clean_Host"]
        ).iterrows():
            host_to_serial[row["Clean_Host"]] = row["Raw_Serial"]

    global_registry = {}
    tool_presence = {k: set() for k in data_frames.keys()}

    for tool_name, df in all_dfs.items():
        if df.empty or "Clean_Host" not in df.columns:
            continue

        df["Resolved_Key"] = df.apply(
            lambda r:
            r["Raw_Serial"]
            if pd.notna(r["Raw_Serial"])
            else host_to_serial.get(
                r["Clean_Host"],
                r["Clean_Host"]
            ),
            axis=1
        )

        if tool_name in tool_presence:
            tool_presence[tool_name].update(
                df["Resolved_Key"].dropna()
            )

        c_user = find_col(
            df,
            ["User Name", "userPrincipalName", "User",
             "Logged-in Users", "Email"]
        )
        c_full = find_col(
            df,
            ["Full User Name", "Name"]
        )
        c_entity = find_col(
            df,
            ["Entity", "Company Name", "Company"]
        )

        c_date = find_col(
            df,
            TOOL_META_COLS.get(tool_name, {}).get("date", [])
        )
        c_ver = find_col(
            df,
            TOOL_META_COLS.get(tool_name, {}).get("ver", [])
        )

        records = df.dropna(
            subset=["Resolved_Key"]
        ).to_dict("records")

        for row in records:
            m_key = row["Resolved_Key"]

            if m_key not in global_registry:
                global_registry[m_key] = {
                    "hostname": row["Clean_Host"],
                    "email": np.nan,
                    "user_id": np.nan,
                    "full_name": np.nan,
                    "serial": np.nan,
                    "entity": np.nan,
                    "tools": {},
                    "hr": {}
                }

            if pd.notna(row["Raw_Serial"]):
                global_registry[m_key]["serial"] = row["Raw_Serial"]
            elif m_key in host_to_serial.values():
                global_registry[m_key]["serial"] = m_key

            e_val = get_val(c_entity, row)
            if (
                e_val
                and pd.isna(global_registry[m_key]["entity"])
            ):
                global_registry[m_key]["entity"] = normalize_entity(
                    e_val
                )

            if tool_name in data_frames:
                d_val = format_date(
                    get_val(c_date, row)
                )

                # Preserve latest record seen for this source.
                global_registry[m_key]["tools"][tool_name] = {
                    "date": d_val or "14-07-2026",
                    "ver": get_val(c_ver, row)
                }

            u_val = get_val(c_user, row)
            if u_val:
                if (
                    "@" in u_val
                    and pd.isna(global_registry[m_key]["email"])
                ):
                    global_registry[m_key]["email"] = u_val
                elif pd.isna(
                    global_registry[m_key]["user_id"]
                ):
                    global_registry[m_key]["user_id"] = clean_user_id(
                        u_val
                    )

            f_val = get_val(c_full, row)
            if (
                f_val
                and pd.isna(global_registry[m_key]["full_name"])
            ):
                global_registry[m_key]["full_name"] = f_val

    # Advanced VLOOKUP-style inverted index.
    lookup_to_key = {}

    for m_key, info in global_registry.items():
        if pd.notna(info.get("email")):
            lookup_to_key[
                str(info["email"]).strip().lower()
            ] = m_key

        if pd.notna(info.get("user_id")):
            lookup_to_key[
                str(info["user_id"]).strip().lower()
            ] = m_key

        if pd.notna(info.get("full_name")):
            lookup_to_key[
                clean_name(info["full_name"])
            ] = m_key

        if pd.notna(info.get("serial")):
            lookup_to_key[
                str(info["serial"]).strip().lower()
            ] = m_key

        lookup_to_key[
            str(m_key).strip().lower()
        ] = m_key

    hr_profiles = {}

    for df_extra in extra_dfs:
        c_email = find_col(
            df_extra,
            ["Email", "Email Address", "Mail", "Email ID"]
        )
        c_userid = find_col(
            df_extra,
            ["User ID", "User Name", "UserID", "Username",
             "Login ID", "SamAccountName"]
        )
        c_name = find_col(
            df_extra,
            ["Name", "Full Name", "Full User Name",
             "Employee Name", "Display Name"]
        )
        c_serial_ex = find_col(
            df_extra,
            ["Serial No", "SerialNumber",
             "serialNumber", "OEM Serial No."]
        )

        found_hr_cols = {}

        for hf in HR_FIELDS:
            ch = find_col(df_extra, [hf])
            if ch:
                found_hr_cols[hf] = ch

        if not found_hr_cols:
            continue

        for row in df_extra.to_dict("records"):
            e = (
                get_val(c_email, row).strip().lower()
                if c_email else ""
            )
            u = (
                clean_user_id(
                    get_val(c_userid, row)
                ).strip().lower()
                if c_userid else ""
            )
            n = (
                clean_name(get_val(c_name, row))
                if c_name else ""
            )
            s = (
                get_val(c_serial_ex, row).strip().lower()
                if c_serial_ex else ""
            )

            target_key = None

            if s and s in lookup_to_key:
                target_key = lookup_to_key[s]
            elif e and e in lookup_to_key:
                target_key = lookup_to_key[e]
            elif u and u in lookup_to_key:
                target_key = lookup_to_key[u]
            elif n and n in lookup_to_key:
                target_key = lookup_to_key[n]

            if target_key:
                profile = {
                    hf: get_val(c, row)
                    for hf, c in found_hr_cols.items()
                }

                if target_key not in hr_profiles:
                    hr_profiles[target_key] = {}

                hr_profiles[target_key].update(profile)

    for m_key in global_registry:
        global_registry[m_key]["hr"] = hr_profiles.get(
            m_key,
            {}
        )

    return global_registry, tool_presence


def tool_status(
    key,
    tool,
    registry,
    tool_presence,
    minimum_versions
):
    if key not in tool_presence[tool]:
        return "Not Reported"

    if tool in minimum_versions:
        actual = (
            registry
            .get(key, {})
            .get("tools", {})
            .get(tool, {})
            .get("ver", "")
        )

        if version_is_below(
            actual,
            minimum_versions[tool]
        ):
            return "Not Compliant"

    return "Reported"


def generate_remark(
    key,
    tool,
    label,
    registry,
    tool_presence,
    minimum_versions
):
    if key not in tool_presence[tool]:
        return "Not Reported"

    info = registry.get(key, {})

    ent_str = (
        info.get("entity")
        if pd.notna(info.get("entity"))
        else "NSEIL"
    )

    t_info = info.get("tools", {}).get(tool, {})
    dt = t_info.get("date", "14-07-2026")
    ver = t_info.get("ver", "")

    if tool in minimum_versions:
        minimum = minimum_versions[tool]

        if version_is_below(
            ver,
            minimum
        ):
            return (
                f"Reported {label} version "
                f"{ver or 'N/A'} below minimum "
                f"{minimum} in {ent_str} "
                f"{label} Inv {dt}"
            )

    if label == "DLP":
        return (
            f"Reported latest DLP "
            f"{ver if ver else '25*'} Ver in "
            f"{ent_str} DLP Inv {dt}"
        )

    if label == "Zscaler":
        return (
            f"Reported latest Zscaler "
            f"{ver if ver else '4.8*'} Ver in "
            f"{ent_str} Zscaler Inv {dt}"
        )

    if label == "Bitlocker":
        return (
            f"Reported Fully Encrypted Bitlocker "
            f"in {ent_str} Bigfix Inv {dt}"
        )

    return f"Reported in {ent_str} {label} Inv {dt}"


def build_output(
    tool_name,
    target_headers,
    data_frames,
    registry,
    tool_presence,
    minimum_versions
):
    df = data_frames[tool_name]

    out_df = (
        df.reindex(columns=target_headers).copy()
        if not df.empty
        else pd.DataFrame(columns=target_headers)
    )

    if out_df.empty or "Resolved_Key" not in df.columns:
        return out_df

    match_col = df["Resolved_Key"]

    mapping_rules = {
        "Intune": "intune",
        "EDR": "edr",
        "AV": "av",
        "CMDB": "cmdb",
        "Bigfix": "bigfix",
        "DLP": "dlp",
        "Zscaler": "zscaler"
    }

    for label, key in mapping_rules.items():
        status_col = f"{label} Status"
        remark_col = f"{label} Remark"

        if status_col in out_df.columns:
            out_df[status_col] = match_col.map(
                lambda x:
                tool_status(
                    x,
                    key,
                    registry,
                    tool_presence,
                    minimum_versions
                )
            )

        if remark_col in out_df.columns:
            out_df[remark_col] = match_col.map(
                lambda x:
                generate_remark(
                    x,
                    key,
                    label,
                    registry,
                    tool_presence,
                    minimum_versions
                )
            )

    if "Bitlocker Status" in out_df.columns:
        out_df["Bitlocker Status"] = match_col.map(
            lambda x:
            "Encrypted"
            if x in tool_presence["bigfix"]
            else "Not Reported"
        )

    if "Bitlocker Remark" in out_df.columns:
        out_df["Bitlocker Remark"] = match_col.map(
            lambda x:
            generate_remark(
                x,
                "bigfix",
                "Bitlocker",
                registry,
                tool_presence,
                minimum_versions
            )
        )

    static_fills = {
        "Asset Status": "In Use",
        "Operational status": "Operational",
        "Encryption State": "Fully Encrypted",
        "Add Remark": ""
    }

    for col, val in static_fills.items():
        if col in out_df.columns:
            out_df[col] = val

    if "Ageing" in out_df.columns:
        c_date = find_col(
            df,
            TOOL_META_COLS[tool_name]["date"]
        )

        if c_date:
            out_df["Ageing"] = (
                df[c_date]
                .apply(calculate_ageing)
                .astype("Int64")
            )

            out_df["Ageing state"] = out_df["Ageing"].apply(
                lambda x:
                "Active"
                if pd.notna(x) and x < 15
                else (
                    "Inactive"
                    if pd.notna(x)
                    else ""
                )
            )
        else:
            out_df["Ageing"] = pd.NA
            out_df["Ageing state"] = ""

    if "Bigfix Online State" in out_df.columns:
        if "Ageing" in out_df.columns:
            out_df["Bigfix Online State"] = out_df["Ageing"].apply(
                lambda x:
                "Online"
                if pd.notna(x) and x < 7
                else (
                    "Offline"
                    if pd.notna(x)
                    else ""
                )
            )
        else:
            out_df["Bigfix Online State"] = ""

    if "Entity" in out_df.columns:
        out_df["Entity"] = match_col.map(
            lambda x:
            registry.get(x, {}).get("entity")
        ).fillna("NSEIL")

    if (
        "Sequence no" in out_df.columns
        and "Entity" in out_df.columns
    ):
        out_df["Sequence no"] = (
            out_df["Entity"]
            .map(ENTITY_SEQ_MAP)
            .fillna(1)
            .astype(int)
        )

    # Dynamic identity and HR mapping.
    for col in out_df.columns:
        base_col = col.split(".")[0]

        if base_col == "Email" and col == "Email":
            out_df[col] = match_col.map(
                lambda x:
                registry.get(x, {}).get("email", np.nan)
            )

        elif base_col in [
            "Serial No", "OEM Serial No", "serialNumber"
        ]:
            out_df[col] = match_col.map(
                lambda x:
                registry.get(x, {}).get("serial", np.nan)
            )

        elif base_col in ["Full User Name", "Name"]:
            out_df[col] = match_col.map(
                lambda x:
                registry.get(x, {}).get("full_name", np.nan)
            )

        elif base_col in [
            "User Name", "User ID",
            "userPrincipalName", "Logged-in Users"
        ]:
            if base_col == "User ID" and col != "User ID":
                continue

            out_df[col] = match_col.map(
                lambda x:
                registry.get(x, {}).get("user_id")
                or registry.get(x, {}).get("email", np.nan)
            )

        elif base_col in HR_FIELDS:
            out_df[col] = match_col.map(
                lambda x:
                registry.get(x, {})
                .get("hr", {})
                .get(base_col, np.nan)
            )

    device_cols = {
        "intune": "deviceName",
        "edr": "DeviceName",
        "av": "DeviceName",
        "dlp": "Hostname",
        "bigfix": "Computer Name",
        "cmdb": "Name",
        "zscaler": "Hostname"
    }

    primary_col = device_cols[tool_name]

    if primary_col in out_df.columns:
        out_df[primary_col] = match_col.map(
            lambda x:
            registry.get(x, {}).get("hostname", x)
        )

    if tool_name == "bigfix":
        if "Action" in out_df.columns:
            actions = pd.Series(
                [""] * len(out_df),
                index=out_df.index
            )

            def add_missing(
                col_name,
                flag_string,
                app_name
            ):
                if col_name not in out_df.columns:
                    return

                mask = out_df[col_name].astype(str).str.contains(
                    flag_string,
                    na=False,
                    regex=True
                )

                actions[mask] += app_name + ", "

            add_missing(
                "Intune Status",
                "Not Reported|Not Compliant",
                "Intune"
            )
            add_missing(
                "EDR Status",
                "Not Reported|Not Compliant",
                "EDR"
            )
            add_missing(
                "AV Status",
                "Not Reported|Not Compliant",
                "AV"
            )
            add_missing(
                "Bitlocker Status",
                "Not Reported|Decrypted",
                "Bitlocker"
            )
            add_missing(
                "DLP Status",
                "Not Reported|Not Compliant",
                "DLP"
            )
            add_missing(
                "CMDB Status",
                "Not Reported|Not Compliant",
                "CMDB"
            )
            add_missing(
                "Zscaler Status",
                "Not Reported|Not Compliant",
                "Zscaler"
            )

            out_df["Action"] = actions.str.rstrip(", ")

        if "Compliance Status" in out_df.columns:
            status_columns = [
                "Intune Status",
                "EDR Status",
                "AV Status",
                "Bitlocker Status",
                "DLP Status",
                "CMDB Status",
                "Zscaler Status"
            ]

            out_df["Compliance Status"] = out_df.apply(
                lambda row:
                "NON-COMPLIANT"
                if any(
                    str(row.get(column, "")).upper()
                    in {
                        "NOT REPORTED",
                        "NOT COMPLIANT",
                        "DECRYPTED"
                    }
                    for column in status_columns
                )
                else "COMPLIANT",
                axis=1
            )

    return out_df


def process_data(
    inspected,
    assignments,
    minimum_versions
):
    data_frames, extra_dfs = choose_data_frames(
        inspected,
        assignments
    )

    registry, tool_presence = build_registry(
        data_frames,
        extra_dfs
    )

    outputs = {}

    for tool in data_frames:
        outputs[tool] = build_output(
            tool,
            HEADERS[tool],
            data_frames,
            registry,
            tool_presence,
            minimum_versions
        )

    summary = build_summary(
        registry,
        tool_presence,
        minimum_versions
    )

    return outputs, summary


def build_summary(
    registry,
    tool_presence,
    minimum_versions
):
    total = len(registry)
    compliant = 0
    non_compliant = 0

    missing = {
        tool: 0
        for tool in tool_presence
    }

    version_failures = {
        tool: 0
        for tool in minimum_versions
    }

    for key in registry:
        failed = False

        for tool in tool_presence:
            if key not in tool_presence[tool]:
                missing[tool] += 1
                failed = True

        for tool, minimum in minimum_versions.items():
            if key not in tool_presence[tool]:
                continue

            actual = (
                registry
                .get(key, {})
                .get("tools", {})
                .get(tool, {})
                .get("ver", "")
            )

            if version_is_below(actual, minimum):
                version_failures[tool] += 1
                failed = True

        if failed:
            non_compliant += 1
        else:
            compliant += 1

    active_sources = sum(
        1 for tool in tool_presence if tool_presence[tool]
    )

    return {
        "total": total,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "missing": missing,
        "version_failures": version_failures,
        "active_sources": active_sources,
    }


def build_chart_data(summary):
    coverage = {}

    for tool, missing in summary["missing"].items():
        coverage[tool.upper()] = max(
            summary["total"] - missing,
            0
        )

    return {
        "compliance": {
            "Compliant": summary["compliant"],
            "Non-Compliant": summary["non_compliant"]
        },
        "coverage": coverage,
        "version_failures": {
            tool.upper(): count
            for tool, count in summary["version_failures"].items()
        }
    }


def export_excel(outputs, output_path):
    with pd.ExcelWriter(
        output_path,
        engine="openpyxl"
    ) as writer:

        for tool in [
            "bigfix", "intune", "edr",
            "av", "dlp", "cmdb", "zscaler"
        ]:
            df = outputs.get(
                tool,
                pd.DataFrame(columns=HEADERS[tool])
            ).copy()

            if tool == "cmdb":
                df.columns = [
                    str(column).split(".")[0]
                    for column in df.columns
                ]

            df.to_excel(
                writer,
                sheet_name=tool.capitalize(),
                index=False
            )

    return output_path
