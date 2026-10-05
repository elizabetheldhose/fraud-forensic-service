"""
Fraud Forensic Investigator - Ingestion Lambda
================================================

S3 ObjectCreated  ->  download (SSE-KMS, decrypted transparently by S3)
                  ->  strict PII masking (cards, SSN, Aadhaar, PAN)
                  ->  fail-closed residual PII scan
                  ->  chunk
                  ->  Amazon Titan Text Embeddings V2 (Bedrock)
                  ->  bulk index into OpenSearch Serverless (VECTORSEARCH collection)

Runtime: Python 3.12
Dependencies (Lambda layer or bundled): opensearch-py>=2.4   (boto3 is in the runtime)

Environment variables
---------------------
AOSS_ENDPOINT          Collection endpoint, e.g. abc123xyz.us-east-1.aoss.amazonaws.com (no scheme)
AOSS_INDEX             Index name (default: fraud-transaction-logs)
BEDROCK_MODEL_ID       Default: amazon.titan-embed-text-v2:0
EMBEDDING_DIMENSIONS   256 | 512 | 1024 (default: 1024) - must match the index mapping
CHUNK_MAX_CHARS        Max characters per chunk (default: 6000; Titan V2 caps input at 8,192 tokens)
CHUNK_OVERLAP_LINES    Lines repeated between consecutive chunks (default: 2)
MAX_OBJECT_BYTES       Reject objects larger than this (default: 50 MiB)
CARD_KEEP_LAST4        "true" keeps last 4 card digits for investigator correlation (PCI DSS permits) - default true
LOG_LEVEL              Default: INFO
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Iterator

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection, helpers

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

REGION = os.environ.get("AWS_REGION", "us-east-1")
AOSS_ENDPOINT = os.environ["AOSS_ENDPOINT"].replace("https://", "").rstrip("/")
AOSS_INDEX = os.environ.get("AOSS_INDEX", "fraud-transaction-logs")
BEDROCK_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "amazon.titan-embed-text-v2:0")
EMBEDDING_DIMENSIONS = int(os.environ.get("EMBEDDING_DIMENSIONS", "1024"))
CHUNK_MAX_CHARS = int(os.environ.get("CHUNK_MAX_CHARS", "6000"))
CHUNK_OVERLAP_LINES = int(os.environ.get("CHUNK_OVERLAP_LINES", "2"))
MAX_OBJECT_BYTES = int(os.environ.get("MAX_OBJECT_BYTES", str(50 * 1024 * 1024)))
CARD_KEEP_LAST4 = os.environ.get("CARD_KEEP_LAST4", "true").lower() == "true"

if EMBEDDING_DIMENSIONS not in (256, 512, 1024):
    raise ValueError("EMBEDDING_DIMENSIONS must be 256, 512 or 1024 for Titan Text Embeddings V2")

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# --------------------------------------------------------------------------------------
# Clients - created once per execution environment and reused across invocations
# --------------------------------------------------------------------------------------

_retry_cfg = Config(retries={"max_attempts": 8, "mode": "adaptive"}, connect_timeout=5, read_timeout=60)

_session = boto3.Session(region_name=REGION)
s3 = _session.client("s3", config=_retry_cfg)
bedrock = _session.client("bedrock-runtime", config=_retry_cfg)

aoss = OpenSearch(
    hosts=[{"host": AOSS_ENDPOINT, "port": 443}],
    http_auth=AWSV4SignerAuth(_session.get_credentials(), REGION, "aoss"),
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection,
    pool_maxsize=10,
    timeout=60,
)

_index_ready = False


# --------------------------------------------------------------------------------------
# PII masking
# --------------------------------------------------------------------------------------

class PIIMaskingError(Exception):
    """Raised when PII survives masking. The pipeline fails closed - nothing is sent downstream."""


def _luhn_valid(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Verhoeff tables (Aadhaar check digit)
_VH_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VH_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VH_D[c][_VH_P[i % 8][ord(ch) - 48]]
    return c == 0


# Card: 13-19 digits, optionally grouped by single spaces or hyphens, not embedded in a longer number.
_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")

# SSN, formatted: excludes area 000/666/9xx, group 00, serial 0000 (SSA rules).
_SSN_FMT_RE = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?!\d)")

# SSN, unformatted 9 digits - only when a keyword is nearby, to avoid masking order IDs / amounts.
_SSN_CTX_RE = re.compile(
    r"(?i)\b(ssn|social[\s_-]*security(?:[\s_-]*(?:no|number|#))?|tax[\s_-]*id|tin)\b"
    r"([\"'\s:=#-]{0,6})"
    r"(?!000|666|9\d\d)(\d{3})(?!00)(\d{2})(?!0000)(\d{4})(?!\d)"
)

# Aadhaar: 12 digits, first digit 2-9, optionally grouped 4-4-4; validated with Verhoeff.
_AADHAAR_RE = re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])")

# PAN (Indian tax ID): 5 letters, 4 digits, 1 letter; 4th char encodes holder type.
_PAN_RE = re.compile(r"\b[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z]\b")


def _mask_card(m: re.Match) -> str:
    raw = m.group(0)
    digits = re.sub(r"\D", "", raw)
    if not (13 <= len(digits) <= 19) or not _luhn_valid(digits):
        return raw  # not a card - leave untouched (amounts, IDs, timestamps)
    return f"[CARD:****{digits[-4:]}]" if CARD_KEEP_LAST4 else "[CARD_REDACTED]"


def _mask_aadhaar(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    return "[NATIONAL_ID_REDACTED]" if _verhoeff_valid(digits) else m.group(0)


@dataclass
class MaskResult:
    text: str
    counts: dict


def mask_pii(text: str) -> MaskResult:
    """
    Order matters: cards first (longest numeric spans), then Aadhaar, then SSN,
    so a shorter pattern never partially consumes a longer identifier.
    """
    counts = {}
    out = text

    before = out
    out = _CARD_RE.sub(_mask_card, out)
    counts["card"] = len(re.findall(r"\[CARD", out)) - len(re.findall(r"\[CARD", before))

    before = out
    out = _AADHAAR_RE.sub(_mask_aadhaar, out)
    counts["aadhaar"] = out.count("[NATIONAL_ID_REDACTED]") - before.count("[NATIONAL_ID_REDACTED]")

    out, n_fmt = _SSN_FMT_RE.subn("[SSN_REDACTED]", out)
    out, n_ctx = _SSN_CTX_RE.subn(lambda m: f"{m.group(1)}{m.group(2)}[SSN_REDACTED]", out)
    counts["ssn"] = n_fmt + n_ctx

    out, counts["pan"] = _PAN_RE.subn("[PAN_REDACTED]", out)

    return MaskResult(text=out, counts=counts)


def assert_no_residual_pii(text: str) -> None:
    """Independent second pass. If anything still matches, fail closed."""
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_valid(digits):
            raise PIIMaskingError("Residual card number detected after masking")
    for m in _AADHAAR_RE.finditer(text):
        if _verhoeff_valid(re.sub(r"\D", "", m.group(0))):
            raise PIIMaskingError("Residual national ID detected after masking")
    if _SSN_FMT_RE.search(text) or _SSN_CTX_RE.search(text):
        raise PIIMaskingError("Residual SSN detected after masking")
    if _PAN_RE.search(text):
        raise PIIMaskingError("Residual PAN detected after masking")


# --------------------------------------------------------------------------------------
# Chunking
# --------------------------------------------------------------------------------------

def chunk_lines(text: str, max_chars: int, overlap_lines: int) -> Iterator[str]:
    """
    Line-aware chunking so a single log record is never split mid-line
    (unless one line alone exceeds max_chars, in which case it is hard-split).
    """
    buf: list[str] = []
    size = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        while len(line) > max_chars:  # pathological single line
            if buf:
                yield "\n".join(buf)
                buf, size = [], 0
            yield line[:max_chars]
            line = line[max_chars:]
        if size + len(line) + 1 > max_chars and buf:
            yield "\n".join(buf)
            buf = buf[-overlap_lines:] if overlap_lines else []
            size = sum(len(l) + 1 for l in buf)
        buf.append(line)
        size += len(line) + 1
    if buf:
        yield "\n".join(buf)


# --------------------------------------------------------------------------------------
# Bedrock embeddings
# --------------------------------------------------------------------------------------

def embed(text: str) -> list[float]:
    body = json.dumps({"inputText": text, "dimensions": EMBEDDING_DIMENSIONS, "normalize": True})
    resp = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=body,
        contentType="application/json",
        accept="application/json",
    )
    payload = json.loads(resp["body"].read())
    vector = payload["embedding"]
    if len(vector) != EMBEDDING_DIMENSIONS:
        raise ValueError(f"Unexpected embedding size {len(vector)}; expected {EMBEDDING_DIMENSIONS}")
    return vector


# --------------------------------------------------------------------------------------
# OpenSearch Serverless
# --------------------------------------------------------------------------------------

def ensure_index() -> None:
    global _index_ready
    if _index_ready:
        return
    if not aoss.indices.exists(index=AOSS_INDEX):
        try:
            aoss.indices.create(
                index=AOSS_INDEX,
                body={
                    "settings": {"index": {"knn": True}},
                    "mappings": {
                        "properties": {
                            "embedding": {
                                "type": "knn_vector",
                                "dimension": EMBEDDING_DIMENSIONS,
                                "method": {
                                    "name": "hnsw",
                                    "engine": "faiss",
                                    "space_type": "innerproduct",  # vectors are normalized -> cosine
                                    "parameters": {"ef_construction": 512, "m": 16},
                                },
                            },
                            "masked_text": {"type": "text"},
                            "chunk_id": {"type": "keyword"},
                            "chunk_index": {"type": "integer"},
                            "source_bucket": {"type": "keyword"},
                            "source_key": {"type": "keyword"},
                            "source_version_id": {"type": "keyword"},
                            "source_etag": {"type": "keyword"},
                            "pii_redactions": {"type": "object"},
                            "embedding_model": {"type": "keyword"},
                            "ingested_at": {"type": "date"},
                        }
                    },
                },
            )
            logger.info("Created index %s", AOSS_INDEX)
        except Exception as exc:  # concurrent cold starts may race on creation
            if "resource_already_exists_exception" not in str(exc):
                raise
    _index_ready = True


def bulk_index(docs: Iterable[dict]) -> None:
    # AOSS vector collections don't support refresh=true or custom _id on index;
    # chunk_id is stored as a field for dedupe/lookup instead.
    actions = ({"_index": AOSS_INDEX, "_source": d} for d in docs)
    success, errors = helpers.bulk(aoss, actions, chunk_size=50, max_retries=3, raise_on_error=False)
    if errors:
        # Log only the error metadata - never document bodies.
        logger.error("Bulk index had %d errors; first: %s", len(errors), json.dumps(errors[0])[:500])
        raise RuntimeError(f"OpenSearch bulk indexing failed for {len(errors)} document(s)")
    logger.info("Indexed %d chunk(s) into %s", success, AOSS_INDEX)


# --------------------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------------------

def download(bucket: str, key: str, version_id: str | None) -> tuple[str, dict]:
    """
    SSE-KMS objects are decrypted server-side by S3 when the caller has kms:Decrypt
    on the key - no client-side KMS call is needed.
    """
    params = {"Bucket": bucket, "Key": key}
    if version_id:
        params["VersionId"] = version_id

    head = s3.head_object(**params)
    size = head["ContentLength"]
    if size > MAX_OBJECT_BYTES:
        raise ValueError(f"Object s3://{bucket}/{key} is {size} bytes; limit is {MAX_OBJECT_BYTES}")
    if head.get("ServerSideEncryption") != "aws:kms":
        logger.warning("s3://%s/%s is not SSE-KMS encrypted (got %s)", bucket, key, head.get("ServerSideEncryption"))

    obj = s3.get_object(**params)
    raw = obj["Body"].read()
    text = raw.decode("utf-8", errors="replace")
    meta = {"etag": obj.get("ETag", "").strip('"'), "version_id": obj.get("VersionId") or version_id}
    return text, meta


# --------------------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------------------

def process_object(bucket: str, key: str, version_id: str | None) -> dict:
    started = time.monotonic()
    raw_text, meta = download(bucket, key, version_id)

    masked = mask_pii(raw_text)
    del raw_text  # drop the unmasked copy as early as possible
    assert_no_residual_pii(masked.text)  # fail closed

    ensure_index()
    ingested_at = datetime.now(timezone.utc).isoformat()
    source_ref = f"{bucket}/{key}#{meta['version_id'] or meta['etag']}"

    docs = []
    for i, chunk in enumerate(chunk_lines(masked.text, CHUNK_MAX_CHARS, CHUNK_OVERLAP_LINES)):
        docs.append(
            {
                "chunk_id": hashlib.sha256(f"{source_ref}:{i}".encode()).hexdigest(),
                "chunk_index": i,
                "masked_text": chunk,
                "embedding": embed(chunk),
                "source_bucket": bucket,
                "source_key": key,
                "source_version_id": meta["version_id"],
                "source_etag": meta["etag"],
                "pii_redactions": masked.counts,
                "embedding_model": BEDROCK_MODEL_ID,
                "ingested_at": ingested_at,
            }
        )

    if not docs:
        logger.info("s3://%s/%s contained no indexable content", bucket, key)
        return {"key": key, "chunks": 0}

    bulk_index(docs)
    result = {
        "key": key,
        "chunks": len(docs),
        "redactions": masked.counts,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }
    logger.info("Processed %s", json.dumps(result))
    return result


def lambda_handler(event, context):
    records = event.get("Records", [])
    if not records:
        logger.warning("Event contained no Records")
        return {"processed": 0}

    results, failures = [], []
    for record in records:
        if not record.get("eventName", "").startswith("ObjectCreated"):
            continue
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])  # keys arrive URL-encoded
        version_id = record["s3"]["object"].get("versionId")
        try:
            results.append(process_object(bucket, key, version_id))
        except PIIMaskingError as exc:
            # Do not retry - the content is the problem, not a transient fault. Route to review.
            logger.critical("PII guard tripped for s3://%s/%s: %s - object NOT indexed", bucket, key, exc)
            failures.append({"key": key, "error": "pii_guard", "retryable": False})
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            logger.error("AWS error for s3://%s/%s: %s", bucket, key, code)
            failures.append({"key": key, "error": code, "retryable": code not in ("AccessDenied", "NoSuchKey")})
        except Exception as exc:
            logger.exception("Failed processing s3://%s/%s", bucket, key)
            failures.append({"key": key, "error": type(exc).__name__, "retryable": True})

    if any(f["retryable"] for f in failures):
        # Async invocation: raising triggers Lambda's built-in retries, then the
        # on-failure destination / DLQ configured on the function.
        raise RuntimeError(f"{len(failures)} object(s) failed: {json.dumps(failures)}")

    return {"processed": len(results), "results": results, "non_retryable_failures": failures}