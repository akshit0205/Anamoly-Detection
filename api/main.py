import logging
import os

import boto3
from fastapi import FastAPI
from fastapi import Security, HTTPException
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from alerts.alert_dispatcher import dispatch_alerts
from detection.pipeline import run_detection
from storage.dynamodb_store import get_user, list_users, save_user


logger = logging.getLogger(__name__)
app = FastAPI()
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "dev-secret-key")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return key


def _storage_region() -> str:
    region = boto3.session.Session().region_name
    if not region:
        raise RuntimeError('DynamoDB region is not configured in AWS session')
    return region


class RegisterRequest(BaseModel):
    account_id: str
    role_arn: str
    region: str
    cloudtrail_bucket: str
    output_bucket: str
    email: str


@app.post('/register')
def register_user(payload: RegisterRequest):
    try:
        user_data = payload.model_dump()
        saved = save_user(user_data, _storage_region())
        if not saved:
            logger.error('Failed to save user account_id=%s', payload.account_id)
            return JSONResponse(status_code=500, content={'error': 'Internal server error'})

        return {'status': 'registered', 'account_id': payload.account_id}
    except ValueError as exc:
        logger.error('Validation error in /register: %s', exc)
        return JSONResponse(status_code=400, content={'error': str(exc)})
    except Exception:
        logger.exception('Unexpected error in /register')
        return JSONResponse(status_code=500, content={'error': 'Internal server error'})


@app.get('/users')
def get_users():
    try:
        users = list_users(_storage_region())
        return {'users': users}
    except Exception:
        logger.exception('Unexpected error in /users')
        return JSONResponse(status_code=500, content={'error': 'Internal server error'})


@app.get('/health')
def health_check():
    return {'status': 'ok'}


@app.get("/rules/count")
async def get_rules_count(api_key: str = Security(verify_api_key)):
    from detection.pipeline import _is_sensitive_api
    import inspect
    # Count items in the sensitive list inside _is_sensitive_api
    source = inspect.getsource(_is_sensitive_api)
    count = source.count("'")
    # Each event name has 2 quotes, divide by 2
    return {"count": count // 2}


@app.post('/run/{account_id}')
async def run_for_user(account_id: str, api_key: str = Security(verify_api_key)):
    try:
        user = get_user(account_id, _storage_region())
        if not user:
            return JSONResponse(status_code=404, content={'error': 'User not found'})

        sender_email = os.environ.get('SENDER_EMAIL')
        if not sender_email:
            logger.error('SENDER_EMAIL environment variable is not set')
            return JSONResponse(status_code=500, content={'error': 'Internal server error'})

        anomalies = run_detection(user)
        dispatch_alerts(anomalies, user, sender_email)

        return {
            "account_id": account_id,
            "anomalies_found": len(anomalies),
            "anomalies": anomalies
        }
    except Exception:
        logger.exception('Unexpected error in /run/%s', account_id)
        return JSONResponse(status_code=500, content={'error': 'Internal server error'})
