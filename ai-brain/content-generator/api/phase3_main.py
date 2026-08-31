from __future__ import annotations

from api.main import app
from api.routes.intent_classification import router as intent_classification_router


app.include_router(intent_classification_router)
