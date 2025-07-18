"""
API Package for Authentication APP

This contains all API-related component:
- Router: It contains all the endpoints for Authentication
- v1: The endpoints are related to v1

"""

from .router import api_router

__all__ = ["api_router"]


