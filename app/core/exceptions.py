# app/core/exceptions.py

from fastapi import HTTPException, status
from typing import Any, Dict, Optional

class APIException(HTTPException):
    """
    Base custom exception for API errors.
    Inherits from HTTPException for FastAPI compatibility.
    """
    def __init__(
        self, 
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        message: str = "An unexpected error occurred.", 
        name: str = "Internal Server Error",
        headers: Optional[Dict[str, Any]] = None
    ):
        self.status_code = status_code
        self.message = message # Custom attribute for a more descriptive message
        self.name = name     # Custom attribute for a user-friendly error name
        super().__init__(status_code=status_code, detail=message, headers=headers)

class unauthorized(APIException):
    """
    Exception for unauthorized access (401).
    """
    def __init__(self, message: str = "Authentication required or invalid credentials."):
        super().__init__(status.HTTP_401_UNAUTHORIZED, message, "Unauthorized")

class forbidden(APIException):
    """
    Exception for forbidden access (403).
    """
    def __init__(self, message: str = "You do not have permission to access this resource."):
        super().__init__(status.HTTP_403_FORBIDDEN, message, "Forbidden")

class not_found(APIException):
    """
    Exception for resource not found (404).
    """
    def __init__(self, message: str = "Resource not found."):
        super().__init__(status.HTTP_404_NOT_FOUND, message, "Not Found")

class conflict(APIException):
    """
    Exception for a conflict, typically a resource already existing (409).
    """
    def __init__(self, message: str = "Resource already exists."):
        super().__init__(status.HTTP_409_CONFLICT, message, "Conflict")

class bad_request(APIException):
    """
    Exception for a bad request (400).
    """
    def __init__(self, message: str = "Bad request."):
        super().__init__(status.HTTP_400_BAD_REQUEST, message, "Bad Request")

class server_error(APIException):
    """
    Exception for internal server error (500).
    """
    def __init__(self, message: str = "An internal server error occurred."):
        super().__init__(status.HTTP_500_INTERNAL_SERVER_ERROR, message, "Internal Server Error")
