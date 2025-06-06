from enum import StrEnum, auto
from typing import Optional

from pydantic import BaseModel


class UserRole(StrEnum):
    """Enum for user roles."""

    ADMIN = auto()
    INSTRUCTOR = auto()
    STUDENT = auto()


# Login Schema
class LoginRequest(BaseModel):
    """Schema for login request body validation."""

    username: str
    password: str


# User Schemas
class UserBase(BaseModel):
    """Base class for User schema with common fields."""

    role: UserRole
    sub: str

    class Config:
        use_enum_values = True


class UserListResponse(UserBase):
    """Schema for user list responses. Minimal fields for admin list
    view.
    """

    id: int


class UserResponse(UserBase):
    """Schema for full user responses. Includes all fields
    conditionally.
    """

    id: int
    courses: Optional[list[str]] = None
    avatar_url: Optional[str] = None


# Avatar Schema
class AvatarCreateResponse(BaseModel):
    """Schema for avatar creation/update response."""

    avatar_url: str


# Error Schema
class ErrorResponse(BaseModel):
    """Model for error responses."""

    Error: str


# ERROR MESSAGES
BAD_REQUEST_ERROR = ErrorResponse(Error="The request body is invalid")
UNAUTHORIZED_ERROR = ErrorResponse(Error="Unauthorized")
FORBIDDEN_ERROR = ErrorResponse(
    Error="You don't have permission on this resource"
)
NOT_FOUND_ERROR = ErrorResponse(Error="Not found")

# CONSTANTS
ROLES_WITH_COURSES = [UserRole.INSTRUCTOR.value, UserRole.STUDENT.value]


# Helper functions for user entities
def user_entity_to_list_response(user, user_id):
    """Convert a Datastore user entity to a UserListResponse schema.

    :param user: The user entity from Datastore.
    :param user_id: The unique identifier for the user.
    :return: UserListResponse schema with minimal fields.
    """
    return UserListResponse(id=user_id, role=user["role"], sub=user["sub"])


def user_entity_to_response(user, user_id):
    """Converts a Datastore user entity to a UserResponse schema.

    :param user: The user entity from Datastore.
    :param user_id: The unique identifier for the user.
    :return: UserResponse schema with all fields.
    """
    courses = None
    if user["role"] in ROLES_WITH_COURSES:
        courses = user.get("courses", [])

    return UserResponse(
        id=user_id,
        role=user["role"],
        sub=user["sub"],
        courses=courses,
        avatar_url=user.get("avatar_url"),
    )
