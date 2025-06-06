from enum import StrEnum, auto
from typing import Optional

from pydantic import BaseModel, Field


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


# Courses Schemas
class CourseBase(BaseModel):
    """Base class for Course schema."""

    subject: str = Field(max_length=4)
    number: int
    title: str = Field(max_length=50)
    term: str = Field(max_length=10)
    instructor_id: int


class CourseCreateRequest(CourseBase):
    """Schema for creating a course."""

    pass


class CourseResponse(CourseBase):
    """Schema for course response."""

    id: int
    self: str


class CourseListResponse(BaseModel):
    """Schema for paginated course list responses."""

    courses: list[CourseResponse]
    next: Optional[str] = None


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


# Helper functions for user entities
def user_entity_to_response(user, user_id, avatar_url=None, courses=None):
    """Converts a Datastore user entity to a UserResponse schema.

    :param user: The user entity from Datastore.
    :param user_id: The unique identifier for the user.
    :return: UserResponse schema with all fields.
    """
    return UserResponse(
        id=user_id,
        role=user["role"],
        sub=user["sub"],
        courses=courses,
        avatar_url=avatar_url,
    )


# Helpter functions for course entities
def course_entity_to_response(course, course_id, self_url):
    """Convert a Datastore course entity to a CourseResponse schema."""
    return CourseResponse(
        id=course_id,
        subject=course["subject"],
        number=course["number"],
        title=course["title"],
        term=course["term"],
        instructor_id=course["instructor_id"],
        self=self_url,
    )
