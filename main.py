"""
Author: Velislav Babatchev
Date: 06/05/2025

Description: This is a Flask application that provides endpoints for
user authentication, course management, and avatar handling. It uses
Google Cloud Datastore for data storage and Google Cloud Storage for
avatar image storage. The application supports JWT-based authentication
and includes endpoints for creating, retrieving, updating, and deleting
users, courses, and avatars. It also allows for user enrollment in
courses and provides functionality for instructors to manage their
courses and enrolled students.
"""

import io
import json
import os
import requests

from enum import Enum
from secrets import token_urlsafe

from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file, url_for
from google.cloud import datastore, storage
from jose import jwt
from pydantic import ValidationError
from six.moves.urllib.request import urlopen

from schemas import (
    BAD_REQUEST_ERROR,
    ENROLLMENT_ERROR,
    FORBIDDEN_ERROR,
    NOT_FOUND_ERROR,
    UNAUTHORIZED_ERROR,
    AvatarCreateResponse,
    CourseCreateRequest,
    CourseListResponse,
    CourseUpdateRequest,
    EnrollmentUpdateRequest,
    LoginRequest,
    UserRole,
    course_entity_to_response,
    user_entity_to_response,
)

# CONSTANTS
ALGORITHMS = ["RS256"]
AVATAR_BUCKET = "a6-babatchv-bucket"
AVATAR_FILENAME_PREFIX = "avatar_"
AVATAR_FILENAME_EXTENSION = ".png"
COURSES = "courses"
ENROLLMENTS = "enrollments"
USERS = "users"


class StatusCode(Enum):
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409


app = Flask(__name__)
app.secret_key = token_urlsafe(32)

client = datastore.Client()

load_dotenv()
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
DOMAIN = os.environ.get("DOMAIN")

oauth = OAuth(app)

auth0 = oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url=f"https://{DOMAIN}",
    access_token_url=f"https://{DOMAIN}/oauth/token",
    authorize_url=f"https://{DOMAIN}/authorize",
    client_kwargs={
        "scope": "openid profile email",
    },
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
class AuthError(Exception):
    """Custom exception class for authentication errors.

    Attributes:
        error (dict): The error message to return.
        status_code (int): The HTTP status code for the error.
    """

    def __init__(self, error, status_code):
        """Initialize the AuthError with an error message and status
        code.

        :param error: The error message to return.
        :param status_code: The HTTP status code for the error.
        """
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    """Handle authentication errors.

    :param ex: The AuthError instance.
    :return: A JSON response with the error message and the status code.
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@app.errorhandler(ValidationError)
def handle_validation_error(ex):
    """Handle Pydantic validation errors.

    :param ex: The ValidationError instance.
    :return: A JSON response with the error message and a 400 status
        code.
    """
    response = jsonify(BAD_REQUEST_ERROR.model_dump())
    response.status_code = StatusCode.BAD_REQUEST.value
    return response


def verify_jwt(request):
    """Verify the JWT in the Authorization header of the request.

    :param request: The Flask request object.
    :return: The decoded JWT payload if the token is valid.
    :raises AuthError: If the JWT is invalid or missing.
    """
    if "Authorization" in request.headers:
        auth_header = request.headers["Authorization"].split()
        token = auth_header[1]
    else:
        raise AuthError(
            UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
        )

    jsonurl = urlopen(f"https://{DOMAIN}/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(
            UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
        )
    if unverified_header["alg"] == "HS256":
        raise AuthError(
            UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
        )
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer=f"https://{DOMAIN}/",
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
            )
        except Exception:
            raise AuthError(
                UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
            )

        return payload
    else:
        raise AuthError(
            UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value
        )


@app.route("/decode", methods=["GET"])
def decode_jwt():
    """Decode the JWT in the Authorization header and return its
    payload.

    :return: The decoded JWT payload
    """
    payload = verify_jwt(request)
    return payload


# USER ENDPOINTS
@app.route(f"/{USERS}", methods=["GET"])
def get_users():
    """Get all users if the Authorization header contains a
    valid JWT belonging to an admin.

    :return: A list of all users.
    """
    payload = verify_jwt(request)

    # Check if the user is admin
    if not is_admin(payload):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    query = client.query(kind=USERS)
    users = query.fetch()

    response = [
        user_entity_to_response(user, user.key.id).model_dump(
            exclude_none=True
        )
        for user in users
    ]

    return response


@app.route(f"/{USERS}/<int:id>", methods=["GET"])
def get_user(id):
    """Get a user by their ID if the Authorization header contains a
    valid JWT belonging to the user or an admin.

    :param id: The ID of the user to retrieve.
    :return: The user or an error, and the HTTP status code
    """
    payload = verify_jwt(request)
    user_key = client.key(USERS, id)
    user = client.get(user_key)

    if user and (user["sub"] == payload.get("sub") or is_admin(payload)):
        # Generate avatar URL if the user has an avatar
        avatar_url = (
            url_for("get_avatar", id=id, _external=True)
            if user_has_avatar(id)
            else None
        )

        # Get courses for the user based on their role
        user_role = user.get("role")
        courses = get_user_courses(id, user_role)
        response = user_entity_to_response(
            user, user.key.id, avatar_url, courses
        ).model_dump(exclude_none=True)
    else:
        response = FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    return response


@app.route(f"/{USERS}/login", methods=["POST"])
def login_user():
    """Login a user using their username and password.

    :return: A JSON response with the user's token or an error, and the
        HTTP status code
    """
    content = request.get_json()

    # Handle missing/null JSON body
    if not content:
        return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

    login_data = LoginRequest(**content)
    body = {
        "grant_type": "password",
        "username": login_data.username,
        "password": login_data.password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"content-type": "application/json"}
    url = f"https://{DOMAIN}/oauth/token"
    r = requests.post(url, json=body, headers=headers)

    # Handle unsuccessful login
    if r.status_code != 200:
        return UNAUTHORIZED_ERROR.model_dump(), StatusCode.UNAUTHORIZED.value

    token = r.json().get("id_token")
    return {"token": token}, 200, {"Content-Type": "application/json"}


# AVATAR ENDPOINTS
@app.route(f"/{USERS}/<int:id>/avatar", methods=["POST"])
def create_avatar(id):
    """Create or update a user's avatar image if the Authorization
    header contains a valid JWT belonging to the user.

    :param id: The ID of the user whose avatar to create or update.
    :return: The URL of the created or updated avatar image or an error,
        and the HTTP status code
    """
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if "file" not in request.files:
        return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

    # Authenticate user
    payload = verify_jwt(request)

    # Get user from datastore
    user_key = client.key(USERS, id)
    user = client.get(user_key)

    # Check if the user exists and if the sub in the JWT payload matches
    if not user or user["sub"] != payload.get("sub"):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Set file_obj to the file sent in the request
    file_obj = request.files["file"]

    # Create a file name for the avatar
    file_name = f"{AVATAR_FILENAME_PREFIX}{id}{AVATAR_FILENAME_EXTENSION}"

    try:
        # Create a storage client
        storage_client = storage.Client()
        # Get a handle on the bucket
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        # Create a blob object for the bucket with the name of the file
        blob = bucket.blob(file_name)
        # Position the file_obj to its beginning
        file_obj.seek(0)
        # Upload the file into Cloud Storage
        blob.upload_from_file(file_obj)

        # Generate the public URL for the uploaded file
        avatar_url = url_for("get_avatar", id=id, _external=True)

        response = AvatarCreateResponse(avatar_url=avatar_url).model_dump()
    except Exception:
        response = BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

    return response


@app.route(f"/{USERS}/<int:id>/avatar", methods=["GET"])
def get_avatar(id):
    """Get a user's avatar image if the Authorization header contains a
    valid JWT belonging to the user and the user has an avatar.

    :param id: The ID of the user whose avatar to retrieve.
    :return: The avatar image or an error, and the HTTP status code
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Get user from datastore
    user_key = client.key(USERS, id)
    user = client.get(user_key)

    # Check if the user exists and if the sub in the JWT payload matches
    if not user or user["sub"] != payload.get("sub"):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    try:
        file_name = f"{AVATAR_FILENAME_PREFIX}{id}{AVATAR_FILENAME_EXTENSION}"
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        # Create a blob with the given file name
        blob = bucket.blob(file_name)

        # Check if the blob exists
        if not blob.exists():
            return NOT_FOUND_ERROR.model_dump(), StatusCode.NOT_FOUND.value

        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()
        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)
        # Position the file_obj to its beginning
        file_obj.seek(0)

        # Send the object as a file in the response with the correct MIME type and file name
        return send_file(
            file_obj, mimetype="image/x-png", download_name=file_name
        )
    except Exception:
        return NOT_FOUND_ERROR.model_dump(), StatusCode.NOT_FOUND.value


@app.route(f"/{USERS}/<int:id>/avatar", methods=["DELETE"])
def delete_avatar(id):
    """Delete a user's avatar image if the Authorization header contains a
    valid JWT belonging to the user.

    :param id: The ID of the user whose avatar to delete.
    :return: Empty response with 204 status code on success, or error response
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Get user from datastore
    user_key = client.key(USERS, id)
    user = client.get(user_key)

    # Check if the user exists and if the sub in the JWT payload matches
    if not user or user["sub"] != payload.get("sub"):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    try:
        file_name = f"{AVATAR_FILENAME_PREFIX}{id}{AVATAR_FILENAME_EXTENSION}"
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)
        # Delete the file from Cloud Storage
        blob.delete()

        return "", 204
    except Exception:
        return NOT_FOUND_ERROR.model_dump(), StatusCode.NOT_FOUND.value


# COURSE ENDPOINTS
@app.route(f"/{COURSES}", methods=["POST"])
def create_course():
    """Create a new course if the Authorization header contains a
    valid JWT belonging to an admin.

    :return: The created course or an error, and the HTTP status code
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Check if the user is admin
    if not is_admin(payload):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    if request.method == "POST":
        content = request.get_json()

        if not content:
            return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

        # Check for valid instructor_id
        instructor_key = client.key(USERS, content["instructor_id"])
        instructor = client.get(instructor_key)

        if (
            not instructor
            or instructor.get("role") != UserRole.INSTRUCTOR.value
        ):
            return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

        # Create new course
        course_data = CourseCreateRequest(**content)

        new_course = datastore.Entity(key=client.key(COURSES))
        new_course.update(course_data.model_dump())
        client.put(new_course)

        # Generate the course URL
        course_url = url_for(
            "get_course", id=new_course.key.id, _external=True
        )

        response = course_entity_to_response(
            new_course,
            new_course.key.id,
            course_url,
        )

        return response.model_dump(), 201
    else:
        return jsonify(error="Method not recognized")


@app.route(f"/{COURSES}/<int:id>", methods=["GET"])
def get_course(id):
    # Get course from datastore
    course_key = client.key(COURSES, id)
    course = client.get(course_key)

    if not course:
        return NOT_FOUND_ERROR.model_dump(), StatusCode.NOT_FOUND.value

    self_url = url_for("get_course", id=id, _external=True)
    response = course_entity_to_response(course, course.key.id, self_url)

    return response.model_dump()


@app.route(f"/{COURSES}", methods=["GET"])
def get_courses():
    """Get all courses with pagination, sorted by subject.

    Query Parameters:
    - offset: Starting position (default: 0)
    - limit: Number of courses to return (default: 3)

    :return: Paginated list of courses with optional next link
    """
    # Get query parameters
    offset = request.args.get("offset", 0, type=int)
    limit = request.args.get("limit", 3, type=int)

    # Query courses sorted by subject
    query = client.query(kind=COURSES)
    query.order = ["subject"]

    # Fetch an extra course for determining if there are more results
    courses = list(query.fetch(limit=limit + 1, offset=offset))

    # Check if there are more results
    has_next = len(courses) > limit
    if has_next:
        courses = courses[:limit]  # Remove the extra course

    # Convert courses to response format
    course_responses = [
        course_entity_to_response(
            course,
            course.key.id,
            url_for("get_course", id=course.key.id, _external=True),
        )
        for course in courses
    ]

    # Generate next URL if there are more results
    next_url = (
        url_for(
            "get_courses", offset=offset + limit, limit=limit, _external=True
        )
        if has_next
        else None
    )

    response = CourseListResponse(courses=course_responses, next=next_url)

    return response.model_dump(exclude_none=True)


@app.route(f"/{COURSES}/<int:id>", methods=["PATCH"])
def update_course(id):
    """Update an existing course if the Authorization header contains a
    valid JWT belonging to an admin.

    :param id: The ID of the course to update.
    :return: The updated course or an error, and the HTTP status code
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Check if the user is admin
    if not is_admin(payload):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Get course from datastore
    course_key = client.key(COURSES, id)
    course = client.get(course_key)

    if not course:
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    content = request.get_json()

    if content is None:
        return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

    # Validate and update course data
    course_data = CourseUpdateRequest(**content)

    # Check to see if instructor_id is valid
    if "instructor_id" in course_data.model_dump(exclude_unset=True):
        instructor_key = client.key(USERS, course_data.instructor_id)
        instructor = client.get(instructor_key)

        if (
            not instructor
            or instructor.get("role") != UserRole.INSTRUCTOR.value
        ):
            return BAD_REQUEST_ERROR.model_dump(), StatusCode.BAD_REQUEST.value

    # Update course entity with new data
    for key, value in course_data.model_dump(exclude_unset=True).items():
        course[key] = value

    client.put(course)

    self_url = url_for("get_course", id=id, _external=True)
    response = course_entity_to_response(course, id, self_url)

    return response.model_dump()


@app.route(f"/{COURSES}/<int:id>", methods=["DELETE"])
def delete_course(id):
    """Delete a course if the Authorization header contains a valid JWT
    belonging to an admin.

    :param id: The ID of the course to delete.
    :return: Empty response with 204 status code on success, or error
        response
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Check if the user is admin
    if not is_admin(payload):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Get course from datastore
    course_key = client.key(COURSES, id)
    course = client.get(course_key)

    if not course:
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Check if the course has any enrollments that need to be deleted
    query = client.query(kind=ENROLLMENTS)
    query.add_filter(
        filter=datastore.query.PropertyFilter("course_id", "=", id)
    )
    enrollments = query.fetch()
    enrollment_keys = [enrollment.key for enrollment in enrollments]
    if enrollment_keys:
        client.delete_multi(enrollment_keys)

    # Delete the course entity
    client.delete(course_key)

    return "", 204


@app.route(f"/{COURSES}/<int:id>/students", methods=["PATCH"])
def update_enrollment(id):
    """Update the enrollment of a course by adding or removing students
    if the Authorization header contains a valid JWT belonging to an
    admin or the course instructor.

    :param id: The ID of the course to update.
    :return: The updated course or an error, and the HTTP status code
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Get course from datastore
    course_key = client.key(COURSES, id)
    course = client.get(course_key)

    if not course:
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Get course instructor
    instructor_id = course.get("instructor_id")
    instructor_key = client.key(USERS, instructor_id)
    instructor = client.get(instructor_key)

    # Check if the user is an admin or the course instructor
    user_sub = payload.get("sub")
    if not is_admin(payload) and (
        not instructor or instructor.get("sub") != user_sub
    ):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    content = request.get_json()

    if not content:
        return ENROLLMENT_ERROR.model_dump(), StatusCode.CONFLICT.value

    try:
        enrollment_data = EnrollmentUpdateRequest(**content)
    except ValidationError:
        return ENROLLMENT_ERROR.model_dump(), StatusCode.CONFLICT.value

    # Validate enrollment data
    for student_id in enrollment_data.add:
        if student_id in enrollment_data.remove:
            return ENROLLMENT_ERROR.model_dump(), StatusCode.CONFLICT.value

        student_key = client.key(USERS, student_id)
        student = client.get(student_key)
        if not student or student.get("role") != UserRole.STUDENT.value:
            return ENROLLMENT_ERROR.model_dump(), StatusCode.CONFLICT.value

    for student_id in enrollment_data.remove:
        student_key = client.key(USERS, student_id)
        student = client.get(student_key)
        if not student or student.get("role") != UserRole.STUDENT.value:
            return ENROLLMENT_ERROR.model_dump(), StatusCode.CONFLICT.value

    # Add students to the course
    for student_id in enrollment_data.add:
        query = client.query(kind=ENROLLMENTS)
        query.add_filter(
            filter=datastore.query.PropertyFilter(
                "student_id", "=", student_id
            ),
        )
        query.add_filter(
            filter=datastore.query.PropertyFilter("course_id", "=", id),
        )
        results = list(query.fetch(limit=1))

        # Create a new enrollment if the student is not already enrolled
        if len(results) == 0:
            new_enrollment = datastore.Entity(key=client.key(ENROLLMENTS))
            new_enrollment.update({"student_id": student_id, "course_id": id})
            client.put(new_enrollment)

    # Remove students from the course
    for student_id in enrollment_data.remove:
        query = client.query(kind=ENROLLMENTS)
        query.add_filter(
            filter=datastore.query.PropertyFilter(
                "student_id", "=", student_id
            ),
        )
        query.add_filter(
            filter=datastore.query.PropertyFilter("course_id", "=", id),
        )
        results = list(query.fetch())

        # If the student is enrolled, delete the enrollment entity
        if results:
            for enrollment in results:
                client.delete(enrollment.key)

    return ""


@app.route(f"/{COURSES}/<int:id>/students", methods=["GET"])
def get_enrolled_students(id):
    """Get the list of students enrolled in a course if the
    Authorization header contains a valid JWT belonging to an admin or
    the course instructor.

    :param id: The ID of the course.
    :return: A list of enrolled students or an error, and the HTTP status code
    """
    # Authenticate user
    payload = verify_jwt(request)

    # Get course from datastore
    course_key = client.key(COURSES, id)
    course = client.get(course_key)

    if not course:
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    # Get course instructor
    instructor_id = course.get("instructor_id")
    instructor_key = client.key(USERS, instructor_id)
    instructor = client.get(instructor_key)

    # Check if the user is an admin or the course instructor
    user_sub = payload.get("sub")
    if not is_admin(payload) and (
        not instructor or instructor.get("sub") != user_sub
    ):
        return FORBIDDEN_ERROR.model_dump(), StatusCode.FORBIDDEN.value

    query = client.query(kind=ENROLLMENTS)
    query.add_filter(
        filter=datastore.query.PropertyFilter("course_id", "=", id)
    )
    enrollments = list(query.fetch())

    student_ids = [enrollment["student_id"] for enrollment in enrollments]

    return student_ids


# HELPER FUNCTIONS
def is_admin(payload):
    """Check if the JWT payload indicates an admin user.

    :param payload: The decoded JWT payload.
    :return: True if the user is an admin, False otherwise.
    """
    user_sub = payload.get("sub")
    query = client.query(kind=USERS)
    query.add_filter(
        filter=datastore.query.PropertyFilter("sub", "=", user_sub)
    )
    user = list(query.fetch(limit=1))
    return user and user[0].get("role") == UserRole.ADMIN.value


def user_has_avatar(user_id):
    """Check if a user has an avatar by checking if the file exists in
    storage.

    :param user_id: The user's ID
    :return: True if avatar exists, False otherwise
    """
    try:
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(
            f"{AVATAR_FILENAME_PREFIX}{user_id}{AVATAR_FILENAME_EXTENSION}"
        )
        return blob.exists()
    except Exception:
        return False


def get_user_courses(user_id, user_role):
    """Get courses for a user based on their role.

    :param user_id: The user's ID
    :param user_role: The user's role
    :return: List of course URLs
    """
    if user_role not in [UserRole.INSTRUCTOR.value, UserRole.STUDENT.value]:
        return None

    # For instructors, filter courses by instructor_id
    if user_role == UserRole.INSTRUCTOR.value:
        query = client.query(kind=COURSES)
        query.add_filter(
            filter=datastore.query.PropertyFilter(
                "instructor_id", "=", user_id
            )
        )
        courses = query.fetch()
        course_ids = [course.key.id for course in courses]
    else:
        # For students, get courses by student_id from enrollments
        query = client.query(kind=ENROLLMENTS)
        query.add_filter(
            filter=datastore.query.PropertyFilter("student_id", "=", user_id)
        )
        enrollments = query.fetch()
        course_ids = [enrollment["course_id"] for enrollment in enrollments]

    return [
        url_for("get_course", id=course_id, _external=True)
        for course_id in course_ids
    ]


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
