"""SQLAlchemy database instance and base model for WraithWall."""
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class BaseModelMixin:
    """Mixin providing common columns for WraithWall models."""
    id = db.Column(db.Integer, primary_key=True)
