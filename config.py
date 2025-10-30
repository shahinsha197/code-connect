import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Base configuration class with default settings."""
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback_dev_secret")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(basedir, 'codeconnect.db')}")
    DEBUG = False

    # 🆕 Add this line:
    UPLOAD_FOLDER = os.path.join(basedir, "static", "uploads")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    ENV = "development"


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test_secret_key"


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    ENV = "production"

    SECRET_KEY = os.getenv("SECRET_KEY")
    if not SECRET_KEY:
        # Instead of crashing, print a warning for now
        print("⚠️  WARNING: No SECRET_KEY set for production. Using a temporary fallback.")
        SECRET_KEY = "temporary_prod_secret"


def get_config():
    """Returns the correct configuration class based on FLASK_ENV."""
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "production":
        return ProductionConfig
    elif env == "testing":
        return TestingConfig
    else:
        return DevelopmentConfig
