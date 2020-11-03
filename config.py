class Config(object):
    DEBUG = False

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    SECRET_KEY = 'SECRET_HASH_KEY'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlight_unit_1_0'
    DEBUG = True

class TestingConfig(Config):
    SECRET_KEY = 'SECRET_HASH_KEY'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlight_unit_1_0'
    TESTING = True

