import os
import secrets

from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate

from db import db
from blocklist import BLOCKLIST
import models


from resources.item import blp as ItemBlueprint
from resources.store import blp as StoreBlueprint
from resources.tag import blp as TagBlueprint
from resources.user import blp as UserBlueprint

def create_app(db_url=None):
    app = Flask(__name__)


    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"

    #SQLAlchemy || DB Connection string
    
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL","sqlite:///data.db")

    db.init_app(app) #connect flask app to sqlalchemy
    
    #Migrate
    migrate = Migrate(app, db)

    #Instatiate api
    api = Api(app)

    #Create instance of JWT
    # app.config["JWT_SECRET_KEY"] = secrets.SystemRandom().getrandbits(128) #signsecretkey
    app.config["JWT_SECRET_KEY"] = "103642720388306738560356036224573424027" #signsecretkey 
    jwt = JWTManager(app) 

    #Claims loader lets you add extra info into the jwt token
    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        #Look in the db and see if user is admin
        if identity == 1:
            return {
                "is_admin": True
            }
        return {"is_admin": False}

    #
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload['jti'] in BLOCKLIST #returns Bool, if True rqst is terminated
    
    #JWT 3 ERROR HANDLING
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header,jwt_payload):
        return (
            jsonify(
                {
                    "description": "Token has been revoked.",
                    "error": "token_revoked"
                }
            )
        )
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh(jwt_header, jwt_payload):
        return(
            jsonify(
                {
                    "description": "The token is not fresh",
                    "error": "fresh_token_required."
                }
            )
        )
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload): #Token time expired
        return(
            jsonify(
                {
                    "message": "Signature verification failed",
                    "error": "token_expired"
                }
            ), 401
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error): #Prevents token change
        return(
            jsonify(
                {
                    "message":"Singature verification failed",
                    "error":"invalid_token"
                }
            ), 401
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error): #Enforce jwt_required() on endpoints
        return(
            jsonify(
                {
                    "message":"Request doesn't contain an access token.",
                    "error":"authorization_required"
                }
            ), 401
        )


    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(TagBlueprint)
    api.register_blueprint(UserBlueprint)

    return app