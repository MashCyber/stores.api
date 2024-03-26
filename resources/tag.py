from flask.views import MethodView
from flask_smorest import Blueprint, abort
from sqlalchemy.exc import SQLAlchemyError

from db import db
from models import TagModel, StoreModel, ItemModel
from schemas import TagSchema, TagAndItemSchema


blp = Blueprint("Tags","tags", description="Operations for tags.")

@blp.route("/store/<int:store_id>/tag")
class TagInStore(MethodView):
    @blp.response(200, TagSchema(many=True))
    def get(self, store_id):
        store = StoreModel.query.get_or_404(store_id)
        return store.tags.all()
    
    @blp.arguments(TagSchema)
    @blp.response(201, TagSchema)
    def post(self, tag_data, store_id):
        tag =TagModel(**tag_data, store_id=store_id)

        try:
            db.session.add(tag)
            db.session.commit()
        except SQLAlchemyError as e:
            abort(500, message=str(e))

        return tag
    
    @blp.route("/tag/<int:tag_id>")
    class Tag(MethodView):
        @blp.response(200,TagSchema)
        def get(self,tag_id):
            tag = TagModel.query.get_or_404(tag_id)
            return tag

        @blp.response(
            202,
            description="Delete a tag if no item is linked to it.",
            example="Tag deleted."
        )
        @blp.alt_response(
            400,
            description="Tag not"
        )
        @blp.alt_response(
            404,
            description="Returned if tag is assigned to item, that case its not deleted."
        )
        def delete(self, tag_id):
            tag = TagModel.query.get_or_404(tag_id)
            
            if not tag.items:
                db.session.delete(tag)
                db.session.commit()
                return{
                    "message":"Tag deleted."
                }
            abort(
                400,
                message="Could not delete tag, tag has associated items."
            )
            

##Linking Tags to items
        
@blp.route("/item/<int:item_id>/tag/<int:tag_id>")
class LinkTagstoItems(MethodView):
    @blp.response(201, TagSchema)
    def post(self, item_id, tag_id):
        item = ItemModel.query.get_or_404(item_id)
        tag = TagModel.query.get_or_404(tag_id)

        item.tags.append(tag)
        try:
            db.session.add(item)
            db.session.commit()
        except SQLAlchemyError as e:
            abort(
                500,
                message="An error occured linking tag to an item."
            )
        return tag

    
    @blp.response(200, TagAndItemSchema)
    def delete(self, item_id, tag_id):
        item = ItemModel.query.get_or_404(item_id)
        tag = TagModel.query.get_or_404(tag_id)

        item.tags.remote(tag)

        try:
            db.session.add(item)
            db.session.commit()
        except SQLAlchemyError:
            abort(
                500,
                message="An error occured unlinking tag from item."
            )
        
        return {
            "message":"Item removed from tag",
            "item": item,
            "tag": tag
        }
