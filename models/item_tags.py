from db import db

class ItemTagsModel(db.Model):
    __tablename__ = "items_tags"

    id = db.Column(db.Integer, primary_key=True)

    #many-to-many
    item_id = db.Column(db.Integer, db.ForeignKey("items.id"))
    tag_id = db.Column(db.Integer, db.ForeignKey("tags.id"))