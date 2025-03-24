import json

from sqlalchemy.orm import Session
from models import get_db, Location

db = next(get_db())
locations_to_dump = db.query(Location).all()

def generate_data(_data):
    json_data = []
    for location in _data:
        loc = {
            'id': location.id,
            'name': location.name,
            'about': location.about,
            'like_amount': location.likes,
            'dislike_amount': location.dislikes,
            'comments_amount'
            'rating': location.rating,
        }
        json_data.append(loc)
    return json_data


def export_to_json():
    exported_locations = open("export/locations.json", "w")
    json.dump(generate_data(locations_to_dump), exported_locations, indent=4, ensure_ascii=False)

    exported_locations.close()

if __name__ == "__main__":
    export_to_json()
