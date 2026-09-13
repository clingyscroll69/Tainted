"""Flask and FastAPI handlers — two vulnerable, two safe."""

from flask import Flask, jsonify, request
from flask_login import current_user, login_required

app = Flask(__name__)


@app.route("/documents/<int:doc_id>")
@login_required
def get_document(doc_id):
    # VULNERABLE: logged in, and the query is still scoped only by the record id.
    document = Document.query.filter_by(id=doc_id).first()
    return jsonify(document.to_dict())


@app.route("/notes/<note_id>")
@login_required
def get_note(note_id):
    # SAFE: the predicate names the owner.
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    return jsonify(note.to_dict())
