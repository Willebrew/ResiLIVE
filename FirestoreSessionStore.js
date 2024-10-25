const session = require('express-session');

class FirestoreSessionStore extends session.Store {
    constructor(db) {
        super();
        this.db = db;
        this.collection = db.collection('sessions');
    }

    get(sid, callback) {
        this.collection.doc(sid).get()
            .then(doc => {
                if (!doc.exists || this.isExpired(doc.data())) {
                    return callback(null, null);
                }
                callback(null, doc.data().session);
            })
            .catch(err => callback(err));
    }

    set(sid, session, callback) {
        const data = {
            session,
            expiresAt: Date.now() + (session.cookie.maxAge || 86400000)
        };
        this.collection.doc(sid).set(data)
            .then(() => callback(null))
            .catch(err => callback(err));
    }

    destroy(sid, callback) {
        this.collection.doc(sid).delete()
            .then(() => callback(null))
            .catch(err => callback(err));
    }

    isExpired(data) {
        return data.expiresAt && data.expiresAt < Date.now();
    }
}

module.exports = FirestoreSessionStore;
