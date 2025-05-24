from auth import get_password_hash

fake_users_db = {
    "javier_thompson": {
        "username": "javier_thompson",
        "hashed_password": get_password_hash("aONF4d6aNBIxRjlgjBRRzrS"),
        "role": "admin"
    },
    "ignacio_tapia": {
        "username": "ignacio_tapia",
        "hashed_password": get_password_hash("f7rWChmQS1JYfThT"),
        "role": "client"
    },
    "stripe_sa": {
        "username": "stripe_sa",
        "hashed_password": get_password_hash("dzkQqDL9XZH33YDzhmsf"),
        "role": "service_account"
    }
}
