import unittest
from app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_user_not_found(self):
        response = self.client.get("/user/9999")
        self.assertIn(response.status_code, [404, 500])

if __name__ == "__main__":
    unittest.main()
