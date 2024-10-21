# Create a user

As an admin, you can create a user using these instructions:

- Start the node server "node server.js"
- Login as an admin:"curl -X POST -H "Content-Type: application/json" -d '{"username":"admin", "password":"adminpassword"}' http://localhost:3000/api/login -v"
- This will print a token in the response. Copy the token (Set-Cookie: connect.sid=s%3A....).
- Then make the new user, insert the token "curl -X POST -H "Content-Type: application/json" -H "Cookie: connect.sid=s%3A...." -d '{"username":"newuser", "password":"newpassword"}' http://localhost:3000/api/register"

And that's it!