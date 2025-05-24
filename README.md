![ResiLIVE](ResiLIVE_Neat_Logo.png)

# ResiLIVE

ResiLIVE is a comprehensive community management system designed to streamline access control and logging for 
residential communities. It provides a robust backend API and a user-friendly web interface for managing communities, 
addresses, residents, and access codes.

## Branch Overview

- **Prototype-1**: Initial proof of concept with basic functionality using JSON file storage
- **Prototype-2**: Extended functionality proof of concept, focusing on features over aesthetics
- **Prototype-3**: Polished system with improved UI/UX, still using JSON file storage
- **Main**: Production-ready version using Firebase, featuring optimized code and improved scalability

## Features

- **Community Management**: Create, view, and delete communities with ease
- **Address Management**: Add and remove addresses within each community
- **Resident Management**: Manage residents associated with each address
- **Access Code System**: Generate and manage time-limited access codes
- **Real-time Logging**: Track and view access logs for each community
- **User Authentication**: Secure login system with role-based access control
- **API Integration**: Seamless integration with external systems

## Technology Stack

### Main Branch (Current)
- Backend: Node.js with Express.js
- Frontend: HTML, CSS, and JavaScript
- Database: Firebase Firestore
- Authentication: Session-based with Firebase Auth
- Hosting: Render

### Legacy Branches (Prototypes 1-3)
- Backend: Node.js with Express.js
- Frontend: HTML, CSS, and JavaScript
- Storage: JSON file-based
- Authentication: Session-based with bcrypt

## Security Features

- **Authentication Security**
    - Password hashing using bcrypt
    - Session-based authentication with secure cookies (HttpOnly, Secure in production, SameSite=Lax)
    - Role-based access control (user, admin, superuser)
    - **Robust Session Secret Management**: The application requires a strong, unique `SESSION_SECRET` to be set in the environment variables for production. It will fail to start if the secret is missing or uses an insecure placeholder, preventing accidental deployment with weak defaults.

- **Data Security**
    - Firebase Firestore security rules
    - Input validation and sanitization
    - CSRF protection via lusca
    - Rate limiting on API endpoints

- **Access Control**
    - Role-based permissions
    - Case-insensitive username validation
    - Protected admin routes
    - Superuser account protection

- **API Security**
    - Request rate limiting
    - **API Key Authentication**: Critical API endpoints (like `/api/log-access`) are protected by an API key (via `X-API-Key` header), ensuring that only authorized services (e.g., the Roblox game server) can access them.
    - **Configurable CORS Policy**: Cross-Origin Resource Sharing (CORS) is strictly configured via the `CLIENT_ORIGIN_URL` environment variable in production, allowing access only from the designated frontend domain(s). In development, it defaults to `http://localhost:3000`.
    - Secure session management
    - Protected endpoints requiring user authentication

## Getting Started

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up Firebase:
    - Create a Firebase project
    - Set up Firestore Database (Rules below)
    - Add Firebase credentials to .env file (Example below)
4. **For first time use**, uncomment createInitialSuperuser(), run `node server.js`, then close the server and comment 
out the function
5. Start the server: `node server.js`
6. Access the web interface at `http://localhost:3000`
7. Default superuser credentials:
    - Username: superuser
    - Password: root (change immediately)

# Firestore Layout

Once the system is up and running, it will look like this:

### Users Collection

- **Document ID:** Auto-generate
- **Fields:**
    - `username`: String (stored in lowercase for case-insensitive comparison)
    - `password`: String (bcrypt-hashed password)
    - `role`: String ("user", "admin", or "superuser")
    - `createdAt`: Timestamp (use Firestore's server timestamp)

### Communities Collection

- **Document ID:** Auto-generate
- **Fields:**
    - `name`: String (community name)
    - `addresses`: Array of objects
        - Each address object contains:
            - `id`: String (timestamp-based ID)
            - `street`: String (street address)
            - `people`: Array of objects
                - Each person object contains:
                    - `id`: String (timestamp-based ID)
                    - `username`: String
                    - `playerId`: String
                    - `codes`: Array of objects
                        - Each code object contains:
                            - `id`: String (timestamp-based ID)
                            - `description`: String
                            - `code`: String
                            - `expiresAt`: String (ISO date string)
                            - `createdAt`: Timestamp
                            - `allowedUsers`: Array of strings (usernames)

### Access Logs Collection

- **Document ID:** Auto-generate
- **Fields:**
    - `community`: String (community name)
    - `player`: String (player name)
    - `action`: String (action description)
    - `timestamp`: Timestamp (use Firestore's server timestamp)

### Firestore Rules

In the **Rules** tab of your Firestore Database, configure the rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null && 
        (get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
    }
    
    match /communities/{communityId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null && 
        (get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin');
    }
    
    match /access_logs/{logId} {
      allow read: if request.auth != null;
      allow write: if request.auth != null;
    }
  }
}
```

## Environment Variables (.env)

To get the environment variables from Firebase, open your Firebase project, press the gear next to "Project Overview", 
select "Project Overview" and press "Project settings". In the "Service Accounts" tab, make sure node.js is selected and press "Generate new private key" (Generate key). This will download a JSON file to your machine with the credentials. Open the file and copy the necessary values into the .env file in the format given below.

```
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY="your-private-key"
FIREBASE_CLIENT_EMAIL=your-client-email
API_SECRET_KEY=your-strong-generated-api-secret-key # Used for server-to-server or trusted client authentication
SESSION_SECRET=a-very-long-random-string-generated-by-you # For user session cookies
CLIENT_ORIGIN_URL=https://your-production-frontend-domain.com # Your frontend URL for CORS in production
NODE_ENV=development # Set to 'production' for deployment
```

**Note on Secrets**: Both `API_SECRET_KEY` and `SESSION_SECRET` should be strong, randomly generated strings. You can use tools like OpenSSL (e.g., `openssl rand -hex 32`) or a password manager to create these. Store them securely and never commit them to version control (ensure your `.env` file is in `.gitignore`).

## Contributing

We welcome contributions to ResiLIVE! Please read our [CONTRIBUTING.md](./CONTRIBUTING.md) guide for details on 
Contributing.

## License

This project is licensed under the [Apache License](LICENSE).
