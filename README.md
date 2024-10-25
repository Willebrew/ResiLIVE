![ResiLIVE](ResiLIVE_Neat_Logo.png)

# ResiLIVE

ResiLIVE is a comprehensive community management system designed to streamline access control and logging for residential communities. It provides a robust backend API and a user-friendly web interface for managing communities, addresses, residents, and access codes.

## Branch Overview

- **Prototype-1**: Initial proof of concept with basic functionality using JSON file storage
- **Prototype-2**: Extended functionality proof of concept, focusing on features over aesthetics
- **Prototype-3**: Polished system with improved UI/UX, still using JSON file storage
- **Main**: Mostly production-ready version using Firebase, featuring optimized code and improved scalability

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

## Getting Started

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up Firebase:
   - Create a Firebase project
   - Set up Firestore Database
   - Add Firebase credentials to .env file
4. Start the server: `node server.js`
5. Access the web interface at `http://localhost:3000`
6. Default superuser credentials:
   - Username: Superuser
   - Password: root (change immediately)

## Environment Variables

```env
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_PRIVATE_KEY=your-private-key
FIREBASE_CLIENT_EMAIL=your-client-email
