# ResiLIVE

ResiLIVE is a comprehensive community management system designed to streamline access control and logging for residential communities. It provides a robust backend API and a user-friendly web interface for managing communities, addresses, residents, and access codes.

## Features

- **Community Management**: Create, view, and delete communities with ease.
- **Address Management**: Add and remove addresses within each community.
- **Resident Management**: Manage residents associated with each address, including their usernames and player IDs.
- **Access Code System**: Generate and manage time-limited access codes for each address.
- **Real-time Logging**: Track and view access logs for each community.
- **User Authentication**: Secure login system with role-based access control (admin and regular users).
- **API Integration**: Seamless integration with external systems (e.g., Roblox games) for real-time access control.

## Technology Stack

- Backend: Node.js with Express.js
- Frontend: HTML, CSS, and JavaScript
- Database: JSON file-based storage (can be easily extended to use a database)
- Authentication: Session-based authentication with bcrypt for password hashing

## Getting Started

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up your environment variables (if any)
4. Start the server: `node server.js`
5. Access the web interface at `http://localhost:3000`

## API Endpoints

- `/api/communities`: CRUD operations for communities
- `/api/communities/:id/addresses`: Manage addresses within a community
- `/api/communities/:id/addresses/:addressId/people`: Manage residents for an address
- `/api/communities/:id/addresses/:addressId/codes`: Manage access codes for an address
- `/api/log-access`: Log access attempts
- `/api/communities/:name/logs`: Retrieve access logs for a community

## Security Features

- Password hashing for user accounts
- Role-based access control
- Session-based authentication
- Input validation and sanitization

## Future Enhancements

- Real-time updates using WebSockets
- Mobile optimized interface for residents

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request if you have any cool ideas.

## License

This project is licensed under the [Apache License](LICENSE).
