# VMware Control Panel

A web-based control panel for managing VMware virtual machines with a modern, user-friendly interface. This application allows users to start, stop, and manage their VPS instances through a secure web interface.

## Features

- 🖥️ **VPS Management**
  - Start/Stop/Reset VPS instances
  - Real-time status monitoring
  - VMware integration
  
- 🔐 **User Authentication**
  - Secure login system
  - Admin and regular user roles
  - Password hashing for security

- 💻 **RDP Integration**
  - Configure RDP settings
  - Download RDP connection files
  - Manage RDP credentials

- 👥 **User Management** (Admin Only)
  - Create and manage users
  - Assign VPS instances to users
  - Toggle admin privileges

## Prerequisites

- Python 3.8+
- VMware Workstation/Player
- Flask and its dependencies

## Installation

1. Clone the repository:
```bash
git clone https://github.com/laggis/vmware-control-panel.git
cd vmware-control-panel
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Initialize the database:
```bash
python init_db.py
```

4. Start the application:
```bash
python app.py
```

The application will be available at `http://localhost:5001`

## Configuration

- Default port: 5001 (can be modified in app.py)
- Database: SQLite (users.db)
- Debug mode: Enabled by default (disable in production)

## Project Structure

```
vmware-control-panel/
├── app.py              # Main application file
├── init_db.py          # Database initialization
├── requirements.txt    # Python dependencies
├── static/            # Static files (CSS, JS)
├── templates/         # HTML templates
│   ├── dashboard.html
│   ├── login.html
│   └── ...
└── instance/         # SQLite database
    └── users.db
```

## Security Features

- Password hashing using Werkzeug
- Login required for all control functions
- Admin-only sections
- Session management
- CSRF protection

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask framework
- VMware for their virtualization technology
- Bootstrap for the UI components
