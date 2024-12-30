from app import app, db, User, VPS
import os

# Create all database tables
with app.app_context():
    # Create database
    db.drop_all()
    db.create_all()

    # Create admin user
    admin = User(username='admin', is_admin=True)
    admin.set_password('Darkandd94!')
    db.session.add(admin)

    # Create regular user
    user = User(username='user')
    user.set_password('Darkandd94!')
    db.session.add(user)

    # Create sample VPS
    vps1 = VPS(
        name='Sample VPS 1',
        vmx_path='C:/path/to/vm1.vmx',
        user_id=2,
        status='stopped',
        rdp_host='localhost',
        rdp_port=3389,
        rdp_username='administrator'
    )
    db.session.add(vps1)

    db.session.commit()
    print("Database initialized with sample data!")

if __name__ == '__main__':
    with app.app_context():
        # Create database
        db.drop_all()
        db.create_all()

        # Create admin user
        admin = User(username='admin', is_admin=True)
        admin.set_password('Darkandd94!')
        db.session.add(admin)

        # Create regular user
        user = User(username='user')
        user.set_password('Darkandd94!')
        db.session.add(user)

        # Create sample VPS
        vps1 = VPS(
            name='Sample VPS 1',
            vmx_path='C:/path/to/vm1.vmx',
            user_id=2,
            status='stopped',
            rdp_host='localhost',
            rdp_port=3389,
            rdp_username='administrator'
        )
        db.session.add(vps1)

        db.session.commit()
        print("Database initialized with sample data!")
