# Project 10: Develop a Secure Web Application

Developing a secure web application and implementing security best practices.

## Prerequisites

- Python 
- Flask

## Guide

### Step 1: Set Up the Development Environment

1. **Install Python:**
    - Ensure Python is installed on your system. You can download it from [https://www.python.org/downloads/](https://www.python.org/downloads/)

2. **Set Up a Virtual Environment:**
    - Create a virtual environment to isolate your project dependencies.

    ```bash
    python -m venv venv
    `venv\Scripts\activate`
    ```

3. **Install Flask:**
    - Install Flask

    ```bash
    pip install Flask
    ```

### Step 2: Create the Web Application

1. **Create the Application Files:**
    - Create the main application file (`app.py`).

2. **Create the HTML templates:**
    - Create the `templates` directory.

    ```bash
    mkdir templates
    ```

    - Create the necessary HTML files (`home.html`, `register.html`, `login.html`, `dashboard.html`, `base.html`).

### Step 3: Configure Database

1. **Initialize the Database:**
    - Open a Python shell and run the commands to create the database and tables.

    ```bash
    python
    ```

    ```python
    from app import db
    db.create_all()
    exit()
    ```

### Step 4: Implement Security Best Practices

1. **Secure Password Storage:**
    - Ensure passwords are hashed.

2. **Use CSRF Protection:**
    - Install Flask-WTF for CSRF protection.

    ```bash
    pip install Flask-WTF
    ```

    - Modify `app.py` to include CSRF protection.

    ```python
    from flask_wtf.csrf import CSRFProtect

    csrf = CSRFProtect()
    csrf.init_app(app)
    ```

3. **Input Validation:**
    - Validate user input to prevent injection attacks.

4. **Secure Sessions:**
    - Ensure session cookies are secure by setting appropriate configurations.

    ```python
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['REMEMBER_COOKIE_HTTPONLY'] = True
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)
    ```

5. **Error Handling:**
    - Implement error handling to prevent information leakage.

    ```python
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500
    ```

### Step 5: Run and Test the Application

1. **Run the Application:**
    - Execute the main application file to start the server.

    ```bash
    python app.py
    ```

2. **Test the Application:**
    - Register a new user.
    - Log in with the new user.
    - Access the dashboard.
    - Log out and ensure session termination.
#   S e c u r e - W e b - A p p l i c a t i o n  
 