
@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    if username and password and email:
        if username not in USERS:
            USERS[username] = {'password': password, 'email': email}
            return redirect(url_for('admin'))
    return "Error creating user", 400
