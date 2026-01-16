
@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(username):
    if username in USERS:
        if request.method == 'POST':
            password = request.form.get('password')
            email = request.form.get('email')
            if password:
                USERS[username]['password'] = password
            if email:
                USERS[username]['email'] = email
            return redirect(url_for('admin'))
        return render_template('edit_user.html', username=username, user_data=USERS[username])
    return "User not found", 404
