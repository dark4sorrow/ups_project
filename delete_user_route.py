
@app.route('/admin/delete_user/<username>')
@login_required
@admin_required
def delete_user(username):
    if username in USERS:
        if username != 'admin': # Prevent admin from deleting themselves
            del USERS[username]
    return redirect(url_for('admin'))
