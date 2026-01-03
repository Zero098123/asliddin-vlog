# routes.py
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, current_user, logout_user, login_required
from models import db, User, Post, Comment
from werkzeug.security import generate_password_hash, check_password_hash

routes = Blueprint('routes', __name__)

# ==================== HOME / USER PAGE ====================
@routes.route('/')
@routes.route('/category/<string:category>')
def user(category=None):
    # Get all unique categories for the filter bar
    all_categories = db.session.query(Post.category).distinct().order_by(Post.category).all()
    categories = [cat[0] for cat in all_categories]

    # Filter posts if category is provided
    query = Post.query.order_by(Post.date_posted.desc())
    if category:
        query = query.filter_by(category=category)

    posts = query.all()

    return render_template(
        'user.html',
        posts=posts,
        categories=categories,
        current_category=category
    )



# ==================== LOGIN ====================
@routes.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('routes.user'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Welcome back!', 'success')
            return redirect(url_for('routes.user'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

# ==================== SIGNUP ====================
@routes.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('routes.user'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form.get('cpwd', '')

        if password != confirm:
            flash('Passwords do not match!', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
        elif len(password) < 4:
            flash('Password too short', 'error')
        else:
            hashed_pw = generate_password_hash(password)
            new_user = User(username=username, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('routes.login'))
    
    return render_template('signup.html')

# ==================== LOGOUT ====================
@routes.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully')
    return redirect(url_for('routes.user'))

# ==================== SINGLE POST + COMMENTS ====================
@routes.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    
    if request.method == 'POST' and current_user.is_authenticated:
        content = request.form['content'].strip()
        if content:
            comment = Comment(content=content, author=current_user, post=post)
            db.session.add(comment)
            db.session.commit()
            flash('Comment added!')
        else:
            flash('Comment cannot be empty', 'error')
    
    return render_template('post.html', post=post)

# ==================== DELETE COMMENT (owner or admin) ====================
@routes.route('/comment/<int:comment_id>/delete')
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Only the comment author or admin can delete
    if current_user != comment.author and not current_user.is_admin:
        flash('You can only delete your own comments', 'error')
        return redirect(url_for('routes.post_detail', post_id=comment.post_id))
    
    db.session.delete(comment)
    db.session.commit()
    flash('Comment deleted', 'success')
    return redirect(url_for('routes.post_detail', post_id=comment.post_id))



# ==================== ADMIN DASHBOARD ====================
@routes.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied — admins only', 'error')
        return redirect(url_for('routes.user'))

    posts = Post.query.order_by(Post.date_posted.desc()).all()
    users = User.query.all()
    comments = Comment.query.order_by(Comment.date_posted.desc()).all()

    return render_template('admin.html',
                           posts=posts,
                           users=users,
                           comments=comments)


# ==================== ADMIN: ADD / EDIT POST ====================
@routes.route('/admin/post/new', methods=['GET', 'POST'])
@routes.route('/admin/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_post_form(post_id=None):
    if not current_user.is_admin:
        flash('Admins only', 'error')
        return redirect(url_for('routes.user'))

    post = Post.query.get_or_404(post_id) if post_id else None

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form.get('category', '').strip()

        if post:
            post.title = title
            post.content = content
            post.category = category or None
            flash('Post updated!', 'success')
        else:
            new_post = Post(
                title=title,
                content=content,
                category=category or None,  # Save empty as None
                author=current_user
            )
            db.session.add(new_post)
            flash('Post created!', 'success')

        db.session.commit()
        return redirect(url_for('routes.admin_dashboard'))

    return render_template('post_form.html', post=post)


# ==================== ADMIN: DELETE POST ====================
@routes.route('/admin/post/<int:post_id>/delete')
@login_required
def admin_delete_post(post_id):
    if not current_user.is_admin:
        return redirect(url_for('routes.user'))

    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted', 'success')
    return redirect(url_for('routes.admin_dashboard'))