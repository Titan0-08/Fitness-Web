from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore
from functools import wraps
import datetime
import requests

app = Flask(__name__)
app.secret_key = "9487790519b6cf89e08a6abf40fcdff6e"

# ---------------- FIREBASE INIT ---------------- #
import os
import json

# -------- Firebase initialization (Render + Local) --------
cred_json = os.environ.get("FIREBASE_CREDENTIALS")

if cred_json:
    # On Render: read credentials from environment variable
    try:
        cred_dict = json.loads(cred_json)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        print("✅ Firebase initialized from Render environment variable")
    except Exception as e:
        print("❌ Failed to initialize Firebase from FIREBASE_CREDENTIALS:", e)
        raise
else:
    # Local fallback for development
    if os.path.exists("serviceAccountKey1.json"):
        cred = credentials.Certificate("serviceAccountKey1.json")
        firebase_admin.initialize_app(cred)
        print("✅ Firebase initialized from local serviceAccountKey1.json")
    else:
        raise RuntimeError(
            "Firebase credentials not found. "
            "Set FIREBASE_CREDENTIALS env var or keep serviceAccountKey1.json locally."
        )
# ------------------------------------------------------------

db = firestore.client()

# ---------------- HELPER: Session-based login ---------------- #
def login_required(role=None):
    """Protect routes and optionally restrict by role"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "uid" not in session:
                print("❌ User not logged in")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                print(f"❌ Unauthorized access attempt by {session.get('uid')}")
                return "Unauthorized", 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------- HELPER: Clean Firestore Data ---------------- #
def clean_firestore_data(data):
    """Convert Firestore data into JSON-safe format."""
    clean = {}
    for k, v in data.items():
        if isinstance(v, datetime.datetime):
            clean[k] = v.isoformat()
        elif isinstance(v, dict):
            clean[k] = clean_firestore_data(v)
        elif isinstance(v, list):
            clean[k] = [clean_firestore_data(item) if isinstance(item, dict) else item for item in v]
        elif hasattr(v, '__class__') and str(v) == str(firestore.SERVER_TIMESTAMP):
            clean[k] = datetime.datetime.now().isoformat()
        else:
            clean[k] = v
    return clean

# ---------------- INTERNAL TRACKING FUNCTION ---------------- #
def track_user_view_internal(view_data, uid):
    """Internal function to track views without HTTP requests"""
    try:
        # Get user document reference
        user_ref = db.collection("users").document(uid)
        
        # Update the recent views array (limit to 50 most recent items)
        user_doc = user_ref.get()
        if user_doc.exists:
            current_views = user_doc.to_dict().get("recent_views", [])
            
            # Remove if already exists to avoid duplicates
            current_views = [v for v in current_views if not (v.get("id") == view_data["id"] and v.get("type") == view_data["type"])]
            
            # Add new view to beginning
            current_views.insert(0, view_data)
            
            # Limit to 50 most recent items
            if len(current_views) > 50:
                current_views = current_views[:50]
                
            # Update user document
            user_ref.update({"recent_views": current_views})
        else:
            # Create user document with initial view
            user_ref.set({"recent_views": [view_data]})
        
        print(f"✅ Tracked view for user {uid}: {view_data['type']} {view_data['id']}")
        return True
    
    except Exception as e:
        print(f"❌ Error in internal view tracking: {e}")
        return False

# ---------------- ROUTES ---------------- #
@app.route("/")
def welcome():
    return render_template("welcomepage.html")

@app.route("/login")
def login():
    return render_template("loginpage.html")

@app.route("/register")
def register():
    return render_template("registerpage.html")

# ---------------- SESSION LOGIN ---------------- #
@app.route("/sessionLogin", methods=["POST"])
def session_login():
    data = request.get_json()
    print("Received JSON from frontend:", data)
    
    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    id_token = data.get("idToken")
    if not id_token:
        return jsonify({"error": "No ID token provided"}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token["uid"]
        print(f"✅ Firebase token verified for UID: {uid}")

        user_doc = db.collection("users").document(uid).get()
        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 400

        user_data = user_doc.to_dict()
        session["uid"] = uid
        session["role"] = user_data.get("role", "user")
        session["email"] = user_data.get("email")

        print(f"✅ Session created for UID: {uid}, Role: {session['role']}")
        return jsonify({"success": True})

    except Exception as e:
        print("❌ Token verification error:", e)
        return jsonify({"error": str(e)}), 400

# ---------------- LOGOUT ---------------- #
@app.route("/logout")
def logout():
    uid = session.get("uid")
    session.clear()
    print(f"✅ Logged out UID: {uid}")
    return redirect(url_for("login"))

# ---------------- USER DASHBOARD ---------------- #
@app.route("/dashboard")
@login_required(role="user")
def dashboard():
    return render_template("home.html", user=session)

# ---------------- ADMIN DASHBOARD ---------------- #
@app.route("/admin")
@login_required(role="admin")
def admin_dashboard():
    return render_template("admindashboard.html", user=session)

# ---------------- API ENDPOINT TO FETCH USER DATA ---------------- #
@app.route("/api/user_data", methods=["GET"])
@login_required()
def get_user_data():
    """Fetches and returns the current user's data."""
    try:
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "error": "User not logged in"}), 401

        user_doc_ref = db.collection("users").document(uid)
        user_doc = user_doc_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            # It's a good practice to clean and sanitize data before sending
            clean_data = clean_firestore_data(user_data)
            return jsonify({"success": True, "user_data": clean_data})
        else:
            return jsonify({"success": False, "error": "User data not found"}), 404
    except Exception as e:
        print(f"❌ Error fetching user data via API: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ---------------- USER PROFILE ROUTE ---------------- #
@app.route("/profile")
@login_required()
def user_profile():
    """
    Fetches user data from Firestore and displays the user profile page.
    """
    try:
        # Get the user's UID from the session
        uid = session.get("uid")
        if not uid:
            # This should be handled by @login_required, but it's a good fail-safe
            return redirect(url_for("login"))

        # Fetch the user document from the 'users' collection
        user_doc_ref = db.collection("users").document(uid)
        user_doc = user_doc_ref.get()

        if user_doc.exists:
            # Convert Firestore data to a Python dictionary
            user_data = user_doc.to_dict()
            print(f"✅ Fetched user data for UID: {uid}")
            
            # Render the profile template with the user data
            return render_template("userprofile.html", user_data=user_data)
        else:
            print(f"❌ User document not found for UID: {uid}")
            return "User data not found.", 404
            
    except Exception as e:
        print(f"❌ Error fetching user profile: {e}")
        return "An error occurred.", 500

# ---------------- RECENT VIEWS API ENDPOINTS ---------------- #
@app.route("/api/user/track-view", methods=["POST"])
@login_required()
def track_user_view():
    """Track when a user views a blog or recipe"""
    try:
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "error": "User not logged in"}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        required_fields = ["type", "id", "title", "url"]
        for field in required_fields:
            if field not in data:
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        # Create view record
        view_data = {
            "type": data["type"],
            "id": data["id"],
            "title": data["title"],
            "description": data.get("description", ""),
            "image": data.get("image", ""),
            "url": data["url"],
            "viewedAt": firestore.SERVER_TIMESTAMP
        }
        
        # Use the internal tracking function
        success = track_user_view_internal(view_data, uid)
        
        if success:
            return jsonify({"success": True, "message": "View tracked successfully"})
        else:
            return jsonify({"success": False, "error": "Failed to track view"})
    
    except Exception as e:
        print(f"❌ Error tracking user view: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/user/recent-views", methods=["GET"])
@login_required()
def get_user_recent_views():
    """Get the current user's recently viewed blogs and recipes"""
    try:
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "error": "User not logged in"}), 401
        
        # Get user's document from Firestore
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            return jsonify({"success": True, "recent_views": []})
        
        user_data = user_doc.to_dict()
        recent_views = user_data.get("recent_views", [])
        
        # Clean the data for JSON response - FIXED VERSION
        cleaned_views = []
        for view in recent_views:
            # Convert Firestore data types to Python native types
            cleaned_view = {}
            for key, value in view.items():
                if hasattr(value, 'isoformat'):  # Handle datetime objects
                    cleaned_view[key] = value.isoformat()
                else:
                    cleaned_view[key] = value
            cleaned_views.append(cleaned_view)
        
        # Return the recent views
        return jsonify({
            "success": True, 
            "recent_views": cleaned_views
        })
    
    except Exception as e:
        print(f"❌ Error fetching user's recent views: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    

@app.route("/api/user/remove-recent-view", methods=["POST"])
@login_required()
def remove_recent_view():
    """Remove a specific item from user's recent views"""
    try:
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "error": "User not logged in"}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        view_id = data.get("viewId")
        view_type = data.get("viewType")
        
        if not view_id or not view_type:
            return jsonify({"success": False, "error": "Missing viewId or viewType"}), 400
        
        # Get user document reference
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            recent_views = user_data.get("recent_views", [])
            
            # Filter out the view to remove
            updated_views = [
                view for view in recent_views 
                if not (view.get("id") == view_id and view.get("type") == view_type)
            ]
            
            # Update user document
            user_ref.update({"recent_views": updated_views})
            
            return jsonify({"success": True, "message": "View removed successfully"})
        else:
            return jsonify({"success": False, "error": "User not found"}), 404
    
    except Exception as e:
        print(f"❌ Error removing recent view: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/user/clear-recent-views", methods=["POST"])
@login_required()
def clear_recent_views():
    """Clear all of user's recent views"""
    try:
        uid = session.get("uid")
        if not uid:
            return jsonify({"success": False, "error": "User not logged in"}), 401
        
        # Get user document reference
        user_ref = db.collection("users").document(uid)
        
        # Update user document to empty the recent views array
        user_ref.update({"recent_views": []})
        
        return jsonify({"success": True, "message": "Recent views cleared successfully"})
    
    except Exception as e:
        print(f"❌ Error clearing recent views: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ---------------- RECENT VIEWS PAGE ---------------- #
@app.route("/recent")
@login_required()
def recent_views():
    """Display the user's recently viewed blogs and recipes"""
    return render_template("recent.html", user=session)

# ---------------- BLOG MANAGEMENT API ENDPOINTS ---------------- #
@app.route("/api/blogs", methods=["GET"])
def get_blogs():
    """Get all published blog posts for the client site"""
    try:
        blogs_ref = db.collection("blogs")
        query = blogs_ref.where("status", "==", "published")
        blogs = query.stream()
        
        blog_list = []
        for blog in blogs:
            blog_data = clean_firestore_data(blog.to_dict())
            blog_data["id"] = blog.id
            blog_list.append(blog_data)
        
        blog_list.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        return jsonify({"success": True, "blogs": blog_list})
    
    except Exception as e:
        print(f"❌ Error fetching blogs: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/blog/<blog_id>", methods=["GET"])
def get_single_blog(blog_id):
    """Get a single blog post by ID"""
    try:
        blog_ref = db.collection("blogs").document(blog_id)
        blog_doc = blog_ref.get()
        
        if not blog_doc.exists:
            return jsonify({"success": False, "error": "Blog not found"}), 404
        
        blog_data = clean_firestore_data(blog_doc.to_dict())
        blog_data["id"] = blog_doc.id
        
        # Record view if user is logged in - DIRECT CALL instead of HTTP request
        if "uid" in session:
            try:
                # Prepare view data
                view_data = {
                    "type": "blog",
                    "id": blog_id,
                    "title": blog_data.get("title", "Untitled Blog"),
                    "description": blog_data.get("shortDesc", ""),
                    "image": blog_data.get("image", ""),
                    "url": f"/blog/{blog_id}"
                }
                
                # Call the tracking function directly
                track_user_view_internal(view_data, session.get("uid"))
            except Exception as e:
                print(f"⚠️ Could not track blog view: {e}")
                # Don't fail the request if tracking fails
        
        return jsonify({"success": True, "blog": blog_data})
    
    except Exception as e:
        print(f"❌ Error fetching single blog: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/blogs", methods=["GET"])
@login_required(role="admin")
def get_admin_blogs():
    """Get all blog posts for admin management (including drafts)"""
    try:
        blogs_ref = db.collection("blogs")
        blogs = blogs_ref.stream()
        
        blog_list = []
        for blog in blogs:
            blog_data = clean_firestore_data(blog.to_dict())
            blog_data["id"] = blog.id
            blog_list.append(blog_data)
        
        blog_list.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        return jsonify({"success": True, "blogs": blog_list})
    
    except Exception as e:
        print(f"❌ Error fetching admin blogs: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/blogs", methods=["POST"])
@login_required(role="admin")
def create_blog():
    """Create a new blog post"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        required_fields = ["title", "shortDesc", "content", "status"]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        blog_data = {
            "title": data["title"],
            "shortDesc": data["shortDesc"],
            "content": data["content"],
            "status": data["status"],
            "date": data.get("date", datetime.datetime.now().strftime("%Y-%m-%d")),
            "image": data.get("image", "https://placehold.co/600x400/3d3d3d/ffffff?text=Blog+Image"),
            "author": session.get("email", "Admin"),
            "authorId": session.get("uid"),
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP
        }
        
        blog_ref = db.collection("blogs").document()
        blog_ref.set(blog_data)
        
        blog_data["id"] = blog_ref.id
        safe_data = clean_firestore_data(blog_data)
        
        print(f"✅ Blog created successfully: {blog_ref.id}")
        return jsonify({"success": True, "blog": safe_data, "message": "Blog created successfully"})
    
    except Exception as e:
        print(f"❌ Error creating blog: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/blogs/<blog_id>", methods=["PUT"])
@login_required(role="admin")
def update_blog(blog_id):
    """Update an existing blog post"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        blog_ref = db.collection("blogs").document(blog_id)
        if not blog_ref.get().exists:
            return jsonify({"success": False, "error": "Blog not found"}), 404
        
        update_data = {"updatedAt": firestore.SERVER_TIMESTAMP}
        for field in ["title", "shortDesc", "content", "status", "date", "image"]:
            if field in data:
                update_data[field] = data[field]
        
        blog_ref.update(update_data)
        print(f"✅ Blog updated successfully: {blog_id}")
        return jsonify({"success": True, "message": "Blog updated successfully"})
    
    except Exception as e:
        print(f"❌ Error updating blog: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/blogs/<blog_id>", methods=["DELETE"])
@login_required(role="admin")
def delete_blog(blog_id):
    """Delete a blog post"""
    try:
        blog_ref = db.collection("blogs").document(blog_id)
        if not blog_ref.get().exists:
            return jsonify({"success": False, "error": "Blog not found"}), 404
        
        blog_ref.delete()
        print(f"✅ Blog deleted successfully: {blog_id}")
        return jsonify({"success": True, "message": "Blog deleted successfully"})
    
    except Exception as e:
        print(f"❌ Error deleting blog: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    
# ---------------- RECIPE MANAGEMENT API ENDPOINTS ---------------- #
@app.route("/api/recipes", methods=["GET"])
def get_recipes():
    """Get all published recipes for the client site"""
    try:
        recipes_ref = db.collection("recipes")
        query = recipes_ref.where("status", "==", "published")
        recipes = query.stream()
        
        recipe_list = []
        for recipe in recipes:
            recipe_data = clean_firestore_data(recipe.to_dict())
            recipe_data["id"] = recipe.id
            recipe_list.append(recipe_data)
        
        recipe_list.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        return jsonify({"success": True, "recipes": recipe_list})
    
    except Exception as e:
        print(f"❌ Error fetching recipes: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/recipe/<recipe_id>", methods=["GET"])
def get_single_recipe(recipe_id):
    """Get a single recipe by ID"""
    try:
        recipe_ref = db.collection("recipes").document(recipe_id)
        recipe_doc = recipe_ref.get()
        
        if not recipe_doc.exists:
            return jsonify({"success": False, "error": "Recipe not found"}), 404
        
        recipe_data = clean_firestore_data(recipe_doc.to_dict())
        recipe_data["id"] = recipe_doc.id
        
        # Record view if user is logged in - DIRECT CALL instead of HTTP request
        if "uid" in session:
            try:
                # Prepare view data
                view_data = {
                    "type": "recipe",
                    "id": recipe_id,
                    "title": recipe_data.get("title", "Untitled Recipe"),
                    "description": recipe_data.get("shortDesc", ""),
                    "image": recipe_data.get("image", ""),
                    "url": f"/recipe/{recipe_id}"
                }
                
                # Call the tracking function directly
                track_user_view_internal(view_data, session.get("uid"))
            except Exception as e:
                print(f"⚠️ Could not track recipe view: {e}")
                # Don't fail the request if tracking fails
        
        return jsonify({"success": True, "recipe": recipe_data})
    
    except Exception as e:
        print(f"❌ Error fetching single recipe: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/recipes", methods=["GET"])
@login_required(role="admin")
def get_admin_recipes():
    """Get all recipes for admin management (including drafts)"""
    try:
        recipes_ref = db.collection("recipes")
        recipes = recipes_ref.stream()
        
        recipe_list = []
        for recipe in recipes:
            recipe_data = clean_firestore_data(recipe.to_dict())
            recipe_data["id"] = recipe.id
            recipe_list.append(recipe_data)
        
        recipe_list.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
        return jsonify({"success": True, "recipes": recipe_list})
    
    except Exception as e:
        print(f"❌ Error fetching admin recipes: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/recipes", methods=["POST"])
@login_required(role="admin")
def create_recipe():
    """Create a new recipe"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        required_fields = ["title", "shortDesc", "content", "status"]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        # Process ingredients and instructions from textarea input
        ingredients = data.get("ingredients", [])
        if isinstance(ingredients, str):
            # Split by newline and filter out empty lines
            ingredients = [line.strip() for line in ingredients.split('\n') if line.strip()]
        
        instructions = data.get("instructions", [])
        if isinstance(instructions, str):
            # Split by newline and filter out empty lines
            instructions = [line.strip() for line in instructions.split('\n') if line.strip()]
        
        # Process tags from comma-separated string
        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(',') if tag.strip()]
        
        # Additional recipe-specific fields
        recipe_data = {
            "title": data["title"],
            "shortDesc": data["shortDesc"],
            "content": data["content"],
            "status": data["status"],
            "date": data.get("date", datetime.datetime.now().strftime("%Y-%m-%d")),
            "image": data.get("image", "https://placehold.co/600x400/3d3d3d/ffffff?text=Recipe+Image"),
            "author": session.get("email", "Admin"),
            "authorId": session.get("uid"),
            "prepTime": data.get("prepTime", ""),
            "cookTime": data.get("cookTime", ""),
            "servings": data.get("servings", ""),
            "ingredients": ingredients,
            "instructions": instructions,
            "tags": tags,
            "category": data.get("category", ""),
            "createdAt": firestore.SERVER_TIMESTAMP,
            "updatedAt": firestore.SERVER_TIMESTAMP
        }
        
        recipe_ref = db.collection("recipes").document()
        recipe_ref.set(recipe_data)
        
        recipe_data["id"] = recipe_ref.id
        safe_data = clean_firestore_data(recipe_data)
        
        print(f"✅ Recipe created successfully: {recipe_ref.id}")
        return jsonify({"success": True, "recipe": safe_data, "message": "Recipe created successfully"})
    
    except Exception as e:
        print(f"❌ Error creating recipe: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/recipes/<recipe_id>", methods=["PUT"])
@login_required(role="admin")
def update_recipe(recipe_id):
    """Update an existing recipe"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        recipe_ref = db.collection("recipes").document(recipe_id)
        if not recipe_ref.get().exists:
            return jsonify({"success": False, "error": "Recipe not found"}), 404
        
        # Process ingredients and instructions if they're provided as strings
        update_data = {"updatedAt": firestore.SERVER_TIMESTAMP}
        
        # Standard fields
        for field in ["title", "shortDesc", "content", "status", "date", "image"]:
            if field in data:
                update_data[field] = data[field]
        
        # Recipe-specific fields with special processing
        if "ingredients" in data:
            if isinstance(data["ingredients"], str):
                # Split by newline and filter out empty lines
                update_data["ingredients"] = [line.strip() for line in data["ingredients"].split('\n') if line.strip()]
            else:
                update_data["ingredients"] = data["ingredients"]
                
        if "instructions" in data:
            if isinstance(data["instructions"], str):
                # Split by newline and filter out empty lines
                update_data["instructions"] = [line.strip() for line in data["instructions"].split('\n') if line.strip()]
            else:
                update_data["instructions"] = data["instructions"]
                
        if "tags" in data:
            if isinstance(data["tags"], str):
                # Split by comma and filter out empty tags
                update_data["tags"] = [tag.strip() for tag in data["tags"].split(',') if tag.strip()]
            else:
                update_data["tags"] = data["tags"]
        
        # Other recipe fields
        for field in ["prepTime", "cookTime", "servings", "category"]:
            if field in data:
                update_data[field] = data[field]
        
        recipe_ref.update(update_data)
        print(f"✅ Recipe updated successfully: {recipe_id}")
        return jsonify({"success": True, "message": "Recipe updated successfully"})
    
    except Exception as e:
        print(f"❌ Error updating recipe: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/admin/recipes/<recipe_id>", methods=["DELETE"])
@login_required(role="admin")
def delete_recipe(recipe_id):
    """Delete a recipe"""
    try:
        recipe_ref = db.collection("recipes").document(recipe_id)
        if not recipe_ref.get().exists:
            return jsonify({"success": False, "error": "Recipe not found"}), 404
        
        recipe_ref.delete()
        print(f"✅ Recipe deleted successfully: {recipe_id}")
        return jsonify({"success": True, "message": "Recipe deleted successfully"})
    
    except Exception as e:
        print(f"❌ Error deleting recipe: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# ---------------- GROUP/COMMUNITY API ENDPOINTS ---------------- #
@app.route("/api/groups", methods=["GET"])
@login_required()
def get_groups():
    """Get all community groups"""
    try:
        groups_ref = db.collection("groups")
        groups = groups_ref.stream()
        group_list = []
        for group in groups:
            group_data = clean_firestore_data(group.to_dict())
            group_data["id"] = group.id
            
            # Get member count from the members subcollection
            members_ref = db.collection("groups").document(group.id).collection("members")
            member_count = len(list(members_ref.stream()))
            group_data["memberCount"] = member_count
            
            # Get message count from the messages subcollection
            messages_ref = db.collection("groups").document(group.id).collection("messages")
            message_count = len(list(messages_ref.stream()))
            group_data["messagesCount"] = message_count
            
            group_list.append(group_data)
        return jsonify(group_list)
    except Exception as e:
        print(f"❌ Error fetching groups: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/groups", methods=["POST"])
@login_required()
def create_group():
    """Create a new community group"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400
        
        required_fields = ["name", "description", "category"]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"success": False, "error": f"Missing required field: {field}"}), 400
        
        # Create the group
        group_ref = db.collection("groups").document()
        group_data = {
            "name": data["name"],
            "description": data["description"],
            "category": data["category"],
            "createdBy": session.get("uid"),
            "createdByEmail": session.get("email"),
            "createdAt": firestore.SERVER_TIMESTAMP,
            "image": data.get("image", "https://placehold.co/400x300/3b82f6/ffffff?text=Fitness+Group")
        }
        group_ref.set(group_data)
        
        # Add the creator as the first member
        members_ref = group_ref.collection("members").document(session.get("uid"))
        members_ref.set({
            "userId": session.get("uid"),
            "userEmail": session.get("email"),
            "joinedAt": firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({"id": group_ref.id, "success": True}), 201
    except Exception as e:
        print(f"❌ Error creating group: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/groups/<group_id>", methods=["GET"])
@login_required()
def get_group(group_id):
    """Get a specific group by ID"""
    try:
        group_ref = db.collection("groups").document(group_id)
        group_doc = group_ref.get()
        
        if not group_doc.exists:
            return jsonify({"success": False, "error": "Group not found"}), 404
        
        group_data = clean_firestore_data(group_doc.to_dict())
        group_data["id"] = group_doc.id
        
        # Get member count
        members_ref = group_ref.collection("members")
        member_count = len(list(members_ref.stream()))
        group_data["memberCount"] = member_count
        
        # Get message count
        messages_ref = group_ref.collection("messages")
        message_count = len(list(messages_ref.stream()))
        group_data["messagesCount"] = message_count
        
        return jsonify(group_data)
    except Exception as e:
        print(f"❌ Error fetching group: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/groups/<group_id>/join", methods=["POST"])
@login_required()
def join_group(group_id):
    """Join a community group"""
    try:
        group_ref = db.collection("groups").document(group_id)
        group_doc = group_ref.get()
        
        if not group_doc.exists:
            return jsonify({"success": False, "error": "Group not found"}), 404
        
        # Check if user is already a member
        member_ref = group_ref.collection("members").document(session.get("uid"))
        member_doc = member_ref.get()
        
        if member_doc.exists:
            return jsonify({"success": False, "error": "Already a member"}), 400
        
        # Add user as a member
        member_ref.set({
            "userId": session.get("uid"),
            "userEmail": session.get("email"),
            "joinedAt": firestore.SERVER_TIMESTAMP
        })
        
        return jsonify({"success": True, "message": "Joined group successfully"})
    except Exception as e:
        print(f"❌ Error joining group: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/groups/<group_id>/messages", methods=["GET"])
@login_required()
def get_messages(group_id):
    """Get messages from a group"""
    try:
        # Check if user is a member of the group
        member_ref = db.collection("groups").document(group_id).collection("members").document(session.get("uid"))
        member_doc = member_ref.get()
        
        if not member_doc.exists:
            return jsonify({"success": False, "error": "Not a member of this group"}), 403
        
        messages_ref = db.collection("groups").document(group_id).collection("messages")
        messages = messages_ref.order_by("timestamp", direction=firestore.Query.DESCENDING).limit(50).stream()
        
        message_list = []
        for message in messages:
            message_data = clean_firestore_data(message.to_dict())
            message_data["id"] = message.id
            message_list.append(message_data)
        
        # Reverse to show oldest first
        message_list.reverse()
        return jsonify(message_list)
    except Exception as e:
        print(f"❌ Error fetching messages: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/groups/<group_id>/messages", methods=["POST"])
@login_required()
def send_message(group_id):
    """Send a message to a group"""
    try:
        # Check if user is a member of the group
        member_ref = db.collection("groups").document(group_id).collection("members").document(session.get("uid"))
        member_doc = member_ref.get()
        
        if not member_doc.exists:
            return jsonify({"success": False, "error": "Not a member of this group"}), 403
        
        data = request.get_json()
        if not data or "content" not in data or not data["content"].strip():
            return jsonify({"success": False, "error": "Message content required"}), 400
        
        # Add the message
        messages_ref = db.collection("groups").document(group_id).collection("messages")
        messages_ref.add({
            "user": session.get("email"),
            "userId": session.get("uid"),
            "content": data["content"].strip(),
            "timestamp": firestore.SERVER_TIMESTAMP,
            "avatar": session.get("avatar", "https://placehold.co/32x32/3b82f6/ffffff?text=U")
        })
        
        return jsonify({"success": True, "message": "Message sent"}), 201
    except Exception as e:
        print(f"❌ Error sending message: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/user/groups", methods=["GET"])
@login_required()
def get_user_groups():
    """Get groups the current user has joined"""
    try:
        # Query all groups where the user is a member
        groups_ref = db.collection("groups")
        user_groups = []
        
        # Get all groups
        all_groups = groups_ref.stream()
        for group in all_groups:
            # Check if user is a member of this group
            member_ref = groups_ref.document(group.id).collection("members").document(session.get("uid"))
            member_doc = member_ref.get()
            
            if member_doc.exists:
                group_data = clean_firestore_data(group.to_dict())
                group_data["id"] = group.id
                
                # Get member count
                members_ref = groups_ref.document(group.id).collection("members")
                member_count = len(list(members_ref.stream()))
                group_data["memberCount"] = member_count
                
                user_groups.append(group_data)
        
        return jsonify(user_groups)
    except Exception as e:
        print(f"❌ Error fetching user groups: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    
#-----------------------------------------------------------#
@app.route("/api/debug/user-data")
@login_required()
def debug_user_data():
    """Debug endpoint to check user data structure"""
    try:
        uid = session.get("uid")
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()
        
        if user_doc.exists:
            user_data = user_doc.to_dict()
            print(f"DEBUG: User data for {uid}: {user_data}")
            
            # Check if recent_views exists and its structure
            recent_views = user_data.get("recent_views", [])
            print(f"DEBUG: Recent views count: {len(recent_views)}")
            for i, view in enumerate(recent_views):
                print(f"DEBUG: View {i}: {view}")
            
            return jsonify({
                "success": True,
                "user_data": user_data,
                "recent_views_count": len(recent_views)
            })
        else:
            return jsonify({"success": False, "error": "User not found"})
            
    except Exception as e:
        print(f"DEBUG Error: {e}")
        return jsonify({"success": False, "error": str(e)})


# ---------------- OTHER PROTECTED ROUTES ---------------- #
@app.route("/menu")
@login_required()
def menu():
    return render_template("menu.html", user=session)

@app.route("/services")
@login_required()
def services():
    return render_template("ourservices.html", user=session)

@app.route("/aboutus")
@login_required()
def aboutus():
    return render_template("aboutus.html", user=session)

@app.route("/blog")
@login_required()
def blog():
    return render_template("blog.html", user=session)

@app.route("/blogdisplay")
@login_required()
def blogdisplay():
    return render_template("blogdisplay.html", user=session)

@app.route('/recipes')
@login_required()
def recipes():
    return render_template('recipes.html')

@app.route("/recipe/<recipe_id>")
@login_required()
def recipe_detail(recipe_id):
    return render_template("recipe_detail.html", user=session)

@app.route("/exercise-library")
@login_required()
def exercise_library():
    return render_template("weightlifting.html", user=session)

@app.route("/cross_fit")
@login_required()
def cross_fit():
    return render_template("crossfit.html", user=session)

@app.route("/muscles_strength")
@login_required()
def muscles_strength():
    return render_template("musclesstrength.html", user=session)

@app.route("/cardio_strength")
@login_required()
def cardio_strength():
    return render_template("cardiostrength.html", user=session)

@app.route("/body_balance")
@login_required()
def body_balance():
    return render_template("bodybalance.html", user=session)

@app.route("/beginner_pilates")
@login_required()
def beginner_pilates():
    return render_template("beginnerpilates.html", user=session)

@app.route("/community")
@login_required()
def community():
    return render_template("community.html", user=session)

@app.route("/alter")
@login_required()
def alter():
    return render_template("workoutrecommondation.html", user=session)

# ---------------- ADMIN CONTENT ---------------- #
@app.route("/admin/content")
@login_required(role="admin")
def admin_content():
    return render_template("adminblog.html", user=session)

@app.route("/admin/recipes")
@login_required(role="admin")
def admin_recipes():
    return render_template("adminrecipes.html", user=session)

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
