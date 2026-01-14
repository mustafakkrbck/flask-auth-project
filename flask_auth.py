import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime

# Brute-force koruması (basit, bellek içi)
basarisizgiris = {}
maxgiris=3
kilitsaniyesi=3*60
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "varsayilan_key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users2.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
limiter=Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    isim = db.Column(db.String(50), unique=True, nullable=False)
    sifre = db.Column(db.String(200), nullable=False)
    yas = db.Column(db.Integer, nullable=False)
    rol = db.Column(db.String(20), default="user")
    guvenliksorusu=db.Column(db.String(100),nullable=False)
    guvenlikcevap=db.Column(db.String(200),nullable=False)
    def __repr__(self):
        return f"<User {self.isim}>"

class BlogPost(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    baslik=db.Column(db.String(50),unique=True,nullable=False)
    icerik=db.Column(db.Text,nullable=False)
    tarih=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    kullanici_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    yazar=db.relationship('User',backref=db.backref('posts',lazy=True))
    
@app.route("/blog")
def blog():
    """Tüm Blog Gönderilerini Listele"""
    posts=BlogPost.query.order_by(BlogPost.tarih.desc()).all()
    return render_template("blog.html",posts=posts)

@app.route("/karar")
@login_required
def kararsayfasi():
    """Kullanıcının giriş sonrası nereye gideceğini seçeceği sayfa"""
    return render_template("karar.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("kararsayfasi"))
    return redirect(url_for("login"))

@app.route("/user_list")
@login_required
def get_users():
    users = User.query.all()
    return render_template("form3.html", users=users)

#Yeni Blog Gönderisi Oluşturma Rotası
@app.route("/yeni_gonderi", methods=["GET", "POST"])
@login_required
def yeni_gonderi():
    if request.method == "POST":
        baslik = request.form.get("baslik").strip()
        icerik = request.form.get("icerik")

        if not baslik or not icerik:
            flash("Başlık ve içerik alanları boş bırakılamaz.", "error")
            return redirect(url_for("yeni_gonderi"))
        
        # Başlığın benzersizliğini kontrol et (BlogPost modelinde unique=True)
        if BlogPost.query.filter_by(baslik=baslik).first():
             flash("Bu başlıkta bir gönderi zaten mevcut. Lütfen farklı bir başlık seçin.", "error")
             return render_template("gonderi_formu.html")
             
        yeni_post = BlogPost(baslik=baslik, icerik=icerik, kullanici_id=current_user.id)
        db.session.add(yeni_post)
        db.session.commit()
        flash("Blog gönderisi başarıyla oluşturuldu!", "success")
        return redirect(url_for("blog"))

    # Yeni gönderi formu (gonderi_formu.html) render edilir.
    return render_template("gonderi_formu.html")

#Gönderiyi Görüntüleme Rotası
@app.route("/gonderi/<int:post_id>")
def gonderi(post_id):
    post = BlogPost.query.get_or_404(post_id)
    # gonderi.html şablonu post değişkenini bekliyor
    return render_template("gonderi.html", post=post)

#Gönderiyi Düzenleme Rotası
@app.route("/duzenle_gonderi/<int:post_id>", methods=["GET", "POST"])
@login_required
def duzenle_gonderi(post_id):
    post = BlogPost.query.get_or_404(post_id)

    # Yetkilendirme Kontrolü (Sadece gönderi sahibi veya admin düzenleyebilir)
    if post.kullanici_id != current_user.id and current_user.rol != "admin":
        flash("Bu gönderiyi düzenleme yetkiniz yok.", "error")
        return redirect(url_for("gonderi", post_id=post.id))

    if request.method == "POST":
        yeni_baslik = request.form.get("baslik").strip()
        yeni_icerik = request.form.get("icerik")
        
        if not yeni_baslik or not yeni_icerik:
            flash("Başlık ve içerik alanları boş bırakılamaz.", "error")
            return redirect(url_for("duzenle_gonderi", post_id=post.id))

        # Başlık değiştirilmişse ve yeni başlık zaten varsa kontrol et
        if yeni_baslik != post.baslik and BlogPost.query.filter_by(baslik=yeni_baslik).first():
            flash("Bu başlıkta başka bir gönderi zaten mevcut.", "error")
            return render_template("gonderi_formu.html", post=post)

        post.baslik = yeni_baslik
        post.icerik = yeni_icerik
        db.session.commit()
        flash("Gönderi başarıyla güncellendi.", "success")
        return redirect(url_for("gonderi", post_id=post.id))

    # Düzenleme formu (gonderi_formu.html) render edilir.
    return render_template("gonderi_formu.html", post=post)

#Gönderiyi Silme Rotası
@app.route("/sil_gonderi/<int:post_id>", methods=["POST"])
@login_required
def sil_gonderi(post_id):
    post = BlogPost.query.get_or_404(post_id)

    # Yetkilendirme Kontrolü (Sadece gönderi sahibi veya admin silebilir)
    if post.kullanici_id != current_user.id and current_user.rol != "admin":
        flash("Bu gönderiyi silme yetkiniz yok.", "error")
        return redirect(url_for("gonderi", post_id=post.id))

    db.session.delete(post)
    db.session.commit()
    flash("Gönderi başarıyla silindi.", "success")
    return redirect(url_for("blog"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        isim = request.form.get("isim").strip()
        yas = request.form.get("yas")
        sifre = request.form.get("sifre")
        guvenliksorusu=request.form.get("guvenliksorusu")
        guvenlikcevap=request.form.get("guvenlikcevap")
        if not isim or len(isim) < 3:
            flash("Kullanıcı adı en az 3 karakter olmalı!", "error")
            return redirect(url_for("register"))
        if not sifre or len(sifre) < 6:
            flash("Şifre en az 6 karakter olmalı!", "error")
            return redirect(url_for("register"))
        if not guvenliksorusu or not guvenlikcevap:
            flash("Güvenlik Sorusu zorunludur.","error")
            return redirect(url_for("register"))
        if len(guvenlikcevap.strip())<3:
            flash("Güvenlik cevabı çok kısa","error")
            return redirect(url_for("register"))
        try:
            yas = int(yas)
            if yas < 1 or yas > 120:
                flash("Geçerli bir yaş girin (1-120)!", "error")
                return redirect(url_for("register"))
        except (ValueError, TypeError):
            flash("Yaş geçerli bir sayı olmalı!", "error")
            return redirect(url_for("register"))
        

        if User.query.filter_by(isim=isim).first():
            flash("Bu kullanıcı adı zaten alınmış!", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(sifre, method='pbkdf2:sha256')
        hashed_guvenlik=generate_password_hash(guvenlikcevap.strip(),method='pbkdf2:sha256')
        if User.query.count() == 0:
            yeni_kullanici = User(isim=isim, yas=yas, sifre=hashed_pw, rol="admin",guvenliksorusu=guvenliksorusu,guvenlikcevap=hashed_guvenlik)
        else:
            yeni_kullanici = User(isim=isim, yas=yas, sifre=hashed_pw, rol="user",guvenliksorusu=guvenliksorusu,guvenlikcevap=hashed_guvenlik)

        db.session.add(yeni_kullanici)
        db.session.commit()
        flash("Kullanıcı başarıyla kayıt oldu.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("3 per minute", key_func=lambda: request.form.get("isim", "anonim"))
def login():
    if current_user.is_authenticated:
        return redirect(url_for("kararsayfasi"))
        
    if request.method == "POST":
        isim = request.form.get("isim").strip()
        sifre = request.form.get("sifre")
        user = User.query.filter_by(isim=isim).first()
        if not isim:
            flash("Kullanıcı adı giriniz.","error")
            return redirect(url_for("login"))

        if not user or not check_password_hash(user.sifre, sifre):
            flash("Kullanıcı adı veya şifre yanlış.", "error")
            return redirect(url_for("login"))

        login_user(user)
        flash(f"Giriş başarılı! Hoş geldin {user.isim}", "success")
        return redirect(url_for("kararsayfasi")) 
        
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop("user_id", None)
    session.pop("username", None)
    flash("Başarıyla çıkış yapıldı.", "success")
    return redirect(url_for("login"))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/sifredegistir", methods=["POST"])
@login_required
def sifredegistir():
    eskisifre = request.form.get("eskisifre")
    yenisifre = request.form.get("yenisifre")

    if not check_password_hash(current_user.sifre, eskisifre):
        flash("Eski şifre yanlış.", "error")
        return redirect(url_for("profile"))
    if len(yenisifre) < 6:
        flash("Yeni şifre en az 6 haneli olmalıdır.", "error")
        return redirect(url_for("profile"))
    if yenisifre == eskisifre:
        flash("Yeni şifre eski şifreyle aynı olamaz.", "error")
        return redirect(url_for("profile"))

    current_user.sifre = generate_password_hash(yenisifre, method='pbkdf2:sha256')
    db.session.commit()
    flash("Şifre başarıyla güncellendi.", "success")
    return redirect(url_for("profile"))

@app.route("/profilguncelleme", methods=["POST"])
@login_required
def profilguncelleme():
    isim = request.form.get("isim").strip()
    yas = request.form.get("yas")

    if len(isim) < 3:
        flash("İsim en az 3 karakter olmalı.", "error")
        return redirect(url_for("profile"))
    try:
        yas = int(yas)
        if yas < 1 or yas > 120:
            flash("Yaş 1 ile 120 arasında olmalı.", "error")
            return redirect(url_for("profile"))
    except (ValueError, TypeError):
        flash("Yaş geçerli bir sayı olmalıdır.", "error")
        return redirect(url_for("profile"))
    
    mevcut_kullanici = User.query.filter_by(isim=isim).first()
    if mevcut_kullanici and mevcut_kullanici.id != current_user.id:
        flash("Bu kullanıcı adı zaten kullanılıyor!", "error")
        return redirect(url_for("profile"))

    current_user.isim = isim
    current_user.yas = yas
    db.session.commit()
    flash("İsim ve yaş bilgileri başarıyla güncellendi.", "success")
    return redirect(url_for("profile"))

def adminrequired(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.rol != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin")
@login_required
@adminrequired
def adminpanel():
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
@adminrequired
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.rol == "admin":
        flash("Admin kullanıcı silinemez!", "error")
    else:
        # Silinecek kullanıcının tüm blog gönderilerini de sil
        BlogPost.query.filter_by(kullanici_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash("Kullanıcı başarıyla silindi.", "success")
    return redirect(url_for("adminpanel"))

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_own_account():
    user = current_user
    if user.rol == "admin":
        flash("Admin kendi hesabını silemez!", "error")
        return redirect(url_for("profile"))
    
    # Kullanıcının tüm blog gönderilerini sil
    BlogPost.query.filter_by(kullanici_id=user.id).delete()
    db.session.commit()
    
    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Hesabınız başarıyla silindi.", "success")
    return redirect(url_for("register"))

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    security_question = None
    isim = None

    if request.method == "POST":
        isim = request.form.get("isim").strip()
        guvenlikcevap = request.form.get("guvenlikcevap")

        user = User.query.filter_by(isim=isim).first()
        if not user:
            flash("Kullanıcı bulunamadı.", "error")
            return redirect(url_for("forgot_password"))

        # Eğer cevap gönderildiyse, kontrol et
        if guvenlikcevap:
            if check_password_hash(user.guvenlikcevap, guvenlikcevap.strip()):
                return redirect(url_for("reset_password", user_id=user.id))
            else:
                flash("Güvenlik cevabı yanlış.", "error")
                return render_template("forgot_password.html", security_question=user.guvenliksorusu, isim=isim)
        else:
            # Sadece kullanıcı adı girildiyse soruyu göster
            security_question = user.guvenliksorusu

    return render_template("forgot_password.html", security_question=security_question, isim=isim)

@app.route("/reset_password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        yenisifre = request.form.get("yenisifre")

        if len(yenisifre) < 6:
            flash("Şifre en az 6 karakter olmalı!", "error")
            return redirect(url_for("reset_password", user_id=user_id))

        user.sifre = generate_password_hash(yenisifre, method='pbkdf2:sha256')
        db.session.commit()
        flash("Şifre başarıyla sıfırlandı. Yeni şifrenizle giriş yapabilirsiniz.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", user=user)
    
@app.route("/change/<int:user_id>", methods=["POST"])
@login_required
@adminrequired
def changerole(user_id):
    user = User.query.get_or_404(user_id)

    # Kendi adminliğini değiştirmesin
    if user.id == current_user.id:
        flash("Kendi rolünüzü değiştiremezsiniz.", "error")
        return redirect(url_for("adminpanel"))

    # Son admin kontrolü
    if user.rol == "admin":
        toplam_admin = User.query.filter_by(rol="admin").count()
        if toplam_admin <= 1:
            flash("Sistemde en az bir admin kalmalı!", "error")
            return redirect(url_for("adminpanel"))

    # Rolü değiştir
    if user.rol == "admin":
        user.rol = "user"
        flash(f"{user.isim} artık bir kullanıcı (user).", "success")
    else:
        user.rol = "admin"
        flash(f"{user.isim} artık bir admin.", "success")

    db.session.commit()
    return redirect(url_for("adminpanel"))
    
@app.route("/guvenlikguncelle",methods=["POST"])
@login_required
def guvenlikguncelle():
    yenisoru=request.form.get("yeniguvenliksorusu")
    yenicevap=request.form.get("yeniguvenlikcevap")
    if not yenisoru or not yenicevap:
        flash("Güvenlik sorusu ve cevabı boş bırakılamaz. ","error")
        return redirect(url_for("profile"))
    if len(yenicevap)<3:
        flash("Güvenlik cevabı çok kısa.","error")
        return redirect(url_for("profile"))
    hashedcevap=generate_password_hash(yenicevap,method='pbkdf2:sha256')
    current_user.guvenliksorusu=yenisoru
    current_user.guvenlikcevap=hashedcevap
    db.session.commit()
    flash("Güvenlik sorusu ve cevabı güncellendi.","success")
    return redirect(url_for("profile"))
    
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"),429
    
if __name__ == "__main__":
    app.run(debug=True)
