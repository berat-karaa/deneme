<?php
// Veritabanı bağlantısı
$conn = new mysqli("localhost", "root", "", "secure_app");

// Bağlantı hatası kontrolü
if ($conn->connect_error) {
    die("Veritabanı bağlantı hatası: " . $conn->connect_error);
}

// Kullanıcı kaydı için fonksiyon
function registerUser($username, $password, $conn) {
    // Kullanıcı adını temizleme ve doğrulama
    $username = filter_var($username, FILTER_SANITIZE_STRING);

    // Şifreyi hashleme (bcrypt kullanılarak)
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    // Kullanıcıyı veritabanına ekleme
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    if (!$stmt) {
        die("SQL hatası: " . $conn->error);
    }
    $stmt->bind_param("ss", $username, $hashedPassword);
    $stmt->execute();
    $stmt->close();
}

// Kullanıcı giriş doğrulama fonksiyonu
function loginUser($username, $password, $conn) {
    // Kullanıcı adını temizleme ve doğrulama
    $username = filter_var($username, FILTER_SANITIZE_STRING);

    // Kullanıcıyı veritabanından getirme
    $stmt = $conn->prepare("SELECT password FROM users WHERE username = ?");
    if (!$stmt) {
        die("SQL hatası: " . $conn->error);
    }
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $hashedPassword = $user['password'];

        // Şifre doğrulama
        if (password_verify($password, $hashedPassword)) {
            echo "Giriş başarılı!";
        } else {
            echo "Hatalı şifre!";
        }
    } else {
        echo "Kullanıcı bulunamadı!";
    }
    $stmt->close();
}

// Kullanıcı kaydı örneği
registerUser("test_user", "secure_password123", $conn);

// Kullanıcı giriş örneği
loginUser("test_user", "secure_password123", $conn);

$conn->close();
?>
