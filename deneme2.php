
<?php
$conn = new mysqli("localhost", "root", "", "test");

$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);

$username = $_GET['username'];
$password = $_GET['password'];
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows > 0) {
    echo "Giriş başarılı!";
} else {
    echo "Hatalı kullanıcı adı veya şifre!";
}
?>
