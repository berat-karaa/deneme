<?php
// Kullanıcıdan gelen veriyi doğrudan SQL sorgusuna yerleştiriyor - TEHLİKELİ
$conn = mysqli_connect("localhost", "root", "", "test");

$username = $_GET['username'];
$password = $_GET['password'];

$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    echo "Giriş başarılı!";
} else {
    echo "Hatalı kullanıcı adı veya şifre!";
}
?>
