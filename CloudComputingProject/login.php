<?php
include 'db.php';
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'] ?? '';

    if (!empty($email) && !empty($password)) {
        $sql = "SELECT id, username, password FROM users WHERE email = ?";
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $stmt->store_result();
            $stmt->bind_result($id, $username, $hashed_password);

            if ($stmt->num_rows > 0) {
                $stmt->fetch();
                if (password_verify($password, $hashed_password)) {
                    $_SESSION['user_id'] = $id;
                    $_SESSION['username'] = $username;
                    header("Location: assets.html");
                    exit();
                } else {
                    echo "Invalid password!";
                }
            } else {
                echo "No user found with that email!";
            }
            $stmt->close();
        } else {
            echo "Database query failed: " . $conn->error;
        }
    } else {
        echo "Email and password are required!";
    }
}
$conn->close();
?>
