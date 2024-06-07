<?php
include 'db.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'] ?? '';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Define password validation pattern
    $password_pattern = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/";

    // Check if all fields are filled
    if (!empty($email) && !empty($username) && !empty($password) && !empty($confirm_password)) {
        // Check if passwords match
        if ($password === $confirm_password) {
            // Validate password format
            if (preg_match($password_pattern, $password)) {
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                $sql = "INSERT INTO users (email, username, password) VALUES (?, ?, ?)";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("sss", $email, $username, $hashed_password);

                if ($stmt->execute()) {
                    // Show success message and redirect
                    echo "<script>alert('Registration successful!'); window.location.href='assets.html';</script>";
                } else {
                    echo "Error: " . $stmt->error;
                }
                $stmt->close();
            } else {
                echo "Password must be at least 6 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.";
            }
        } else {
            echo "Passwords do not match!";
        }
    } else {
        echo "All fields are required!";
    }
}
$conn->close();
?>
