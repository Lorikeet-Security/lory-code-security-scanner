<?php
// Fixture only.
$conn = mysqli_connect("localhost", "root", "toor");

$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM accounts WHERE id = " . $_GET['id']);

echo "<p>Welcome back, " . $_GET['name'] . "</p>";

include($_GET['page'] . ".php");

$data = unserialize($_COOKIE['prefs']);

system("convert " . $_POST['file'] . " /tmp/out.png");

ini_set('display_errors', 1);
setcookie("session", $token);
