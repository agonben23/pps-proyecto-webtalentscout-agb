<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    // Consulta preparada para evitar la inyección SQL
    $query = 'SELECT userId, password FROM users WHERE username = :username';
    $stmt = $db->prepare($query);
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);
    
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        return FALSE;  // Usuario no encontrado
    }

    // Comparación directa de la contraseña
    if ($password == $row['password']) {
        $userId = $row['userId'];
        session_start(); 
        $_SESSION['userId'] = $userId; // Usa sesión para almacenar la id del usuario
        return TRUE;
    } else {
        return FALSE;  // Contraseña incorrecta
    }
}


# On login
if (isset($_POST['username'])) {		
	$_SESSION['user'] = $_POST['username']; // Usa session en vez de cookies
    if(isset($_POST['password']))
	    $_SESSION['password'] = $_POST['password'];
    else
        $_SESSION['password'] = "";
} else {
    if (!isset($_POST['Logout']) && !isset($_SESSION['user'])) {
        $_SESSION['user'] = "";
        $_SESSION['password'] = "";
    }
}

# On logout
if (isset($_POST['Logout'])) {
	// Elimina todas las variables de sesión
    session_unset();

    // Destruye la sesión
    session_destroy();

	header("Location: index.php");
}


# Check user and password
if (isset($_SESSION['user']) && isset($_SESSION['password'])) {
	if (areUserAndPasswordValid($_SESSION['user'], $_SESSION['password'])) {
		$login_ok = TRUE;
		$error = "";
	} else {
		$login_ok = FALSE;
		$error = "Invalid user or password.<br>";
	}
} else {
	$login_ok = FALSE;
	$error = "This page requires you to be logged in.<br>";
}

if ($login_ok == FALSE) {

?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username"><br>
                    <label>Password</label>
                    <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    <?php
    exit (0);
}

#setcookie('user', $_COOKIE['user']);
#setcookie('password', $_COOKIE['password']);


?>
