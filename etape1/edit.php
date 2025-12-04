<?php
require_once '../config.php';

$pdo = getConnection();
$errors = [];

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
if ($id <= 0) {
    header('Location: index.php');
    exit;
}

// Charger l'utilisateur
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute([':id' => $id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    die("Utilisateur introuvable.");
}

$email = $user['email'];
$role  = $user['role'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = cleanInput($_POST['email'] ?? '');
    $role = $_POST['role'] ?? 'guest';
    $newPassword = $_POST['password'] ?? '';

    if (empty($email) || !validateEmail($email)) {
        $errors[] = "Email invalide.";
    }

    $rolesAutorises = ['guest', 'author', 'editor', 'admin'];
    if (!in_array($role, $rolesAutorises, true)) {
        $errors[] = "Rôle invalide.";
    }

    if (empty($errors)) {
        // Si un nouveau mot de passe est saisi, on le modifie 
        if (!empty($newPassword)) {
            if (strlen($newPassword) < 6) {
                $errors[] = "Le mot de passe doit contenir au moins 6 caractères.";
            } else {
                $sql = "UPDATE users SET email = :email, role = :role, password = :password WHERE id = :id";
                $params = [
                    ':email' => $email,
                    ':role' => $role,
                    ':password' => hashPassword($newPassword),
                    ':id' => $id
                ];
            }
        } else {
        // Mot de passe inchangé   
            $sql = "UPDATE users SET email = :email, role = :role WHERE id = :id";
            $params = [
                ':email' => $email,
                ':role' => $role,
                ':id' => $id
            ];
        }

        if (empty($errors)) {
            $stmtUpdate = $pdo->prepare($sql);
            $stmtUpdate->execute($params);

            header('Location: index.php');
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Modifier l'utilisateur</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
    <h1>Modifier l'utilisateur</h1>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger">
            <ul class="mb-0">
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="post">
        <div class="mb-3">
            <label class="form-label">Email</label>
            <input type="email" name="email" class="form-control"
                   value="<?= htmlspecialchars($email) ?>" required>
        </div>

        <div class="mb-3">
            <label class="form-label">Nouveau mot de passe (optionnel)</label>
            <input type="password" name="password" class="form-control">
            <div class="form-text">Laissez vide pour garder l'ancien mot de passe.</div>
        </div>

        <div class="mb-3">
            <label class="form-label">Rôle</label>
            <select name="role" class="form-select">
                <option value="guest"  <?= $role === 'guest'  ? 'selected' : '' ?>>Guest</option>
                <option value="author" <?= $role === 'author' ? 'selected' : '' ?>>Author</option>
                <option value="editor" <?= $role === 'editor' ? 'selected' : '' ?>>Editor</option>
                <option value="admin"  <?= $role === 'admin'  ? 'selected' : '' ?>>Admin</option>
            </select>
        </div>

        <button type="submit" class="btn btn-primary">Enregistrer</button>
        <a href="index.php" class="btn btn-secondary">Annuler</a>
    </form>
</div>
</body>
</html>
