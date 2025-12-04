<?php
require_once '../config.php';

$pdo = getConnection();
$errors = [];
$email = '';
$role = 'guest';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = cleanInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'guest';

    // Validations
    if (empty($email) || !validateEmail($email)) {
        $errors[] = "Email invalide.";
    }
    if (empty($password) || strlen($password) < 6) {
        $errors[] = "Le mot de passe doit contenir au moins 6 caractères.";
    }
    $rolesAutorises = ['guest', 'author', 'editor', 'admin'];
    if (!in_array($role, $rolesAutorises, true)) {
        $errors[] = "Rôle invalide.";
    }

    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare(
                "INSERT INTO users (email, password, role) VALUES (:email, :password, :role)"
            );
            $stmt->execute([
                ':email' => $email,
                ':password' => hashPassword($password),
                ':role' => $role
            ]);

            header('Location: index.php');
            exit;
        } catch (PDOException $e) {
          // Email déjà utilisé, par exemple 
            $errors[] = "Erreur lors de l'insertion : " . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Créer un utilisateur</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
    <h1>Créer un utilisateur</h1>

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
            <label class="form-label">Mot de passe</label>
            <input type="password" name="password" class="form-control" required>
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