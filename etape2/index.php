<?php
require_once '../config.php';

$pdo = getConnection();

// Action courante (par défaut : liste)
$action = $_GET['action'] ?? 'list';
$errors = [];
$success = '';

// Pour les formulaires
$email = '';
$role = 'guest';
$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
$rolesAutorises = ['guest', 'author', 'editor', 'admin'];

// ----- TRAITEMENT DES ACTIONS -----

// Création d'un utilisateur
if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = cleanInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] ?? 'guest';

    if (empty($email) || !validateEmail($email)) {
        $errors[] = "Email invalide.";
    }
    if (empty($password) || strlen($password) < 6) {
        $errors[] = "Le mot de passe doit contenir au moins 6 caractères.";
    }
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
            $success = "Utilisateur créé avec succès.";
            // On revient à la liste
            $action = 'list';
        } catch (PDOException $e) {
            $errors[] = "Erreur lors de l'insertion : " . $e->getMessage();
        }
    }
}

// Modification d'un utilisateur
if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST' && $id > 0) {
    $email = cleanInput($_POST['email'] ?? '');
    $role = $_POST['role'] ?? 'guest';
    $newPassword = $_POST['password'] ?? '';

    if (empty($email) || !validateEmail($email)) {
        $errors[] = "Email invalide.";
    }
    if (!in_array($role, $rolesAutorises, true)) {
        $errors[] = "Rôle invalide.";
    }

    if (empty($errors)) {
        if (!empty($newPassword)) {
            if (strlen($newPassword) < 6) {
                $errors[] = "Le mot de passe doit contenir au moins 6 caractères.";
            } else {
                $sql = "UPDATE users 
                        SET email = :email, role = :role, password = :password 
                        WHERE id = :id";
                $params = [
                    ':email' => $email,
                    ':role' => $role,
                    ':password' => hashPassword($newPassword),
                    ':id' => $id
                ];
            }
        } else {
            $sql = "UPDATE users 
                    SET email = :email, role = :role 
                    WHERE id = :id";
            $params = [
                ':email' => $email,
                ':role' => $role,
                ':id' => $id
            ];
        }

        if (empty($errors)) {
            $stmtUpdate = $pdo->prepare($sql);
            $stmtUpdate->execute($params);
            $success = "Utilisateur mis à jour.";
            $action = 'list';
        }
    }
}

// Suppression d'un utilisateur
if ($action === 'delete' && $id > 0) {
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
    $stmt->execute([':id' => $id]);
    $success = "Utilisateur supprimé.";
    $action = 'list';
}

// ----- RÉCUPÉRATION DES DONNÉES POUR L’AFFICHAGE -----

// Pour la liste
if ($action === 'list') {
    $stmt = $pdo->query("SELECT id, email, role, created_at, updated_at 
                         FROM users ORDER BY created_at DESC");
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Pour view / edit : charger l'utilisateur
if (in_array($action, ['view', 'edit'], true) && $id > 0) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute([':id' => $id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        $errors[] = "Utilisateur introuvable.";
        $action = 'list';
        $stmt = $pdo->query("SELECT id, email, role, created_at, updated_at 
                             FROM users ORDER BY created_at DESC");
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] !== 'POST') {
            // Pré-remplir le formulaire uniquement lors du premier affichage
            $email = $user['email'];
            $role = $user['role'];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TP CRUD PHP/MySQL - Étape 2</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
    <h1 class="mb-3">TP CRUD PHP/MySQL – Étape 2 (un seul fichier)</h1>

    <div class="mb-3">
        <a href="index.php?action=list" class="btn btn-outline-primary btn-sm">Liste</a>
        <a href="index.php?action=create" class="btn btn-outline-success btn-sm">Créer</a>
    </div>

    <?php if (!empty($success)): ?>
        <div class="alert alert-success">
            <?= htmlspecialchars($success) ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-danger">
            <ul class="mb-0">
                <?php foreach ($errors as $error): ?>
                    <li><?= htmlspecialchars($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <?php if ($action === 'list'): ?>

        <!-- LISTE DES UTILISATEURS -->
        <h2>Liste des utilisateurs</h2>
        <table class="table table-striped table-bordered mt-3">
            <thead>
            <tr>
                <th>#</th>
                <th>Email</th>
                <th>Rôle</th>
                <th>Créé le</th>
                <th>Mis à jour le</th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody>
            <?php if (!empty($users)): ?>
                <?php foreach ($users as $u): ?>
                    <tr>
                        <td><?= htmlspecialchars($u['id']) ?></td>
                        <td><?= htmlspecialchars($u['email']) ?></td>
                        <td><?= htmlspecialchars($u['role']) ?></td>
                        <td><?= htmlspecialchars($u['created_at']) ?></td>
                        <td><?= htmlspecialchars($u['updated_at']) ?></td>
                        <td>
                            <a href="index.php?action=view&id=<?= $u['id'] ?>" class="btn btn-sm btn-info">
                                <i class="bi bi-eye"></i>
                            </a>
                            <a href="index.php?action=edit&id=<?= $u['id'] ?>" class="btn btn-sm btn-warning">
                                <i class="bi bi-pencil"></i>
                            </a>
                            <a href="index.php?action=delete&id=<?= $u['id'] ?>"
                               class="btn btn-sm btn-danger"
                               onclick="return confirm('Supprimer cet utilisateur ?');">
                                <i class="bi bi-trash"></i>
                            </a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="6">Aucun utilisateur.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>

    <?php elseif ($action === 'create'): ?>

        <!-- FORMULAIRE DE CRÉATION -->
        <h2>Créer un utilisateur</h2>
        <form method="post" class="mt-3">
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

            <button type="submit" class="btn btn-success">Enregistrer</button>
            <a href="index.php?action=list" class="btn btn-secondary">Annuler</a>
        </form>

    <?php elseif ($action === 'view' && isset($user)): ?>

        <!-- DÉTAILS D'UN UTILISATEUR -->
        <h2>Détails de l'utilisateur #<?= htmlspecialchars($user['id']) ?></h2>
        <ul class="list-group mt-3">
            <li class="list-group-item"><strong>Email :</strong> <?= htmlspecialchars($user['email']) ?></li>
            <li class="list-group-item"><strong>Rôle :</strong> <?= htmlspecialchars($user['role']) ?></li>
            <li class="list-group-item"><strong>Créé le :</strong> <?= htmlspecialchars($user['created_at']) ?></li>
            <li class="list-group-item"><strong>Mis à jour le :</strong> <?= htmlspecialchars($user['updated_at']) ?></li>
        </ul>
        <a href="index.php?action=list" class="btn btn-secondary mt-3">Retour</a>

    <?php elseif ($action === 'edit' && isset($user)): ?>

        <!-- FORMULAIRE D'ÉDITION -->
        <h2>Modifier l'utilisateur #<?= htmlspecialchars($user['id']) ?></h2>
        <form method="post" class="mt-3">
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

            <button type="submit" class="btn btn-primary">Mettre à jour</button>
            <a href="index.php?action=list" class="btn btn-secondary">Annuler</a>
        </form>

    <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>