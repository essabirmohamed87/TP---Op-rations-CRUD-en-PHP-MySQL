<?php
require_once '../config.php';

$pdo = getConnection();

$id = isset($_GET['id']) ? (int) $_GET['id'] : 0;
if ($id <= 0) {
    header('Location: index.php');
    exit;
}

$stmt = $pdo->prepare("SELECT id, email, role, created_at, updated_at FROM users WHERE id = :id");
$stmt->execute([':id' => $id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    die("Utilisateur introuvable.");
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Détails utilisateur</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
    <h1>Détails de l'utilisateur #<?= htmlspecialchars($user['id']) ?></h1>

    <ul class="list-group mb-3">
        <li class="list-group-item"><strong>Email :</strong> <?= htmlspecialchars($user['email']) ?></li>
        <li class="list-group-item"><strong>Rôle :</strong> <?= htmlspecialchars($user['role']) ?></li>
        <li class="list-group-item"><strong>Créé le :</strong> <?= htmlspecialchars($user['created_at']) ?></li>
        <li class="list-group-item"><strong>Mis à jour le :</strong> <?= htmlspecialchars($user['updated_at']) ?></li>
    </ul>

    <a href="index.php" class="btn btn-secondary">Retour</a>
</div>
</body>
</html>
