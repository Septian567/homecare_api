<?php

namespace App\Controllers\Api;

use App\Controllers\BaseController;
use App\Models\UserModel;
use Firebase\JWT\JWT;

class Auth extends BaseController
{
    public function login()
    {
        $data = $this->request->getJSON(true);

        if (empty($data['email']) || empty($data['password'])) {
            return $this->response
                ->setStatusCode(400)
                ->setJSON([
                    'status' => false,
                    'message' => 'Email dan password wajib diisi'
                ]);
        }

        $userModel = new UserModel();

        $user = $userModel
            ->where('email', $data['email'])
            ->first();

        if (!$user || !password_verify($data['password'], $user['password'])) {
            return $this->response
                ->setStatusCode(401)
                ->setJSON([
                    'status' => false,
                    'message' => 'Email atau password salah'
                ]);
        }

        $key = env('JWT_SECRET_KEY');

        $payload = [
            'iss' => 'ci-api',
            'aud' => 'ci-client',
            'iat' => time(),
            'exp' => time() + 3600,
            'uid' => $user['id'],
            'email' => $user['email'],
        ];

        $token = JWT::encode($payload, $key, 'HS256');

        return $this->response->setJSON([
            'status' => true,
            'message' => 'Login berhasil',
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'data' => [
                'id' => $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
            ]
        ]);
    }

    public function changePassword()
    {
        $data = $this->request->getJSON(true);

        if (
            empty($data['current_password']) ||
            empty($data['new_password'])
        ) {
            return $this->response
                ->setStatusCode(400)
                ->setJSON([
                    'status' => false,
                    'message' => 'Password lama dan password baru wajib diisi'
                ]);
        }

        // User ID didapat dari JWT
        $userId = $this->request->user['uid'] ?? null;

        if (!$userId) {
            return $this->response
                ->setStatusCode(401)
                ->setJSON([
                    'status' => false,
                    'message' => 'Token tidak valid'
                ]);
        }

        $userModel = new UserModel();

        $user = $userModel->find($userId);

        if (!$user) {
            return $this->response
                ->setStatusCode(404)
                ->setJSON([
                    'status' => false,
                    'message' => 'User tidak ditemukan'
                ]);
        }

        // Verifikasi password lama
        if (!password_verify(
            $data['current_password'],
            $user['password']
        )) {
            return $this->response
                ->setStatusCode(401)
                ->setJSON([
                    'status' => false,
                    'message' => 'Password lama salah'
                ]);
        }

        // Minimal 8 karakter
        if (strlen($data['new_password']) < 8) {
            return $this->response
                ->setStatusCode(400)
                ->setJSON([
                    'status' => false,
                    'message' => 'Password baru minimal 8 karakter'
                ]);
        }

        // Jangan gunakan password lama sebagai password baru
        if (password_verify(
            $data['new_password'],
            $user['password']
        )) {
            return $this->response
                ->setStatusCode(400)
                ->setJSON([
                    'status' => false,
                    'message' => 'Password baru harus berbeda dari password lama'
                ]);
        }

        $userModel->update($userId, [
            'password' => password_hash(
                $data['new_password'],
                PASSWORD_DEFAULT
            )
        ]);

        return $this->response->setJSON([
            'status' => true,
            'message' => 'Password berhasil diubah'
        ]);
    }
}
