<?php

namespace App\Filters;

use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use CodeIgniter\Filters\FilterInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JwtFilter implements FilterInterface
{
    public function before(
        RequestInterface $request,
        $arguments = null
    ) {
        $header = $request->getHeaderLine('Authorization');

        if (!$header || !preg_match('/Bearer\s(\S+)/', $header, $matches)) {
            return service('response')
                ->setStatusCode(401)
                ->setJSON([
                    'status' => false,
                    'message' => 'Token tidak ditemukan'
                ]);
        }

        $token = $matches[1];

        try {
            $key = env('JWT_SECRET_KEY');

            $decoded = JWT::decode(
                $token,
                new Key($key, 'HS256')
            );

            // Simpan payload JWT ke request
            $request->user = (array) $decoded;
        } catch (\Throwable $e) {
            return service('response')
                ->setStatusCode(401)
                ->setJSON([
                    'status' => false,
                    'message' => 'Token tidak valid'
                ]);
        }
    }

    public function after(
        RequestInterface $request,
        ResponseInterface $response,
        $arguments = null
    ) {}
}
