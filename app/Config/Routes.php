<?php

use CodeIgniter\Router\RouteCollection;

/** @var RouteCollection $routes */
$routes->get('/', 'Home::index');
$routes->post('api/login', 'Api\Auth::login');
$routes->put(
    'api/change-password',
    'Api\Auth::changePassword',
    ['filter' => 'jwt']
);