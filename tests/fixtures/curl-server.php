<?php

declare(strict_types=1);

// Router for the CurlClient tests: php -S 127.0.0.1:PORT tests/fixtures/curl-server.php

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

switch ($path) {
    case '/text':
        header('Content-Type: text/markdown');
        header('X-Twice: one');
        header('X-Twice: two', false);
        echo "# Advisory\n\nAffected: <1.2.3\n";
        break;
    case '/echo':
        header('Content-Type: application/json');
        echo json_encode([
            'method' => $_SERVER['REQUEST_METHOD'],
            'body' => file_get_contents('php://input'),
            'agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'accept' => $_SERVER['HTTP_ACCEPT'] ?? null,
            'type' => $_SERVER['CONTENT_TYPE'] ?? null,
        ]);
        break;
    case '/redirect':
        header('Location: /text', true, 302);
        break;
    case '/loop':
        header('Location: /loop', true, 302);
        break;
    case '/missing':
        http_response_code(404);
        echo 'nope';
        break;
    case '/boom':
        http_response_code(503);
        echo 'try later';
        break;
    case '/slow':
        sleep(3);
        echo 'late';
        break;
    default:
        http_response_code(404);
}
