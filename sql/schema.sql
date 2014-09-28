CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL,
  `last_logined_ip` varchar(255) NOT NULL,
  `last_logined_at` datetime NOT NULL
) DEFAULT CHARSET=utf8;
