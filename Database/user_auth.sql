-- phpMyAdmin SQL Dump
-- versi 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Waktu Pembuatan: 25 Mei 2025 pukul 16:56
-- Versi Server: 10.4.28-MariaDB
-- Versi PHP: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `user_auth`
--

-- --------------------------------------------------------

--
-- Struktur tabel untuk tabel `login`
--

DROP TABLE IF EXISTS `login`;
CREATE TABLE `login` (
  `id` int(50) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data untuk tabel `login`
--

INSERT INTO `login` (`id`, `name`, `email`, `password`) VALUES
(1, 'admin', 'admin@gmail.com', '$2b$10$01IgVEzas2kSYZvBTGc9helsvWJxSP8d7QhCpvDfnYj0uTfW1S6Tu'),
(2, 'admin1', 'admin1@gmail.com', '$2b$10$DQPFkjrnnbF.RYmSv1UZUuuKyKErvqlWB/PAd1J58ma/7FStdfCQe'),
(3, 'admin2', 'admin2@gmail.com', '$2b$10$XrOI8F2UKrs.aO4hJvmEsezwRMtEf2nEMoXE6qOn/mDA1MqyLZnO6'),
(4, 'admin3', 'admin3@gmail.com', '$2b$10$zqVAvj8BiUHp6omeSukpn.uZumI9MqB7GRMpa0/Jziu.E1E4q3I5.'),
(5, 'oke', 'oke@gmail.com', '$2b$10$A9oQ0MtCUlRh3y/.FgURNuz8jHovrpXHrjeSr67zoh/75gh1hRPSm'),
(6, 'sip', 'sip@gmail.com', '$2b$10$AY/UAfZrdiVMyTIWQr6lwerFHQXqxRC.uSJUBOC1Q.NlF7eQtb6z6'),
(7, 'adminn', 'adminn@gmail.com', '$2b$10$MhZfXAk/i//eJDnNZdgA0Or7i2bAG/gDITsWJExjKSkyKj7HrKsr2'),
(8, 'lexa', 'lexa@gmail.com', '$2b$10$8byd6sCFmw9swdKFjom4p.ZysHXvXGhxyW/7V0guU/n/G4PJEfUNK'),
(9, 'halo', 'halo@gmail.com', '$2b$10$9XFdsTVPeWgQL6aGgbvAAur4RPuuHA4Ny9MkTTJq.dejHrKDIRhS2'),
(10, 'Ronaldo', 'ronaldo@gmail.com', '$2b$10$kg9q3a/1Arr.wE/1qiDiFumrkfHA4CT8noB9fS6kMDRJ0jf6MxsCS'),
(11, 'mantap', 'mantap@gmail.com', '$2b$10$fAJIqNESFY5TyJnTTXWqPu1HTlXFQkYifrauTmcF5pZmVs.SpbLn6'),
(12, 'yoi', 'yoi@gmail.com', '$2b$10$KjySSpuscXIf4532C/Et.uGdW0iudh3ACtvlPfvtECI2SN42NbHP6'),
(22, 'qwerty', 'qwerty@gmail.com', '$2b$10$az/FbW4yJe8vc3XDcMyugOld7gS/tHWtsw48QQI2jJdlecbbznTfS'),
(24, 'Ronaldo', 'ronaldo1@gmail.com', '$2b$10$FKul7Y3pqUkiZ1q69I72cu1Iq2c7N1YIRQqtwjr5LUjWeYZykWv.m'),
(26, 'Ronaldo', 'ronaldo2@gmail.com', '$2b$10$WO7aFhhl.36R.sf9NdG83uHLGlHDITBQIadxgtmUchV7ASFv1yYyG');

--
-- Struktur tabel untuk tabel `detection_history`
--

DROP TABLE IF EXISTS `detection_history`;
CREATE TABLE `detection_history` (
  `id` int(50) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(50) UNSIGNED NOT NULL,
  `symptoms` TEXT NOT NULL,
  `detection_result` varchar(255) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `detection_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `login` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- AUTO_INCREMENT untuk tabel `login`
--
ALTER TABLE `login` MODIFY `id` int(50) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=27;

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
