-- MySQL dump 10.13  Distrib 5.7.39, for Win64 (x86_64)
--
-- Host: localhost    Database: user_auth
-- ------------------------------------------------------
-- Server version	5.5.5-10.4.32-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `detection_history`
--

DROP TABLE IF EXISTS `detection_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `detection_history` (
  `id` int(50) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(50) unsigned NOT NULL,
  `symptoms` text NOT NULL,
  `detection_result` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `detection_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `login` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `detection_history`
--

LOCK TABLES `detection_history` WRITE;
/*!40000 ALTER TABLE `detection_history` DISABLE KEYS */;
INSERT INTO `detection_history` VALUES (1,27,'{\"meriang\":true,\"menggigil\":true}','ALERGI','2025-06-12 08:28:41'),(2,27,'{\"meriang\":true,\"menggigil\":true,\"nyeri_sendi\":true,\"mata_menguning\":true}','ALERGI','2025-06-12 08:29:03'),(3,27,'{\"nyeri_sendi\":true,\"mata_menguning\":true}','HEPATITIS D.','2025-06-12 08:29:15');
/*!40000 ALTER TABLE `detection_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(50) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','admin@gmail.com','$2b$10$01IgVEzas2kSYZvBTGc9helsvWJxSP8d7QhCpvDfnYj0uTfW1S6Tu'),(2,'admin1','admin1@gmail.com','$2b$10$DQPFkjrnnbF.RYmSv1UZUuuKyKErvqlWB/PAd1J58ma/7FStdfCQe'),(3,'admin2','admin2@gmail.com','$2b$10$XrOI8F2UKrs.aO4hJvmEsezwRMtEf2nEMoXE6qOn/mDA1MqyLZnO6'),(4,'admin3','admin3@gmail.com','$2b$10$zqVAvj8BiUHp6omeSukpn.uZumI9MqB7GRMpa0/Jziu.E1E4q3I5.'),(5,'oke','oke@gmail.com','$2b$10$A9oQ0MtCUlRh3y/.FgURNuz8jHovrpXHrjeSr67zoh/75gh1hRPSm'),(6,'sip','sip@gmail.com','$2b$10$AY/UAfZrdiVMyTIWQr6lwerFHQXqxRC.uSJUBOC1Q.NlF7eQtb6z6'),(7,'adminn','adminn@gmail.com','$2b$10$MhZfXAk/i//eJDnNZdgA0Or7i2bAG/gDITsWJExjKSkyKj7HrKsr2'),(8,'lexa','lexa@gmail.com','$2b$10$8byd6sCFmw9swdKFjom4p.ZysHXvXGhxyW/7V0guU/n/G4PJEfUNK'),(9,'halo','halo@gmail.com','$2b$10$9XFdsTVPeWgQL6aGgbvAAur4RPuuHA4Ny9MkTTJq.dejHrKDIRhS2'),(10,'Ronaldo','ronaldo@gmail.com','$2b$10$kg9q3a/1Arr.wE/1qiDiFumrkfHA4CT8noB9fS6kMDRJ0jf6MxsCS'),(11,'mantap','mantap@gmail.com','$2b$10$fAJIqNESFY5TyJnTTXWqPu1HTlXFQkYifrauTmcF5pZmVs.SpbLn6'),(12,'yoi','yoi@gmail.com','$2b$10$KjySSpuscXIf4532C/Et.uGdW0iudh3ACtvlPfvtECI2SN42NbHP6'),(22,'qwerty','qwerty@gmail.com','$2b$10$az/FbW4yJe8vc3XDcMyugOld7gS/tHWtsw48QQI2jJdlecbbznTfS'),(24,'Ronaldo','ronaldo1@gmail.com','$2b$10$FKul7Y3pqUkiZ1q69I72cu1Iq2c7N1YIRQqtwjr5LUjWeYZykWv.m'),(26,'Ronaldo','ronaldo2@gmail.com','$2b$10$WO7aFhhl.36R.sf9NdG83uHLGlHDITBQIadxgtmUchV7ASFv1yYyG'),(27,'NAUFAL ARSYAPUTRA PRADANA','111202214606@mhs.dinus.ac.id','$2b$10$YMj5g3g56GmlnF66c9lSzeN0UqobG04dEcxQnN1f4qnBY5MMkpqba');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-06-12 15:31:49
