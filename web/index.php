<html>
<head>
<title>Vulnerable index</title>
</head>
<body>
<a href="?content=year.php">Current year</a>
</br>
<a href="?content=month.php">Current month</a>
</br>
</br>
<?php
$file = $_GET['content'];
include($file);
?>
</body>
</html>
