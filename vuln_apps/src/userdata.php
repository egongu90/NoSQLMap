<!DOCTYPE html>
<html>
	<head>
		<title>User Profile Lookup</title>
	</head>
	<body>
		<?php
		if (isset($_GET['usersearch']) && !empty($_GET['usersearch'])) {
			try {
				$conn = new MongoDB\Driver\Manager('mongodb://root:prisma@mongo:27017');
				$search = $_GET['usersearch'];
				$js = "function () { var query = '". $search . "'; return this.username == query;}";
				$query = new MongoDB\Driver\Query(['$where' => $js]);
				$cursor = $conn->executeQuery('appUserData.users', $query);
				$count = 0;
				foreach ($cursor as $obj) {
					$count++;
					echo 'Name: ' . $obj->name . '<br/>';
					echo 'Username: ' . $obj->username . '<br/>';
					echo 'Email: ' . $obj->email . '<br/>';
					echo '<br/>';
				}
				echo $count . ' user(s) found. <br/>';
			} catch (\Exception $e) {
				die('Error: ' . $e->getMessage());
			}
		}
		?>


		<b>Enter your username:</b><br>
		<form method="get" id="usersearch">
			<p>Search <input type="text" name="usersearch" id="usersearch" /> <input type="submit" name="submitbutton"
					value="Submit" /></p>
		</form>
		<div id="results">
		</div>
	</body>
</html>
