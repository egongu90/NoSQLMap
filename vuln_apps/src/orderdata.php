<!DOCTYPE html>
<html>
	<head>
		<title>Order Lookup</title>
	</head>
	<body>
		<?php
		if (isset($_GET['ordersearch']) && !empty($_GET['ordersearch'])) {
			try {
				$conn = new MongoDB\Driver\Manager('mongodb://root:prisma@mongo:27017');
				$search = $_GET['ordersearch'];
				$js = "function () { var query = '". $search . "'; return this.id == query;}";
				$query = new MongoDB\Driver\Query(['$where' => $js]);
				$cursor = $conn->executeQuery('shop.orders', $query);
				$count = 0;
				foreach ($cursor as $obj) {
					$count++;
					echo 'Order ID: ' . $obj->id . '<br/>';
					echo 'Name: ' . $obj->name . '<br/>';
					echo 'Item: ' . $obj->item . '<br/>';
					echo 'Quantity: ' . $obj->quantity . '<br/>';
					echo '<br/>';
				}
				echo $count . ' order(s) found. <br/>';
			} catch (\Exception $e) {
				die('Error: ' . $e->getMessage());
			}
		}
		?>


		<b>Use the Order ID to locate your order:</b><br>
		<form method="get" id="usersearch">
			<p>Search <input type="text" name="ordersearch" id="ordersearch" /> <input type="submit" name="submitbutton"
					value="Submit" /></p>
		</form>
		<div id="results">
		</div>
	</body>
</html>
