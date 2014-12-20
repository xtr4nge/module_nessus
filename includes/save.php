<?

//include "../login_check.php";
include "../../../config/config.php";
include "../_info_.php";
include "../../../functions.php";

include "options_config.php";

// Checking POST & GET variables...
if ($regex == 1) {
    regex_standard($_POST['type'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['tempname'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['action'], "../../../msg.php", $regex_extra);
    regex_standard($_GET['mod_action'], "../../../msg.php", $regex_extra);
    regex_standard($_GET['mod_service'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['new_rename'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['new_rename_file'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['nessus_server'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['nessus_user'], "../../../msg.php", $regex_extra);
    regex_standard($_POST['nessus_pass'], "../../../msg.php", $regex_extra);
}

$type = $_POST['type'];
$tempname = $_POST['tempname'];
$action = $_POST['action'];
$mod_action = $_GET['mod_action'];
$mod_service = $_GET['mod_service'];
$newdata = html_entity_decode(trim($_POST["newdata"]));
$newdata = base64_encode($newdata);
$new_rename = $_POST["new_rename"];
$new_rename_file = $_POST["new_rename_file"];

$nessus_server = $_POST["nessus_server"];
$nessus_user = $_POST["nessus_user"];
$nessus_pass = $_POST["nessus_pass"];

// ngrep options
if ($type == "opt_nessus") {
    $exec = "/bin/sed -i 's/opt_nessus_server.*/opt_nessus_server = \\\"$nessus_server\\\";/g' options_config.php";
    //exec("/usr/share/FruityWifi/bin/danger \"" . $exec . "\"", $output); //DEPRECATED
    $output = exec_fruitywifi($exec);
	
    $exec = "/bin/sed -i 's/opt_nessus_user.*/opt_nessus_user = \\\"$nessus_user\\\";/g' options_config.php";
    //exec("/usr/share/FruityWifi/bin/danger \"" . $exec . "\"", $output); //DEPRECATED
    $output = exec_fruitywifi($exec);
	
    $exec = "/bin/sed -i 's/opt_nessus_pass.*/opt_nessus_pass = \\\"$nessus_pass\\\";/g' options_config.php";
    //exec("/usr/share/FruityWifi/bin/danger \"" . $exec . "\"", $output); //DEPRECATED
    $output = exec_fruitywifi($exec);
	
    header('Location: ../index.php?tab=2');
    exit;
}

header('Location: ../index.php');

?>