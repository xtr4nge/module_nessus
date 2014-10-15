<? 
/*
    Copyright (C) 2013-2014 xtr4nge [_AT_] gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/ 
?>
<?
//include "../login_check.php";
include "../_info_.php";
include "/usr/share/FruityWifi/www/config/config.php";
include "/usr/share/FruityWifi/www/functions.php";

include "options_config.php";

// Checking POST & GET variables...
if ($regex == 1) {
    regex_standard($_GET["service"], "../msg.php", $regex_extra);
    regex_standard($_GET["action"], "../msg.php", $regex_extra);
    regex_standard($_GET["page"], "../msg.php", $regex_extra);
    regex_standard($io_action, "../msg.php", $regex_extra);
    regex_standard($_GET["install"], "../msg.php", $regex_extra);
    regex_standard($_POST["nessus"], "../msg.php", $regex_extra);
    regex_standard($_POST["nessus_target"], "../msg.php", $regex_extra);
    regex_standard($_POST["nessus_policy_id"], "../msg.php", $regex_extra);
    regex_standard($_POST["nessus_scan_name"], "../msg.php", $regex_extra);
}

$service = $_GET['service'];
$action = $_GET['action'];
$page = $_GET['page'];
$install = $_GET['install'];
$nessus = $_POST['nessus'];
$nessus_target = $_POST["nessus_target"];
$nessus_policy_id = $_POST["nessus_policy_id"];
$nessus_scan_name = $_POST["nessus_scan_name"];

if($service != "") {
    
    if ($action == "start") {
        
	$exec = "/etc/init.d/nessusd start > /dev/null 2 &";
        exec("$bin_danger \"$exec\"" );
        
    } else if($action == "stop") {
        // STOP MODULE

	$exec = "/etc/init.d/nessusd stop";
        exec("$bin_danger \"$exec\"" );

    }

}

if ($nessus == "new_scan") {

    include "nessus.php";

    $nessus = new NessusInterface("https://$opt_nessus_server", "8834", "$opt_nessus_user", "$opt_nessus_pass");
    $nessus->scanNew($nessus_target, $nessus_policy_id, "fw-".$nessus_scan_name);

    header('Location: ../index.php');
    exit;
}

if ($page == "status") {
    header('Location: ../../../action.php');
} else {
    header('Location: ../../action.php?page=nessus');
}

?>
