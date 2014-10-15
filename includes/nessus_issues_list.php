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
include "options_config.php";
include "nessus.php";
$nessus = new NessusInterface("https://$opt_nessus_server", "8834", "$opt_nessus_user", "$opt_nessus_pass");

//$report = $_REQUEST["report_uuid"];
$report = $_POST["report_uuid"];

$ar = $nessus->report2Vulnerabilities($report);

//$a[] = "";

foreach ($ar as $value){
	
    $hosts = $nessus->report2HostsPLugin($report, $value["severity"], $value["plugin_id"]);
    
    foreach ($hosts as $host){
        $a[] = $host["hostname"] .";". $value["severity"] .";". $value["plugin_name"] . ";" . $value["plugin_id"];
    }
}

if (empty($a)) { 
    echo "\n<br>This report is empty." ;
    exit;
}

arsort($a);

foreach ($a as $value){
	
    $temp = explode(";", $value);
    
    //if ($flag != $temp[0]) $output[] = "<b>" . $temp[0] . "</b><br>";
    if ($flag != $temp[0]) $output[] = "<div style='color: white; width: 700px; background-color:#333; padding:4px; margin-bottom:2px; border-bottom: 1px solid; border-color:#BAC1C4; -moz-border-radius: 4px; border-radius: 4px;'>".$temp[0]."</div>";
    if ($temp[1] >= 0 and $flag_name != $temp[2]) {
        switch ($temp[1]) {
            case 4:
                $color = "#EE1f1f"; // Blue (Crit)
                $icon = "s_crit.png";
                break;
            case 3:
                $color = "#ff9900"; // Green (High)
                $icon = "s_high.png";
                break;
            case 2:
                $color = "#ffd800"; // Yellow (Medium)
                $icon = "s_med.png";
                break;
            case 1:
                $color = "#2aba2d"; // Red (Low)
                $icon = "s_low.png";
                break;
            case 0:
                $color = "#2a64ba"; // Red (Info)
                $icon = "s_info.png";
                break;
        }
        $output[] = "<div style='width: 700px; background-color:#E5E5E5; padding:4px; margin-bottom:2px; border-bottom: 1px solid; border-color:#BAC1C4; -moz-border-radius: 4px; border-radius: 4px;'><img src='includes/img/$icon'> <font color='black'>" . $temp[2] . "</font> (<a href='http://www.tenable.com/plugins/index.php?view=single&id=".$temp[3]."' target='_blank' style='color:black'>".$temp[3]."</a>)" . "</div>";
    }
    $flag_name = $temp[2];
    $flag = $temp[0];
}

echo json_encode($output);

?>