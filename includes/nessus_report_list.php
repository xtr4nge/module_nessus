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
?>
<?
foreach ($nessus->reportList() as $value){
    foreach ($value as $key => $sub){
	$reportList[] = $sub["timestamp"] . ";" . $sub["readableName"] . ";" . $sub["status"] . ";" . $key;
    }
}
arsort($reportList);

function nessusVulCount($nessus, $report) {
    $ar = $nessus->report2Vulnerabilities($report);

    foreach($ar as $value) {
	$severity[] = $value["severity"];
    }

    if (is_array($severity)) {
	$occurences = array_count_values($severity);

	if ($occurences["4"] != "") $severitycount .= " <img src='includes/img/s_crit.png' title='".$occurences["4"]."' alt='".$occurences["4"]."'> ";

	if ($occurences["3"] != "") $severitycount .=  " <img src='includes/img/s_high.png' title='".$occurences["3"]."' alt='".$occurences["3"]."'> ";

	if ($occurences["2"] != "") $severitycount .= " <img src='includes/img/s_med.png' title='".$occurences["2"]."' alt='".$occurences["2"]."'> ";

	if ($occurences["1"] != "") $severitycount .= " <img src='includes/img/s_low.png' title='".$occurences["1"]."' alt='".$occurences["1"]."'> ";

	if ($occurences["0"] != "") $severitycount .= " <img src='includes/img/s_info.png' title='".$occurences["0"]."' alt='".$occurences["0"]."'> ";
	
	return $severitycount;
    } 
    else
    {
	//echo "[empty] " . $report;
    }
}

function nessusReportList ($nessus) {
	
    foreach ($nessus->reportList() as $value){
	foreach ($value as $key => $sub){
	    if (strpos(strtolower($sub["readableName"]), "fw-") !== false) {
		$reportList[] = $sub["timestamp"] . ";" . str_replace("fw-","",$sub["readableName"]) . ";" . $sub["status"] . ";" . $key;
	    }
	}
    }
    
    //if (!empty($reportList)) {
    arsort($reportList);

    $output[] = "<div style='color: white; width: 696px; background-color:#333; padding:4px; margin-bottom:2px; border-bottom: 1px solid; border-color:#BAC1C4; -moz-border-radius: 4px; border-radius: 4px;'>Reports</div>";
    foreach($reportList as $value) {
	$temp = explode(";", $value);
	
	$setline = "<div style='width: 700px; background-color:#E5E5E5; padding-left:4px; margin-bottom:2px; border-bottom: 1px solid; border-color:#BAC1C4; -moz-border-radius: 4px; border-radius: 4px;'>";
	$setline .= "<div style='display:inline-block; padding-top:5px; padding-bottom:5px; width:58%;'><a href='#' onclick=\"getIssues('".$temp[3]."')\" style='color: black;'>".$temp[1]."</a></div>\n";
	$setline .= "<div style='display:inline-block; width:12%;'>".date('Y-m-d', $temp[0])."</div>\n";
	$setline .= "<div style='display:inline-block; width:12%;'>".$temp[2]."</div>\n";
	$setline .= "<div style='display:inline-block; width:14%;'>".nessusVulCount($nessus, $temp[3])."</div>\n";
	$setline .= "</div>";
	$output[] = $setline;
    }
    //}
    return($output);
}

$output = nessusReportList($nessus);

echo json_encode($output);
?>