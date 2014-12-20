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
<!DOCTYPE HTML>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>FruityWifi</title>
<script src="../js/jquery.js"></script>
<script src="../js/jquery-ui.js"></script>
<link rel="stylesheet" href="../css/jquery-ui.css" />
<link rel="stylesheet" href="../css/style.css" />
<link rel="stylesheet" href="../../../style.css" />

<script>
$(function() {
    $( "#action" ).tabs();
    $( "#result" ).tabs();
});

</script>

</head>
<body>

<? include "../menu.php"; ?>

<br>

<?

include "../../config/config.php";
include "_info_.php";
include "../../login_check.php";
include "../../functions.php";

// Checking POST & GET variables...
if ($regex == 1) {
    regex_standard($_POST["newdata"], "msg.php", $regex_extra);
    regex_standard($_GET["logfile"], "msg.php", $regex_extra);
    regex_standard($_GET["action"], "msg.php", $regex_extra);
    regex_standard($_POST["service"], "msg.php", $regex_extra);
}

$newdata = $_POST['newdata'];
$logfile = $_GET["logfile"];
$action = $_GET["action"];
$tempname = $_GET["tempname"];
$service = $_POST["service"];

// DELETE LOG
if ($logfile != "" and $action == "delete") {
    $exec = "$bin_rm ".$mod_logs_history.$logfile.".log";
    //exec("$bin_danger \"$exec\"", $dump); //DEPRECATED
    exec_fruitywifi($exec);
}

include "includes/options_config.php";

?>

<div class="rounded-top" align="left"> &nbsp; <b><?=$mod_alias?></b> </div>
<div class="rounded-bottom">

    &nbsp;&nbsp;version <?=$mod_version?><br>
    <? 
    if (file_exists("/opt/nessus/sbin/nessusd")) { 
        echo "&nbsp;&nbsp;&nbsp;Nessus <font style='color:lime'>installed</font><br>";
    } else {
        echo "&nbsp;&nbsp;&nbsp;Nessus <a href='includes/module_action.php?install=install_responder' style='color:red'>install</a><br>";
    } 
    ?>
    
    <?
    $ismoduleup = exec($mod_isup);
    if ($ismoduleup != "") {
        echo "&nbsp;&nbsp;&nbsp;Nessus <font color=\"lime\"><b>enabled</b></font>.&nbsp; | <a href=\"includes/module_action.php?service=responder&action=stop&page=module\"><b>stop</b></a>";
    } else { 
        echo "&nbsp;&nbsp;&nbsp;Nessus <font color=\"red\"><b>disabled</b></font>. | <a href=\"includes/module_action.php?service=responder&action=start&page=module\"><b>start</b></a>"; 
    }
    ?>

</div>

<?
    $ismoduleup = exec($mod_isup);
    if ($ismoduleup == "") {
            echo "<br> <div style='color: red'>&nbsp;&nbsp;Nessus is disabled.</div>";
            exit;
	}
?>

<br>


<div id="msg" style="font-size:largest;">
Loading, please wait...
</div>

<?
try {
    include "includes/options_config.php";
    include "includes/nessus.php";
    $nessus = new NessusInterface("https://$opt_nessus_server", "8834", "$opt_nessus_user", "$opt_nessus_pass");
    $nesus_error = False;
} catch (Exception $e) {
    //echo $e;
    $nesus_error = True;
}
?>

<div id="body" style="display:none;">


    <div id="result" class="module">
        <ul>
            <li><a href="#result-1">Reports</a></li>
            <li><a href="#result-2">Scan</a></li>
            <li><a href="#result-3">Config</a></li>
            <li><a href="#result-4">About</a></li>
        </ul>
        
        <!-- Reports -->

        <div id="result-1" class="general">
            <? if ($nesus_error == False) { ?>
                <input type="button" class="input" onclick="getReports();" value="reports"> <div style='display:inline-block;' id="nessus-loading">...</div>
                <br><br>
                <div id="nessus-output" class="general"></div>             
            <?
            } else {
                echo "<br>Nessus error.<br><br>";
            }
            ?>

        </div>

	<!-- Scan -->

        <div id="result-2" class="general">
            <? if ($nesus_error == False) { ?>
            
                <form id="formScan" name="formScan" method="POST" autocomplete="off" action="includes/module_action.php">
                <input type="submit" value="scan" class="input">
                <br><br>
                    <div id="scan" class="module-content" style="font-family: courier;">
                            
                        <table>
                            <tr>
                                <td align="right">policy_id</td>
                                <td>
                                    <select name="nessus_policy_id" class="input">
                                        <?
                                            foreach ($nessus->policyList() as $value){
                                                foreach ($value as $key => $sub){
                                                    //echo $key . ": " . $sub . "<br>";
                                                    echo "<option value='$key'>$sub</option>";
                                                }
                                            }
                                        ?>
                                    </select>
                                </td>
                            </tr>
                            <tr>
                                <td align="right">target</td>
                                <td><input name="nessus_target" class="input"></td>
                            </tr>
                            <tr>
                                <td align="right">scan_name</td>
                                <td><input name="nessus_scan_name" class="input"></td>
                            </tr>
                            <tr>
                                <td></td>
                                <td>
                                    <input type="hidden" name="nessus" value="new_scan">
                                </td>
                            </tr>
                        </table>
                            
                    </div>
                        
                <input type="hidden" name="type" value="scan">
                </form>
                
            <?
            } else {
                echo "<br>Nessus error.<br><br>";
            }
            ?>
        </div>

        <!-- CONFIG -->

        <div id="result-3" >
            <form id="formInject" name="formInject" method="POST" autocomplete="off" action="includes/save.php">
            <input type="submit" value="save">
            <br><br>
            
            <div class="module-content" style="font-family: courier;" >
            <table>
				<!-- // OPTION SERVER --> 
                <tr>
                    <? $opt = "nessus_server"; ?>
                    <td style="padding-right:10px" align="right">Server</td>
                    <td><input type="input" name="nessus_server" value="<?=$opt_nessus_server?>"></td>
                    <td nowrap></td>
                </tr>
				<!-- // OPTION USER --> 
                <tr>
                    <? $opt = "nessus_user"; ?>
                    <td style="padding-right:10px" align="right">Username</td>
                    <td><input type="input" name="nessus_user" value="<?=$opt_nessus_user?>"></td>
                    <td nowrap></td>
                </tr>
				<!-- // OPTION PASS --> 
                <tr>
                    <? $opt = "nessus_pass"; ?>
                    <td style="padding-right:10px" align="right">Password</td>
                    <td><input type="password" name="nessus_pass" value="<?=$opt_nessus_pass?>"></td>
                    <td nowrap></td>
                </tr>
            </table>
            </div>

            <input type="hidden" name="type" value="opt_nessus">
            </form>
            
            <br>
            <?
                $filename = "$mod_path/includes/mode_d.txt";
                
                $data = open_file($filename);
                
            ?>
            
        </div>

        <!-- ABOUT -->

        <div id="result-4" class="history">
            <? include "includes/about.php";?>
        </div>
        
    </div>

    <div id="loading" class="ui-widget" style="width:100%;background-color:#000; padding-top:4px; padding-bottom:4px;color:#FFF">
        Loading...
    </div>

    <?
    if ($_GET["tab"] == 1) {
        echo "<script>";
        echo "$( '#result' ).tabs({ active: 1 });";
        echo "</script>";
    } else if ($_GET["tab"] == 2) {
        echo "<script>";
        echo "$( '#result' ).tabs({ active: 2 });";
        echo "</script>";
    } else if ($_GET["tab"] == 3) {
        echo "<script>";
        echo "$( '#result' ).tabs({ active: 3 });";
        echo "</script>";
    } else if ($_GET["tab"] == 4) {
        echo "<script>";
        echo "$( '#result' ).tabs({ active: 4 });";
        echo "</script>";
    } 
    ?>

</div>

<script type="text/javascript">
$('#loading').hide();
$(document).ready(function() {
    $('#body').show();
    $('#msg').hide();
});
</script>

<script>

function getIssues(report_uuid) {
    //$('#nessus-output').html(report_uuid);
    //var refInterval = setInterval(function() {
        $("#nessus-loading").css("visibility","visible");
        $.ajax({
            type: 'POST',
            url: 'includes/nessus_issues_list.php',
            data: 'report_uuid='+report_uuid,
            dataType: 'json',
            success: function (data) {
                console.log(data);
                $('#nessus-output').html('');
                
                $("#nessus-loading").html( "<img src='includes/img/loading.gif'>" );
                $.each(data, function (index, value) {
                    $("#nessus-output").append( value ); //.append("<br>");
                });
                $("#nessus-loading").css("visibility","hidden");
            }
        });
    //},8000);
}

function getReports() {
    //var refInterval = setInterval(function() {
        $("#nessus-loading").css("visibility","visible");
        $("#nessus-loading").html( "<img src='includes/img/loading.gif'>" ); 
        $.ajax({
            type: 'POST',
            url: 'includes/nessus_report_list.php',
            data: 'service=&path=',
            dataType: 'json',
            success: function (data) {
                console.log(data);
                $('#nessus-output').html('');
                               
                $.each(data, function (index, value) {
                    $("#nessus-output").append( value ); //.append("<br>");
                });
                $("#nessus-loading").css("visibility","hidden");
            }
        });
    //},8000);
}
</script>

<? if ($nesus_error == False) { ?>
<script> getReports(); </script>
<? } ?>
</body>
</html>
