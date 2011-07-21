<?php

if(isset($_POST['sparedata'])) {
        for($x = 0; $x < strlen($_POST['sparedata']); $x++)
        {
                if( is_numeric($_POST['sparedata'][$x]) )
                        continue;

                echo "bad value in $x offset";
                exit;
        }
        echo $_POST['sparedata'];
}

?>

