<?php

/*
 * reporturi.php
 * a collector for CSP violation reports from the report-uri directive
 * jsaylor 20260226
 *

    csp-violation-php: collectors for csp violations written in php
    Copyright (C) 2026 js0000

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
    
 *
 */
 
// get out if not supported
if (! extension_loaded('pdo')) {
    exit('PDO extension required.');
} else if (! extension_loaded('sqlite3')) {
    exit('sqlite3 extension required.');
}

// Configuration (CHANGE ME):
$sqlitedbfile = '/tmp/report-uri.db';


// prepare db and tables
$dsn = 'sqlite:' . $sqlitedbfile;
try {
    $pdo = new PDO($dsn);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode(" ", array(
        'FAIL! could not connect to db',
        $excmsg,
        'DSN: ' . $dsn
    ));
    error_log($msg);
    exit($msg);
}

try {
    $pdo->exec("PRAGMA foreign_keys = ON");
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not set foreign_keys pragma',
        $excmsg
    ));
    error_log($msg);
    exit($msg);
}

$sourcestable = implode(' ', array(
    "CREATE TABLE IF NOT EXISTS sources (",
    "id INTEGER PRIMARY KEY AUTOINCREMENT,",
    "date_created DATETIME DEFAULT CURRENT_TIMESTAMP,",
    "unprocessed_src TEXT NOT NULL",
    ")"
));
try {
    $pdo->exec($sourcestable);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode(" ", array(
        'FAIL! could not create sources table',
        $excmsg,
        'SQL: ' . $sourcestable
    ));
    error_log($msg);
    exit($msg);
}

$reportstable = implode(' ', array(
    "CREATE TABLE IF NOT EXISTS reports (",
    "id INTEGER PRIMARY KEY AUTOINCREMENT,",
    "src_id INT NOT NULL,",
    "document_uri TEXT,",
    "referrer TEXT,",
    "violated_directive TEXT,",
    "original_policy TEXT,",
    "blocked_uri TEXT,",
    "source_file TEXT,",
    "line_number TEXT,",
    "column_number TEXT,",
    "status_code TEXT,",
    "FOREIGN KEY(src_id) REFERENCES sources(id)",
    ")"
));
try {
    $pdo->exec($reportstable);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode(" ", array(
        'FAIL! could not create reports table',
        $excmsg,
        'SQL: ' . $reportstable
    ));
    error_log($msg);
    exit($msg);
}

$insertsources = implode(' ', array(
    "INSERT INTO sources (",
    "unprocessed_src",
    ") VALUES (",
    ":unprocessedsrc",
    ")"
));
try {
    $srcstmt = $pdo->prepare($insertsources);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode(" ", array(
        'FAIL! could not prepare statement',
        $excmsg,
        'SQL: ' . $insertsources
    ));
    error_log($msg);
    exit($msg);
}

$insertreports = implode(' ', array(
    "INSERT INTO reports (",
    "src_id, document_uri, referrer, violated_directive, original_policy,",
    "blocked_uri, source_file, line_number, column_number, status_code",
    ") VALUES (",
    ":srcid, :documenturi, :referrer, :violateddirective, :originalpolicy,",
    ":blockeduri, :sourcefile, :linenumber, :columnnumber, :statuscode",
    ")"
));
try {
    $rptstmt = $pdo->prepare($insertreports);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode(" ", array(
        'FAIL! could not prepare',
        $excmsg,
        'SQL: ' . $insertreports
    ));
    error_log($msg);
    exit($msg);
}


// populate variables
$rptnames = array(
    'src_id',
    'document-uri',
    'referrer',
    'violated-directive',
    'original-policy',
    'blocked-uri',
    'source-file',
    'line-number',
    'column-number',
    'status-code' 
);
$rptfields = array();
foreach($rptnames as $n) {
    $k = ':' . preg_replace('/[\-_]/', '', $n);
    $rptfields[] = array(
        'name' => $n,
        'key' => $k
    );
 }


// process input
$src = array();
$rpt = array();
$rawsource = file_get_contents('php://input');
if(! $rawsource or strlen($rawsource) < 1) {
    $src[':unprocessedsrc'] = '<blank>';
    $src['fail'] = true;
}
else {
    $jsonrpt = json_decode($rawsource, true);
    if(! $jsonrpt) {
        $jsonerr = json_last_error_msg();
        $msg = implode("\n", array(
            'FAIL! could not (json) decode input',
            $jsonerr,
            $rawsource
        ));
        error_log($msg);
        $src[':unprocessedsrc'] = $rawsource;
        $src['fail'] = true;;
    } else {
        $src[':unprocessedsrc'] = '<processed>';
        foreach($rptfields as $f) {
            if(isset($jsonrpt['csp-report'][$f['name']])) {
                $rpt[$f['key']] = $jsonrpt['csp-report'][$f['name']];
            } else {
                $rpt[$f['key']] = '';
            }
        }
    }
}


// update db
try {
    $srcstmt->bindParam(':unprocessedsrc', $src[':unprocessedsrc']);
    $srcstmt->execute();
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $bindvars = print_r($src, true);
    $msg = implode(" ", array(
        'FAIL! could not insert',
        $excmsg,
        'SQL: '. $insertreports,
        $bindvars
    ));
    error_log($msg);
    exit($msg);
}

if(isset($src['fail'])) {
    $msg = date('c');
    exit($msg);
}

$srcid = $pdo->lastInsertId();
$rpt[':srcid'] = $srcid;
foreach($rptfields as $f) {
    $rptstmt->bindParam($f['key'], $rpt[$f['key']]);
}

try {
    $rptstmt->execute();
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $bindvars = var_export($rpt, true);
    $msg = implode(" ", array(
        'FAIL! could not insert row',
        $excmsg,
        'SQL: ' . $insertreports,
        $bindvars,
        $excmsg
    ));
    error_log($msg);
    exit($msg);
}
$msg = date('c');
exit($msg);
?>
