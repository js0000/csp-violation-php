<?php

/*
 * reportto.php
 * a collector for CSP violation reports from report-to directive
 * puts them in a sqlite db
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
$sqlitedbfile = '/tmp/report-to.db';


// initialize PDO connection
$dsn = 'sqlite:' . $sqlitedbfile;
try {
    $pdo = new PDO($dsn);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not connect to db',
        $dsn,
        $excmsg
    ));
    exit($msg);
}


// set foreign key pragma
try {
    $pdo->exec("PRAGMA foreign_keys = ON");
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not set foreign_keys pragma',
        $excmsg
    ));
    exit($msg);
}


// create sources table (if needed)
$sourcestable = implode(' ', array(
    "CREATE TABLE IF NOT EXISTS sources (",
    "id INTEGER PRIMARY KEY AUTOINCREMENT,",
    "datecreated DATETIME DEFAULT CURRENT_TIMESTAMP,",
    "age INTEGER,",
    "type TEXT,",
    "url TEXT,",
    "useragent TEXT,",
    "unprocessedsrc TEXT NOT NULL",
    ")"
));
try {
    $pdo->exec($sourcestable);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not create sources table',
        $sourcestable,
        $excmsg
    ));
    exit($msg);
}


// create reports table
$reportstable = implode(' ', array(
    "CREATE TABLE IF NOT EXISTS reports (",
    "id INTEGER PRIMARY KEY AUTOINCREMENT,",
    "srcid INT NOT NULL,",
    "documentURL TEXT,",
    "referrer TEXT,",
    "effectiveDirective TEXT,",
    "originalPolicy TEXT,",
    "blockedURL TEXT,",
    "sourceFile TEXT,",
    "lineNumber TEXT,",
    "columnNumber TEXT,",
    "statusCode TEXT,",
    "disposition TEXT,",
    "sample TEXT,",
    "FOREIGN KEY(srcid) REFERENCES sources(id)",
    ")"
));
try {
    $pdo->exec($reportstable);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not create reports table',
        $reportstable,
        $excmsg
    ));
    exit($msg);
}

$insertsources = implode(' ', array(
    "INSERT INTO sources (",
    "age, type, url, useragent, unprocessedsrc",
    ") VALUES (",
    ":age, :type, :url, :useragent, :unprocessedsrc",
    ")"
));
try {
    $srcstmt = $pdo->prepare($insertsources);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not prepare',
        $insertsources,
        $excmsg
    ));
    exit($msg);
}

$insertreports = implode(' ', array(
    "INSERT INTO reports (",
    "srcid, documentURL, referrer, effectiveDirective, originalPolicy, blockedURL,",
    "sourceFile, lineNumber, columnNumber, statusCode, disposition, sample",
    ") VALUES (",
    ":srcid, :documentURL, :referrer, :effectiveDirective, :originalPolicy, :blockedURL,",
    ":sourceFile, :lineNumber, :columnNumber, :statusCode, :disposition, :sample",
    ")"
));
try {
    $rptstmt = $pdo->prepare($insertreports);
} catch (PDOException $pdo_exc) {
    $excmsg = $pdo_exc->getMessage();
    $msg = implode("\n", array(
        'FAIL! could not prepare',
        $insertreports,
        $excmsg
    ));
    exit($msg);
}


// prepare variables for processing
$srcnames = array(
    "age",
    "type",
    "url",
    "user_agent"
);
$rptnames = array(
    "documentURL",
    "referrer",
    "effectiveDirective",
    "originalPolicy",
    "blockedURL",
    "sourceFile",
    "lineNumber",
    "columnNumber",
    "statusCode",
    "disposition",
    "sample"
);
$srcfields = array();
$rptfields = array();
foreach($srcnames as $n) {
    $k = ':' . str_replace('_', '', $n);
    $srcfields[] = array(
        'name' => $n,
        'key' => $k
    );
 }
foreach($rptnames as $n) {
    $k = ':' . $n;
    $rptfields[] = array(
        'name' => $n,
        'key' => $k
    );
 }
 $src = array();
 $rpt = array();
 $sources = array();
 $reports = array();


// process input
$rawsource = file_get_contents('php://input');
if(! $rawsource or strlen($rawsource) < 1) {
    $src[':unprocessedsrc'] = '<blank>';
    $src['fail'] = true;
} else {
    $jsonreports = json_decode($rawsource, true);
    if(! $jsonreports) {
        $jsonerr = json_last_error_msg();
        $msg = implode("\n", array(
            'FAIL! could not (json) decode input',
            $jsonerr,
            $rawsource
        ));
        error_log($msg);
        $src[':unprocessedsrc'] = $rawsource;
        $src['fail'] = true;
    } else {
        for($i = 0; $i < count($jsonreports); $i++) {
            $src = array();
            $rpt = array();
            $src[':unprocessedsrc'] = '<processed>';
            for($j = 0; $j < count($srcfields); $j++) {
                if(isset($jsonreports[$i][$srcfields[$j]['name']])) {
                    $src[$srcfields[$j]['key']] = $jsonreports[$i][$srcfields[$j]['name']];
                } else {
                    $src[$srcfields[$j]['key']] = '';
                }
            }
            for($k = 0; $k < count($rptfields); $k++) {
                if(isset($jsonreports[$i]['body'][$rptfields[$k]['name']])) {
                    $rpt[$rptfields[$k]['key']] =
                    $jsonreports[$i]['body'][$rptfields[$k]['name']];
                } else {
                    $rpt[$rptfields[$k]['key']] = '';
                }
            }
            $sources[] = $src;
            $reports[] = $rpt;
        }
    }
}

if(isset($src['fail'])) {
    for($i = 0; $i < count($srcfields); $i++) {
        $src[$srcfields[$i]['key']] = '';
    }
    unset($src['fail']);
    $sources[] = $src;
}

// update db
for($i = 0; $i < count($sources); $i++) {
    foreach($sources[$i] as $k => $v) {
        $srcstmt->bindValue($k, $v);
    }
    try {
        $srcstmt->execute();
    } catch (PDOException $pdo_exc) {
        $excmsg = $pdo_exc->getMessage();
        $bindvars = var_export($sources[$i], true);
        $msg = implode(" ", array(
            'FAIL! could not insert',
            $excmsg,
            'SQL: ' . $insertsources,
            $bindvars
        ));
        error_log($msg);
        continue;
    }

    if(isset($reports[$i]) and count($reports[$i]) > 0) {
        $srcid = $pdo->lastInsertId();
        $rptstmt->bindValue(':srcid', $srcid);
        foreach($reports[$i] as $k => $v) {
            $rptstmt->bindValue($k, $v);
        }
        try {
            $rptstmt->execute();
        } catch (PDOException $pdo_exc) {
            $excmsg = $pdo_exc->getMessage();
            $bindvars = var_export($reports[$i], true);
            $msg = implode(" ", array(
                'FAIL! could not insert row',
                $excmsg,
                'SQL: ' . $insertreports,
                $bindvars,
            ));
            error_log($msg);
            continue;
       }
    }
}

$msg = date('c');
exit($msg);
?>
