<?php
declare(strict_types=1);

/**
 * Internal blacklist eligibility check. Historical keyed hashes may still be
 * read from pre-existing phone records so removing the public collection API
 * does NOT silently lift bans previously enforced on those exact records.
 * This module never accepts raw IMEI/SIM numbers or generates identity keys.
 */
function mobile_blacklist_match(PDO $connection,string $phoneId,?string $imeiHash,?string $phoneHash=null): ?array {
    $sql="SELECT id,identifier_type,reason FROM phonehub_mobile_blacklist
          WHERE enabled=1 AND ((identifier_type='phone_id' AND identifier_hash=?)";
    $params=[$phoneId];
    if ($imeiHash!==null) {
        $sql.=" OR (identifier_type='imei_hash' AND identifier_hash=?)";
        $params[]=$imeiHash;
    }
    if ($phoneHash!==null) {
        $sql.=" OR (identifier_type='phone_hash' AND identifier_hash=?)";
        $params[]=$phoneHash;
    }
    $sql.=") ORDER BY id DESC LIMIT 1";
    $stmt=$connection->prepare($sql);
    $stmt->execute($params);
    $row=$stmt->fetch(PDO::FETCH_ASSOC);
    return $row?:null;
}
