<?php
// FALSE NEGATIVE: credentials that are not directly assigned from a string
$password = base64_decode('bmV2ZXItZ29ubmEtZ2l2ZS15b3UtdXA=');
$password2 = strtoupper('VeRy-SecuRe-PaSsWoRd')