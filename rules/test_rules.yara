rule Andr_Adware_Kuguo_1
{
    meta:
        source = "clamav"
        original_name = "Andr_Adware_Kuguo_1"

    strings:
        $a0 = { 64 65 78 0a 30 33 35 00 }
        $a1 = { 4c 63 6f 6d 2f 6b 75 67 75 6f 2f 61 64 2f 50 75 73 68 41 64 73 4d 61 6e 61 67 65 72 3b 00 }

    condition:
        $a0 or $a1
}

rule Andr_Adware_Kuguo_2
{
    meta:
        source = "clamav"
        original_name = "Andr_Adware_Kuguo_2"

    strings:
        $a0 = { 64 65 78 0a 30 33 35 00 }
        $a1 = { 4c 63 6f 6d 2f 6b 75 67 75 6f 2f 61 64 2f 4b 75 67 75 6f 41 64 73 4d 61 6e 61 67 65 72 3b 00 }

    condition:
        $a0 or $a1
}
