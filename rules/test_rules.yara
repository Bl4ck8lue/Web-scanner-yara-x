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

rule Win_Downloader_Small_1395
{
    meta:
        source = "clamav"
        original_name = "Win_Downloader_Small_1395"

    strings:
        $a0 = { 7c 31 40 00 28 31 40 00 c0 33 40 00 90 33 40 00 00 34 40 00 d0 33 40 00 38 34 40 00 08 34 40 00 70 34 40 00 40 34 40 00 b8 34 40 00 88 34 40 00 00 00 00 00 60 35 40 00 55 8b ec 83 c4 f0 b8 88 35 40 00 e8 34 fd ff ff 68 10 36 40 00 6a 00 e8 94 fe ff ff ba 50 36 40 00 b8 78 36 40 00 e8 c5 fe ff ff 84 c0 74 0c 6a 00 68 ac 36 40 00 e8 bd fd ff ff e8 ec f7 ff ff 68 00 74 00 74 00 70 00 3a 00 2f 00 }

    condition:
        $a0
}
