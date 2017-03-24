<?php
namespace carono\exe;

class File
{
    /**
     * @source http://stackoverflow.com/questions/2029409/get-version-of-exe-via-php
     *
     * @param $filePath
     * @return array|bool
     */
    public static function getVersion($filePath)
    {
        $handle = fopen($filePath, 'rb');
        $SecHdr = '';
        $SubOff = '';
        if (!$handle) return FALSE;
        $header = fread($handle, 64);
        if (substr($header, 0, 2) != 'MZ') return FALSE;
        $PEOffset = unpack("V", substr($header, 60, 4));
        if ($PEOffset[1] < 64) return FALSE;
        fseek($handle, $PEOffset[1], SEEK_SET);
        $header = fread($handle, 24);
        if (substr($header, 0, 2) != 'PE') return FALSE;
        $Machine = unpack("v", substr($header, 4, 2));
        if ($Machine[1] != 332) return FALSE;
        $NoSections = unpack("v", substr($header, 6, 2));
        $OptHdrSize = unpack("v", substr($header, 20, 2));
        fseek($handle, $OptHdrSize[1], SEEK_CUR);
        $ResFound = FALSE;
        for ($x = 0; $x < $NoSections[1]; $x++) {      //$x fixed here
            $SecHdr = fread($handle, 40);
            if (substr($SecHdr, 0, 5) == '.rsrc') {         //resource section
                $ResFound = TRUE;
                break;
            }
        }
        if (!$ResFound) return FALSE;
        $InfoVirt = unpack("V", substr($SecHdr, 12, 4));
        $InfoSize = unpack("V", substr($SecHdr, 16, 4));
        $InfoOff = unpack("V", substr($SecHdr, 20, 4));
        fseek($handle, $InfoOff[1], SEEK_SET);
        $Info = fread($handle, $InfoSize[1]);
        $NumDirs = unpack("v", substr($Info, 14, 2));
        $InfoFound = FALSE;
        for ($x = 0; $x < $NumDirs[1]; $x++) {
            $Type = unpack("V", substr($Info, ($x * 8) + 16, 4));
            if ($Type[1] == 16) {             //FILEINFO resource
                $InfoFound = TRUE;
                $SubOff = unpack("V", substr($Info, ($x * 8) + 20, 4));
                break;
            }
        }
        if (!$InfoFound) return FALSE;
        $SubOff[1] &= 0x7fffffff;
        $InfoOff = unpack("V", substr($Info, $SubOff[1] + 20, 4)); //offset of first FILEINFO
        $InfoOff[1] &= 0x7fffffff;
        $InfoOff = unpack("V", substr($Info, $InfoOff[1] + 20, 4));    //offset to data
        $DataOff = unpack("V", substr($Info, $InfoOff[1], 4));
        $DataSize = unpack("V", substr($Info, $InfoOff[1] + 4, 4));
        $CodePage = unpack("V", substr($Info, $InfoOff[1] + 8, 4));
        $DataOff[1] -= $InfoVirt[1];
        $version = unpack("v4", substr($Info, $DataOff[1] + 48, 8));
        $x = $version[2];
        $version[2] = $version[1];
        $version[1] = $x;
        $x = $version[4];
        $version[4] = $version[3];
        $version[3] = $x;
        return $version;
    }
}