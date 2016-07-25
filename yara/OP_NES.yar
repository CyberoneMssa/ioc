rule OP_NES_ver2 :OP_NES
{
    meta:
        author = "MSSA_Sungmin.lim"
        date = "2016-07-15"
        filename = "rdpclip.exe"
        hash = "259c82d6db2883dd135c87b0feb44069"
        description = "Reverse Backdoor & RAT"
    
    strings:
	
	$c2_opcode = {B9 07 00 00 00 BF ?? ?? 4D ?? 8D B5 ?? ?? ?? ?? 33 D2 F3 A6 75 ??}
    $iat_decryt_opcode = {8D ?? 24 ?? 00 00 00 ?? 53 FF D6 85 C0 A3 ?? ?? ?? 00 75 10}
    $str_v2_1 =  "ehrecVr.eXE" wide ascii
    $str_v2_2 =  "wudfhost.Exe" wide ascii
    $str_v2_3 =  "SpPsvc.exe" wide ascii
    $str_v2_4 =  "werFaUlt.exE" wide ascii
    $str_v2_5 =  "smsS.exe" wide ascii
    $str_v2_6 =  "wIniniT.Exe" wide ascii
    $str_v2_7 =  "spOoLsv.eXe" wide ascii
    $str_v2_8 =  "cONhosT.exE"wide ascii 
    $str_v2_9 =  "WinlogOn.exE" wide ascii
    $str_v2_10 = "sVchost.EXe" wide ascii 
    $str_v2_11 = "rundll32.eXE" wide ascii
    $str_v2_12 = "Csrss.exe"wide ascii    
    $str_v2_13 = "lsass.Exe" wide ascii
    $str_v2_14 = "wmPnetwk.exe" wide ascii
    $str_v2_15 = "msdtc.Exe" wide ascii   
    $str_v2_16 = "ServIcEs.exE" wide ascii
    $str_v2_17 = "ehsCHed.eXE"wide ascii  
    $str_v2_18 = "uSErinit.exe" wide ascii
    $str_v2_19 = "lsm.EXe" wide ascii     
    $str_v2_20 = "dWm.exE" wide ascii
    $str_v2_21 = "dllhOst.exe" wide ascii
    $str_v2_22 = "searchindEXeR.eXe" wide ascii
		
    condition:
        $c2_opcode and $iat_decryt_opcode and 15 of ($str_v2_*)
}



rule OP_NES_ver1 : OP_NES
{
    meta:
        author = "MSSA_Sungmin"
        date = "2015-12-02"
        hash0 = "ec5282cf2be05038cf1ceae3a5a28194"
	    hash1 = "75ad2a8313371e45181e3ef419deda3e"
        description = "RAT"
        filename = "naverinfo.exe"
    
    strings:
        $iat_decryt_opcode = {8D ?? 24 ?? ?? 57 FF D6 85 C0 A3 ?? 66 41 00 75 0A}
        $str_v1_0 = "searchiNDexer.ExE" wide ascii
	    $str_v1_1 = "WIninIT.exe" wide ascii
	    $str_v1_2 = "LSAss.ExE" wide ascii 
	    $str_v1_3 = "ehScHed.eXE" wide ascii
	    $str_v1_4 = "ehrEcVr.eXE" wide ascii
	    $str_v1_5 = "sVcHoSt.exe" wide ascii
	    $str_v1_6 = "runDLl32.eXE" wide ascii
	    $str_v1_7 = "spPsvc.exe" wide ascii
	    $str_v1_8 = "SErVices.exe" wide ascii
	    $str_v1_9 = "Lsm.eXe" wide ascii
	    $str_v1_10 = "wiNlogon.Exe" wide ascii
	    $str_v1_11 = "cOnHoSt.EXe" wide ascii
	    $str_v1_12 = "spOOlsV.eXe" wide ascii
	    $str_v1_13 = "csRss.eXe" wide ascii
    
    condition:
        $iat_decryt_opcode and 13 of ($str_v1_*)

}

rule OP_NES_suspicious_str : OP_NES
{
    
    strings:

        $str_v1_0 = "searchiNDexer.ExE" wide ascii
	    $str_v1_1 = "WIninIT.exe" wide ascii
	    $str_v1_2 = "LSAss.ExE" wide ascii 
	    $str_v1_3 = "ehScHed.eXE" wide ascii
	    $str_v1_4 = "ehrEcVr.eXE" wide ascii
	    $str_v1_5 = "sVcHoSt.exe" wide ascii
	    $str_v1_6 = "runDLl32.eXE" wide ascii
	    $str_v1_7 = "spPsvc.exe" wide ascii
	    $str_v1_8 = "SErVices.exe" wide ascii
	    $str_v1_9 = "Lsm.eXe" wide ascii
	    $str_v1_10 = "wiNlogon.Exe" wide ascii
	    $str_v1_11 = "cOnHoSt.EXe" wide ascii
	    $str_v1_12 = "spOOlsV.eXe" wide ascii
	    $str_v1_13 = "csRss.eXe" wide ascii
        $str_v2_1 =  "ehrecVr.eXE" wide ascii
        $str_v2_2 =  "wudfhost.Exe" wide ascii
        $str_v2_3 =  "SpPsvc.exe" wide ascii
        $str_v2_4 =  "werFaUlt.exE" wide ascii
        $str_v2_5 =  "smsS.exe" wide ascii
        $str_v2_6 =  "wIniniT.Exe" wide ascii
        $str_v2_7 =  "spOoLsv.eXe" wide ascii
        $str_v2_8 =  "cONhosT.exE"wide ascii 
        $str_v2_9 =  "WinlogOn.exE" wide ascii
        $str_v2_10 = "sVchost.EXe" wide ascii 
        $str_v2_11 = "rundll32.eXE" wide ascii
        $str_v2_12 = "Csrss.exe"wide ascii    
        $str_v2_13 = "lsass.Exe" wide ascii
        $str_v2_14 = "wmPnetwk.exe" wide ascii
        $str_v2_15 = "msdtc.Exe" wide ascii   
        $str_v2_16 = "ServIcEs.exE" wide ascii
        $str_v2_17 = "ehsCHed.eXE"wide ascii  
        $str_v2_18 = "uSErinit.exe" wide ascii
        $str_v2_19 = "lsm.EXe" wide ascii     
        $str_v2_20 = "dWm.exE" wide ascii
        $str_v2_21 = "dllhOst.exe" wide ascii
        $str_v2_22 = "searchindEXeR.eXe" wide ascii
    
    condition:
        any of them

}

