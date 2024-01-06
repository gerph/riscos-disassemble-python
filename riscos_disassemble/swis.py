# AUTOMATICALLY generated header

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ADFS
ADFS_DiscOp = 0x00040240
ADFS_HDC = 0x00040241
ADFS_Drives = 0x00040242
ADFS_FreeSpace = 0x00040243
ADFS_Retries = 0x00040244
ADFS_DescribeDisc = 0x00040245
ADFS_VetFormat = 0x00040246
ADFS_FlpProcessDCB = 0x00040247
ADFS_ControllerType = 0x00040248
ADFS_PowerControl = 0x00040249
ADFS_SetIDEController = 0x0004024A
ADFS_IDEUserOp = 0x0004024B
ADFS_MiscOp = 0x0004024C                               #  &4024C
ADFS_SectorDiscOp = 0x0004024D                         #  &4024D
ADFS_NOP2 = 0x0004024E                                 #  &4024E
ADFS_NOP3 = 0x0004024F                                 #  &4024F
ADFS_ECCSAndRetries = 0x00040250                       #  &40250
ADFS_LockIDE = 0x00040251                              #  &40251
ADFS_FreeSpace64 = 0x00040252                          #  &40252

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ATAPI
ATAPI_GetDrives = 0x0004A740                           #   +0

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Buffer
Buffer_Create = 0x00042940
Buffer_Remove = 0x00042941
Buffer_Register = 0x00042942
Buffer_Deregister = 0x00042943
Buffer_ModifyFlags = 0x00042944
Buffer_LinkDevice = 0x00042945
Buffer_UnlinkDevice = 0x00042946
Buffer_GetInfo = 0x00042947
Buffer_Threshold = 0x00042948
Buffer_InternalInfo = 0x00042949

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ARM3Cache
Cache_Control = 0x00000280
Cache_Cacheable = 0x00000281
Cache_Updateable = 0x00000282
Cache_Disruptive = 0x00000283
Cache_Flush = 0x00000284

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/CDROM
CD_Version = 0x00041240                                #   +0
CD_ReadData = 0x00041241                               #   +1
CD_SeekTo = 0x00041242                                 #   +2
CD_DriveStatus = 0x00041243                            #   +3
CD_DriveReady = 0x00041244                             #   +4
CD_GetParameters = 0x00041245                          #   +5     Private
CD_SetParameters = 0x00041246                          #   +6     Private
CD_OpenDrawer = 0x00041247                             #   +7
CD_EjectButton = 0x00041248                            #   +8
CD_EnquireAddress = 0x00041249                         #   +9
CD_EnquireDataMode = 0x0004124A                        #  +10     Private
CD_PlayAudio = 0x0004124B                              #  +11
CD_PlayTrack = 0x0004124C                              #  +12
CD_AudioPause = 0x0004124D                             #  +13
CD_EnquireTrack = 0x0004124E                           #  +14
CD_ReadSubChannel = 0x0004124F                         #  +15     Private
CD_CheckDrive = 0x00041250                             #  +16
CD_DiscChanged = 0x00041251                            #  +17     Private
CD_StopDisc = 0x00041252                               #  +18
CD_DiscUsed = 0x00041253                               #  +19
CD_AudioStatus = 0x00041254                            #  +20
CD_Inquiry = 0x00041255                                #  +21
CD_DiscHasChanged = 0x00041256                         #  +22     Private
CD_Control = 0x00041257                                #  +23
CD_Supported = 0x00041258                              #  +24     Private
CD_Prefetch = 0x00041259                               #  +25
CD_Reset = 0x0004125A                                  #  +26
CD_CloseDrawer = 0x0004125B                            #  +27     Private
CD_IsDrawerLocked = 0x0004125C                         #  +28     Private
CD_AudioControl = 0x0004125D                           #  +29     Private
CD_LastError = 0x0004125E                              #  +30
CD_AudioLevel = 0x0004125F                             #  +31     Private
CD_Register = 0x00041260                               #  +32
CD_Unregister = 0x00041261                             #  +33
CD_ByteCopy = 0x00041262                               #  +34     Private
CD_Identify = 0x00041263                               #  +35
CD_ConvertToLBA = 0x00041264                           #  +36
CD_ConvertToMSF = 0x00041265                           #  +37
CD_ReadAudio = 0x00041266                              #  +38
CD_ReadUserData = 0x00041267                           #  +39
CD_SeekUserData = 0x00041268                           #  +40
CD_GetAudioParms = 0x00041269                          #  +41
CD_SetAudioParms = 0x0004126A                          #  +42

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/CDFS
CDFS_ConvertDriveToDevice = 0x00041E80
CDFS_SetBufferSize = 0x00041E81
CDFS_GetBufferSize = 0x00041E82
CDFS_SetNumberOfDrives = 0x00041E83
CDFS_GetNumberOfDrives = 0x00041E84
CDFS_GiveFileType = 0x00041E85
CDFS_DescribeDisc = 0x00041E86

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ColourPick
ColourPicker_RegisterModel = 0x00047700
ColourPicker_DeregisterModel = 0x00047701
ColourPicker_OpenDialogue = 0x00047702
ColourPicker_CloseDialogue = 0x00047703
ColourPicker_UpdateDialogue = 0x00047704
ColourPicker_ReadDialogue = 0x00047705
ColourPicker_SetColour = 0x00047706
ColourPicker_HelpReply = 0x00047707
ColourPicker_ModelSWI = 0x00047708

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ColourTran
ColourTrans_SelectTable = 0x00040740                   #  &40740
ColourTrans_SelectGCOLTable = 0x00040741               #  &40741
ColourTrans_ReturnGCOL = 0x00040742                    #  &40742
ColourTrans_SetGCOL = 0x00040743                       #  &40743
ColourTrans_ReturnColourNumber = 0x00040744            #  &40744
ColourTrans_ReturnGCOLForMode = 0x00040745             #  &40745
ColourTrans_ReturnColourNumberForMode = 0x00040746     #  &40746
ColourTrans_ReturnOppGCOL = 0x00040747                 #  &40747
ColourTrans_SetOppGCOL = 0x00040748                    #  &40748
ColourTrans_ReturnOppColourNumber = 0x00040749         #  &40749
ColourTrans_ReturnOppGCOLForMode = 0x0004074A          #  &4074A
ColourTrans_ReturnOppColourNumberForMode = 0x0004074B  #  &4074B
ColourTrans_GCOLToColourNumber = 0x0004074C            #  &4074C
ColourTrans_ColourNumberToGCOL = 0x0004074D            #  &4074D
ColourTrans_ReturnFontColours = 0x0004074E             #  &4074E
ColourTrans_SetFontColours = 0x0004074F                #  &4074F
ColourTrans_InvalidateCache = 0x00040750               #  &40750
ColourTrans_SetCalibration = 0x00040751                #  &40751
ColourTrans_ReadCalibration = 0x00040752               #  &40752
ColourTrans_ConvertDeviceColour = 0x00040753           #  &40753
ColourTrans_ConvertDevicePalette = 0x00040754          #  &40754
ColourTrans_ConvertRGBToCIE = 0x00040755               #  &40755
ColourTrans_ConvertCIEToRGB = 0x00040756               #  &40756
ColourTrans_WriteCalibrationToFile = 0x00040757        #  &40757
ColourTrans_ConvertRGBToHSV = 0x00040758               #  &40758
ColourTrans_ConvertHSVToRGB = 0x00040759               #  &40759
ColourTrans_ConvertRGBToCMYK = 0x0004075A              #  &4075A
ColourTrans_ConvertCMYKToRGB = 0x0004075B              #  &4075B
ColourTrans_ReadPalette = 0x0004075C                   #  &4075C
ColourTrans_WritePalette = 0x0004075D                  #  &4075D
ColourTrans_SetColour = 0x0004075E                     #  &4075E
ColourTrans_MiscOp = 0x0004075F                        #  &4075F
ColourTrans_WriteLoadingsToFile = 0x00040760           #  &40760
ColourTrans_SetTextColour = 0x00040761                 #  &40761
ColourTrans_SetOppTextColour = 0x00040762              #  &40762
ColourTrans_GenerateTable = 0x00040763                 #  &40763

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Debugger
Debugger_Disassemble = 0x00040380
Debugger_DisassembleThumb = 0x00040381

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/DeviceFS
DeviceFS_Register = 0x00042740
DeviceFS_Deregister = 0x00042741
DeviceFS_RegisterObjects = 0x00042742
DeviceFS_DeregisterObjects = 0x00042743
DeviceFS_CallDevice = 0x00042744
DeviceFS_Threshold = 0x00042745
DeviceFS_ReceivedCharacter = 0x00042746
DeviceFS_TransmitCharacter = 0x00042747

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/DMA
DMA_RegisterChannel = 0x00046140
DMA_DeregisterChannel = 0x00046141
DMA_QueueTransfer = 0x00046142
DMA_TerminateTransfer = 0x00046143
DMA_SuspendTransfer = 0x00046144
DMA_ResumeTransfer = 0x00046145
DMA_ExamineTransfer = 0x00046146

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/DragASprit
DragASprite_Start = 0x00042400                         #  &42500
DragASprite_Stop = 0x00042401                          #  &42501

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/DragAnObj
DragAnObject_Start = 0x00049C40
DragAnObject_Stop = 0x00049C41

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Draw
Draw_ProcessPath = 0x00040700                          #  &40700
Draw_ProcessPathFP = 0x00040701                        #  &40701
Draw_Fill = 0x00040702                                 #  &40702
Draw_FillFP = 0x00040703                               #  &40703
Draw_Stroke = 0x00040704                               #  &40704
Draw_StrokeFP = 0x00040705                             #  &40705
Draw_StrokePath = 0x00040706                           #  &40706
Draw_StrokePathFP = 0x00040707                         #  &40707
Draw_FlattenPath = 0x00040708                          #  &40708
Draw_FlattenPathFP = 0x00040709                        #  &40709
Draw_TransformPath = 0x0004070A                        #  &4070A
Draw_TransformPathFP = 0x0004070B                      #  &4070B
Draw_FillClipped = 0x0004070C                          #  &4070C
Draw_FillClippedFP = 0x0004070D                        #  &4070D
Draw_StrokeClipped = 0x0004070E                        #  &4070E
Draw_StrokeClippedFP = 0x0004070F                      #  &4070F

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Econet
Econet_CreateReceive = 0x00040000                      #  40000
Econet_ExamineReceive = 0x00040001                     #  40001
Econet_ReadReceive = 0x00040002                        #  40002
Econet_AbandonReceive = 0x00040003                     #  40003
Econet_WaitForReception = 0x00040004                   #  40004
Econet_EnumerateReceive = 0x00040005                   #  40005
Econet_StartTransmit = 0x00040006                      #  40006
Econet_PollTransmit = 0x00040007                       #  40007
Econet_AbandonTransmit = 0x00040008                    #  40008
Econet_DoTransmit = 0x00040009                         #  40009
Econet_ReadLocalStationAndNet = 0x0004000A             #  4000A
Econet_ConvertStatusToString = 0x0004000B              #  4000B
Econet_ConvertStatusToError = 0x0004000C               #  4000C
Econet_ReadProtection = 0x0004000D                     #  4000D
Econet_SetProtection = 0x0004000E                      #  4000E
Econet_ReadStationNumber = 0x0004000F                  #  4000F
Econet_PrintBanner = 0x00040010                        #  40010
Econet_ReadTransportType = 0x00040011                  #  40011
Econet_ReleasePort = 0x00040012                        #  40012
Econet_AllocatePort = 0x00040013                       #  40013
Econet_DeAllocatePort = 0x00040014                     #  40014
Econet_ClaimPort = 0x00040015                          #  40015
Econet_StartImmediate = 0x00040016                     #  40016
Econet_DoImmediate = 0x00040017                        #  40017
Econet_AbandonAndReadReceive = 0x00040018              #  40018
Econet_Version = 0x00040019                            #  40019
Econet_NetworkState = 0x0004001A                       #  4001A
Econet_PacketSize = 0x0004001B                         #  4001B
Econet_ReadTransportName = 0x0004001C                  #  4001C
Econet_InetRxDirect = 0x0004001D                       #  4001D
Econet_EnumerateMap = 0x0004001E                       #  4001E
Econet_EnumerateTransmit = 0x0004001F                  #  4001F
Econet_HardwareAddresses = 0x00040020                  #  40020
Econet_NetworkParameters = 0x00040021                  #  40021
NetFS_ReadFSNumber = 0x00040040                        #  40040
NetFS_SetFSNumber = 0x00040041                         #  40041
NetFS_ReadFSName = 0x00040042                          #  40042
NetFS_SetFSName = 0x00040043                           #  40043
NetFS_ReadCurrentContext = 0x00040044                  #  40044
NetFS_SetCurrentContext = 0x00040045                   #  40045
NetFS_ReadFSTimeouts = 0x00040046                      #  40046
NetFS_SetFSTimeouts = 0x00040047                       #  40047
NetFS_DoFSOp = 0x00040048                              #  40048
NetFS_EnumerateFSList = 0x00040049                     #  40049
NetFS_EnumerateFS = 0x0004004A                         #  4004A
NetFS_ConvertDate = 0x0004004B                         #  4004B
NetFS_DoFSOpToGivenFS = 0x0004004C                     #  4004C
NetFS_UpdateFSList = 0x0004004D                        #  4004D
NetFS_EnumerateFSContexts = 0x0004004E                 #  4004E
NetFS_ReadUserId = 0x0004004F                          #  4004F
NetFS_GetObjectUID = 0x00040050                        #  40050
NetFS_EnableCache = 0x00040051                         #  40051
NetPrint_ReadPSNumber = 0x00040200                     #  40200
NetPrint_SetPSNumber = 0x00040201                      #  40201
NetPrint_ReadPSName = 0x00040202                       #  40202
NetPrint_SetPSName = 0x00040203                        #  40203
NetPrint_ReadPSTimeouts = 0x00040204                   #  40204
NetPrint_SetPSTimeouts = 0x00040205                    #  40205
NetPrint_BindPSName = 0x00040206                       #  40206
NetPrint_ListServers = 0x00040207                      #  40207
NetPrint_ConvertStatusToString = 0x00040208            #  40208
NetMonitor_PrintChar = 0x00080040                      #  80040
NetMonitor_DefineTask = 0x00080041                     #  80041
NetMonitor_AbandonTask = 0x00080042                    #  80042
NetMonitor_ConvertFont = 0x00080043                    #  80043
NetMonitor_UseFont = 0x00080044                        #  80044
NetMonitor_RestoreFont = 0x00080045                    #  80045
NetMonitor_StartWithCurrentFont = 0x00080046           #  80046
NetMonitor_StartWithInternalFont = 0x00080047          #  80047

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/FileCore
FileCore_DiscOp = 0x00040540
FileCore_Create = 0x00040541
FileCore_Drives = 0x00040542
FileCore_FreeSpace = 0x00040543
FileCore_FloppyStructure = 0x00040544
FileCore_DescribeDisc = 0x00040545
FileCore_DiscardReadSectorsCache = 0x00040546
FileCore_DiscFormat = 0x00040547
FileCore_LayoutStructure = 0x00040548
FileCore_MiscOp = 0x00040549
FileCore_SectorDiscOp = 0x0004054A
FileCore_FreeSpace64 = 0x0004054B
FileCore_DiscOp64 = 0x0004054C
FileCore_Features = 0x0004054D

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/FilerAct
FilerAction_SendSelectedDirectory = 0x00040F80
FilerAction_SendSelectedFile = 0x00040F81
FilerAction_SendStartOperation = 0x00040F82

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Filter
Filter_RegisterPreFilter = 0x00042640
Filter_RegisterPostFilter = 0x00042641
Filter_DeRegisterPreFilter = 0x00042642
Filter_DeRegisterPostFilter = 0x00042643
Filter_RegisterRectFilter = 0x00042644
Filter_DeRegisterRectFilter = 0x00042645
Filter_RegisterCopyFilter = 0x00042646
Filter_DeRegisterCopyFilter = 0x00042647
Filter_RegisterPostRectFilter = 0x00042648
Filter_DeRegisterPostRectFilter = 0x00042649
Filter_RegisterPostIconFilter = 0x0004264A
Filter_DeRegisterPostIconFilter = 0x0004264B
Filter_RegisterIconBorderFilter = 0x0004264C
Filter_DeRegisterIconBorderFilter = 0x0004264D

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Font
Font_CacheAddr = 0x00040080                            #  &40080
Font_FindFont = 0x00040081                             #  &40081
Font_LoseFont = 0x00040082                             #  &40082
Font_ReadDefn = 0x00040083                             #  &40083
Font_ReadInfo = 0x00040084                             #  &40084
Font_StringWidth = 0x00040085                          #  &40085
Font_Paint = 0x00040086                                #  &40086
Font_Caret = 0x00040087                                #  &40087
Font_ConverttoOS = 0x00040088                          #  &40088
Font_Converttopoints = 0x00040089                      #  &40089
Font_SetFont = 0x0004008A                              #  &4008A
Font_CurrentFont = 0x0004008B                          #  &4008B
Font_FutureFont = 0x0004008C                           #  &4008C
Font_FindCaret = 0x0004008D                            #  &4008D
Font_CharBBox = 0x0004008E                             #  &4008E
Font_ReadScaleFactor = 0x0004008F                      #  &4008F
Font_SetScaleFactor = 0x00040090                       #  &40090
Font_ListFonts = 0x00040091                            #  &40091
Font_SetFontColours = 0x00040092                       #  &40092
Font_SetPalette = 0x00040093                           #  &40093
Font_ReadThresholds = 0x00040094                       #  &40094
Font_SetThresholds = 0x00040095                        #  &40095
Font_FindCaretJ = 0x00040096                           #  &40096
Font_StringBBox = 0x00040097                           #  &40097
Font_ReadColourTable = 0x00040098                      #  &40098
Font_MakeBitmap = 0x00040099                           #  &40099
Font_UnCacheFile = 0x0004009A                          #  &4009A
Font_SetFontMax = 0x0004009B                           #  &4009B
Font_ReadFontMax = 0x0004009C                          #  &4009C
Font_ReadFontPrefix = 0x0004009D                       #  &4009D
Font_SwitchOutputToBuffer = 0x0004009E                 #  &4009E
Font_ReadFontMetrics = 0x0004009F                      #  &4009F
Font_DecodeMenu = 0x000400A0                           #  &400A0
Font_ScanString = 0x000400A1                           #  &400A1
Font_SetColourTable = 0x000400A2                       #  &400A2
Font_CurrentRGB = 0x000400A3                           #  &400A3
Font_FutureRGB = 0x000400A4                            #  &400A4
Font_ReadEncodingFilename = 0x000400A5                 #  &400A5
Font_FindField = 0x000400A6                            #  &400A6
Font_ApplyFields = 0x000400A7                          #  &400A7
Font_LookupFont = 0x000400A8                           #  &400A8
Font_ChangeArea = 0x000400BF                           #  +63  -  for OS_ChangeDynamicArea

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Free
Free_Register = 0x000444C0                             #  &444C0
Free_DeRegister = 0x000444C1                           #  &444C1

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/FSLock
FSLock_Version = 0x00044780
FSLock_Status = 0x00044781
FSLock_ChangeStatus = 0x00044782

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Hourglass
Hourglass_On = 0x000406C0
Hourglass_Off = 0x000406C1
Hourglass_Smash = 0x000406C2
Hourglass_Start = 0x000406C3
Hourglass_Percentage = 0x000406C4
Hourglass_LEDs = 0x000406C5
Hourglass_Colours = 0x000406C6

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/HostFS
HostFS_HostVdu = 0x00040100
HostFS_TubeVdu = 0x00040101
HostFS_WriteC = 0x00040102

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/IIC
IIC_Control = 0x00000240                               #  +0

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/MakePSFont
MakePSFont_MakeFont = 0x00043440                       #  &43440

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/MsgTrans
MessageTrans_FileInfo = 0x00041500                     #  &41500
MessageTrans_OpenFile = 0x00041501                     #  &41501
MessageTrans_Lookup = 0x00041502                       #  &41502
MessageTrans_MakeMenus = 0x00041503                    #  &41503
MessageTrans_CloseFile = 0x00041504                    #  &41504
MessageTrans_EnumerateTokens = 0x00041505              #  &41505
MessageTrans_ErrorLookup = 0x00041506                  #  &41506
MessageTrans_GSLookup = 0x00041507                     #  &41507
MessageTrans_CopyError = 0x00041508                    #  &41508
MessageTrans_Dictionary = 0x00041509                   #  &41509

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/RISCOS
OS_WriteC = 0x00000000                                 #  &00
OS_WriteS = 0x00000001                                 #  &01
OS_Write0 = 0x00000002                                 #  &02
OS_NewLine = 0x00000003                                #  &03
OS_ReadC = 0x00000004                                  #  &04
OS_CLI = 0x00000005                                    #  &05
OS_Byte = 0x00000006                                   #  &06
OS_Word = 0x00000007                                   #  &07
OS_File = 0x00000008                                   #  &08
OS_Args = 0x00000009                                   #  &09
OS_BGet = 0x0000000A                                   #  &0A
OS_BPut = 0x0000000B                                   #  &0B
OS_GBPB = 0x0000000C                                   #  &0C
OS_Find = 0x0000000D                                   #  &0D
OS_ReadLine = 0x0000000E                               #  &0E
OS_Control = 0x0000000F                                #  &0F
OS_GetEnv = 0x00000010                                 #  &10
OS_Exit = 0x00000011                                   #  &11
OS_SetEnv = 0x00000012                                 #  &12
OS_IntOn = 0x00000013                                  #  &13
OS_IntOff = 0x00000014                                 #  &14
OS_CallBack = 0x00000015                               #  &15
OS_EnterOS = 0x00000016                                #  &16
OS_BreakPt = 0x00000017                                #  &17
OS_BreakCtrl = 0x00000018                              #  &18
OS_UnusedSWI = 0x00000019                              #  &19
OS_UpdateMEMC = 0x0000001A                             #  &1A
OS_SetCallBack = 0x0000001B                            #  &1B
OS_Mouse = 0x0000001C                                  #  &1C
OS_Heap = 0x0000001D                                   #  &1D ; Our new ones start here
OS_Module = 0x0000001E                                 #  &1E
OS_Claim = 0x0000001F                                  #  &1F ; PMF's vector handling
OS_Release = 0x00000020                                #  &20 ; routines
OS_ReadUnsigned = 0x00000021                           #  &21 ; Read an unsigned number
OS_GenerateEvent = 0x00000022                          #  &22
OS_ReadVarVal = 0x00000023                             #  &23 ; read variable value & type
OS_SetVarVal = 0x00000024                              #  &24 ; set  variable value & type
OS_GSInit = 0x00000025                                 #  &25
OS_GSRead = 0x00000026                                 #  &26
OS_GSTrans = 0x00000027                                #  &27
OS_BinaryToDecimal = 0x00000028                        #  &28
OS_FSControl = 0x00000029                              #  &29
OS_ChangeDynamicArea = 0x0000002A                      #  &2A
OS_GenerateError = 0x0000002B                          #  &2B
OS_ReadEscapeState = 0x0000002C                        #  &2C
OS_EvaluateExpression = 0x0000002D                     #  &2D
OS_SpriteOp = 0x0000002E                               #  &2E
OS_ReadPalette = 0x0000002F                            #  &2F ; (was FontManager)
OS_ServiceCall = 0x00000030                            #  &30 ; was Claim_Release_FIQ
OS_ReadVduVariables = 0x00000031                       #  &31
OS_ReadPoint = 0x00000032                              #  &32
OS_UpCall = 0x00000033                                 #  &33
OS_CallAVector = 0x00000034                            #  &34 ; was ReadCurrentError
OS_ReadModeVariable = 0x00000035                       #  &35
OS_RemoveCursors = 0x00000036                          #  &36
OS_RestoreCursors = 0x00000037                         #  &37
OS_SWINumberToString = 0x00000038                      #  &38
OS_SWINumberFromString = 0x00000039                    #  &39
OS_ValidateAddress = 0x0000003A                        #  &3A
OS_CallAfter = 0x0000003B                              #  &3B
OS_CallEvery = 0x0000003C                              #  &3C
OS_RemoveTickerEvent = 0x0000003D                      #  &3D
OS_InstallKeyHandler = 0x0000003E                      #  &3E
OS_CheckModeValid = 0x0000003F                         #  &3F
OS_ChangeEnvironment = 0x00000040                      #  &40
OS_ClaimScreenMemory = 0x00000041                      #  &41
OS_ReadMonotonicTime = 0x00000042                      #  &42
OS_SubstituteArgs = 0x00000043                         #  &43
OS_PrettyPrint = 0x00000044                            #  &44
OS_Plot = 0x00000045                                   #  &45
OS_WriteN = 0x00000046                                 #  &46
OS_AddToVector = 0x00000047                            #  &47
OS_WriteEnv = 0x00000048                               #  &48
OS_ReadArgs = 0x00000049                               #  &49
OS_ReadRAMFsLimits = 0x0000004A                        #  &4A
OS_ClaimDeviceVector = 0x0000004B                      #  &4B
OS_ReleaseDeviceVector = 0x0000004C                    #  &4C
OS_DelinkApplication = 0x0000004D                      #  &4D
OS_RelinkApplication = 0x0000004E                      #  &4E
OS_HeapSort = 0x0000004F                               #  &4F
OS_ExitAndDie = 0x00000050                             #  &50
OS_ReadMemMapInfo = 0x00000051                         #  &51
OS_ReadMemMapEntries = 0x00000052                      #  &52
OS_SetMemMapEntries = 0x00000053                       #  &53
OS_AddCallBack = 0x00000054                            #  &54
OS_ReadDefaultHandler = 0x00000055                     #  &55
OS_SetECFOrigin = 0x00000056                           #  &56
OS_SerialOp = 0x00000057                               #  &57
OS_ReadSysInfo = 0x00000058                            #  &58
OS_Confirm = 0x00000059                                #  &59
OS_ChangedBox = 0x0000005A                             #  &5A
OS_CRC = 0x0000005B                                    #  &5B
OS_ReadDynamicArea = 0x0000005C                        #  &5C
OS_PrintChar = 0x0000005D                              #  &5D
OS_ChangeRedirection = 0x0000005E                      #  &5E
OS_RemoveCallBack = 0x0000005F                         #  &5F
OS_FindMemMapEntries = 0x00000060                      #  &60
OS_SetColour = 0x00000061                              #  &61
OS_ClaimSWI = 0x00000062                               #  &62 ; In ToolkitSpt - Must be implemented
OS_ReleaseSWI = 0x00000063                             #  &63 ; OS > 3.10.
OS_Pointer = 0x00000064                                #  &64
OS_ScreenMode = 0x00000065                             #  &65
OS_DynamicArea = 0x00000066                            #  &66
OS_AbortTrap = 0x00000067                              #  &67
OS_Memory = 0x00000068                                 #  &68
OS_ClaimProcessorVector = 0x00000069                   #  &69
OS_Reset = 0x0000006A                                  #  &6A
OS_MMUControl = 0x0000006B                             #  &6B
OS_ResyncTime = 0x0000006C                             #  &6C
OS_PlatformFeatures = 0x0000006D                       #  &6D
OS_SynchroniseCodeAreas = 0x0000006E                   #  &6E
OS_CallASWI = 0x0000006F                               #  &6F
OS_AMBControl = 0x00000070                             #  &70
OS_CallASWIR12 = 0x00000071                            #  &71
OS_SpecialControl = 0x00000072                         #  &72
OS_EnterUSR32 = 0x00000073                             #  &73
OS_EnterUSR26 = 0x00000074                             #  &74
OS_UKSWI75 = 0x00000075                                #  &75
OS_UKSWI76 = 0x00000076                                #  &76
OS_ClaimOSSWI = 0x00000077                             #  &77
OS_TaskControl = 0x00000078                            #  &78
OS_DeviceDriver = 0x00000079                           #  &79
OS_Hardware = 0x0000007A                               #  &7A
OS_IICOp = 0x0000007B                                  #  &7B
OS_LeaveOS = 0x0000007C                                #  &7C
OS_ReadLine32 = 0x0000007D                             #  &7D
OS_SubstituteArgs32 = 0x0000007E                       #  &7E
OS_HeapSort32 = 0x0000007F                             #  &7F
OS_ConvertStandardDateAndTime = 0x000000C0             #  &C0
OS_ConvertDateAndTime = 0x000000C1                     #  &C1
OS_ConvertHex1 = 0x000000D0                            #  &D0
OS_ConvertHex2 = 0x000000D1                            #  &D1
OS_ConvertHex4 = 0x000000D2                            #  &D2
OS_ConvertHex6 = 0x000000D3                            #  &D3
OS_ConvertHex8 = 0x000000D4                            #  &D4
OS_ConvertCardinal1 = 0x000000D5                       #  &D5
OS_ConvertCardinal2 = 0x000000D6                       #  &D6
OS_ConvertCardinal3 = 0x000000D7                       #  &D7
OS_ConvertCardinal4 = 0x000000D8                       #  &D8
OS_ConvertInteger1 = 0x000000D9                        #  &D9
OS_ConvertInteger2 = 0x000000DA                        #  &DA
OS_ConvertInteger3 = 0x000000DB                        #  &DB
OS_ConvertInteger4 = 0x000000DC                        #  &DC
OS_ConvertBinary1 = 0x000000DD                         #  &DD
OS_ConvertBinary2 = 0x000000DE                         #  &DE
OS_ConvertBinary3 = 0x000000DF                         #  &DF
OS_ConvertBinary4 = 0x000000E0                         #  &E0
OS_ConvertSpacedCardinal1 = 0x000000E1                 #  &E1
OS_ConvertSpacedCardinal2 = 0x000000E2                 #  &E2
OS_ConvertSpacedCardinal3 = 0x000000E3                 #  &E3
OS_ConvertSpacedCardinal4 = 0x000000E4                 #  &E4
OS_ConvertSpacedInteger1 = 0x000000E5                  #  &E5
OS_ConvertSpacedInteger2 = 0x000000E6                  #  &E6
OS_ConvertSpacedInteger3 = 0x000000E7                  #  &E7
OS_ConvertSpacedInteger4 = 0x000000E8                  #  &E8
OS_ConvertFixedNetStation = 0x000000E9                 #  &E9
OS_ConvertNetStation = 0x000000EA                      #  &EA
OS_ConvertFixedFileSize = 0x000000EB                   #  &EB
OS_ConvertFileSize = 0x000000EC                        #  &EC
OS_WriteI = 0x00000100                                 #  &100-&1FF

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/PDriver
PDriver_Info = 0x00080140                              #  +0
PDriver_SetInfo = 0x00080141                           #  +1
PDriver_CheckFeatures = 0x00080142                     #  +2
PDriver_PageSize = 0x00080143                          #  +3
PDriver_SetPageSize = 0x00080144                       #  +4
PDriver_SelectJob = 0x00080145                         #  +5
PDriver_CurrentJob = 0x00080146                        #  +6
PDriver_FontSWI = 0x00080147                           #  +7
PDriver_EndJob = 0x00080148                            #  +8
PDriver_AbortJob = 0x00080149                          #  +9
PDriver_Reset = 0x0008014A                             #  +10
PDriver_GiveRectangle = 0x0008014B                     #  +11
PDriver_DrawPage = 0x0008014C                          #  +12
PDriver_GetRectangle = 0x0008014D                      #  +13
PDriver_CancelJob = 0x0008014E                         #  +14
PDriver_ScreenDump = 0x0008014F                        #  +15
PDriver_EnumerateJobs = 0x00080150                     #  +16
PDriver_SetPrinter = 0x00080151                        #  +17
PDriver_CancelJobWithError = 0x00080152                #  +18
PDriver_SelectIllustration = 0x00080153                #  +19
PDriver_InsertIllustration = 0x00080154                #  +20
PDriver_DeclareFont = 0x00080155                       #  +21
PDriver_DeclareDriver = 0x00080156                     #  +22
PDriver_RemoveDriver = 0x00080157                      #  +23
PDriver_SelectDriver = 0x00080158                      #  +24
PDriver_EnumerateDrivers = 0x00080159                  #  +25
PDriver_MiscOp = 0x0008015A                            #  +26
PDriver_MiscOpForDriver = 0x0008015B                   #  +27
PDriver_SetDriver = 0x0008015C                         #  +28
PDriver_JPEGSWI = 0x0008015D                           #  +29

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/PDumper
PDumper_Info = 0x00041B00                              #  &41B00
PDumper_Claim = 0x00041B01                             #  &41B01
PDumper_Free = 0x00041B02                              #  &41B02
PDumper_Find = 0x00041B03                              #  &41B03
PDumper_StartJob = 0x00041B04                          #  &41B04
PDumper_TidyJob = 0x00041B05                           #  &41B05
PDumper_SetColour = 0x00041B06                         #  &41B06
PDumper_PrepareStrip = 0x00041B07                      #  &41B07
PDumper_LookupError = 0x00041B08                       #  &41B08
PDumper_CopyFilename = 0x00041B09                      #  &41B09

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Podule
Podule_ReadID = 0x00040280
Podule_ReadHeader = 0x00040281
Podule_EnumerateChunks = 0x00040282
Podule_ReadChunk = 0x00040283
Podule_ReadBytes = 0x00040284
Podule_WriteBytes = 0x00040285
Podule_CallLoader = 0x00040286
Podule_RawRead = 0x00040287
Podule_RawWrite = 0x00040288
Podule_HardwareAddress = 0x00040289
Podule_EnumerateChunksWithInfo = 0x0004028A
Podule_HardwareAddresses = 0x0004028B
Podule_ReturnNumber = 0x0004028C
Podule_ReadInfo = 0x0004028D
Podule_SetSpeed = 0x0004028E

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Portable
Portable_Speed = 0x00042FC0                            #  &42FC0
Portable_Control = 0x00042FC1                          #  &42FC1
Portable_ReadBMUVariable = 0x00042FC2                  #  &42FC2
Portable_WriteBMUVariable = 0x00042FC3                 #  &42FC3
Portable_CommandBMU = 0x00042FC4                       #  &42FC4
Portable_ReadFeatures = 0x00042FC5                     #  &42FC5
Portable_Idle = 0x00042FC6                             #  &42FC6
Portable_Stop = 0x00042FC7                             #  &42FC7
Portable_Status = 0x00042FC8                           #  &42FC8

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/RAMFS
RamFS_DiscOp = 0x00040780                              #  &40780
RamFS_NOP1 = 0x00040781                                #  &40781
RamFS_Drives = 0x00040782                              #  &40782
RamFS_FreeSpace = 0x00040783                           #  &40783
RamFS_NOP2 = 0x00040784                                #  &40784
RamFS_DescribeDisc = 0x00040785                        #  &40785

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ResourceFS
ResourceFS_RegisterFiles = 0x00041B40                  #  &41B40
ResourceFS_DeregisterFiles = 0x00041B41                #  &41B41

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ScrBlank
ScreenBlanker_Control = 0x00043100                     #  &43100

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/ScrModes
ScreenModes_ReadInfo = 0x000487C0

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/SCSI
SCSI_Version = 0x000403C0                              #  +0   &403C0
SCSI_Initialise = 0x000403C1                           #  +1   &403C1
SCSI_Control = 0x000403C2                              #  +2   &403C2
SCSI_Op = 0x000403C3                                   #  +3   &403C3
SCSI_Status = 0x000403C4                               #  +4   &403C4
SCSI_ReadControlLines = 0x000403C5                     #  +5   &403C5  } Not supported by Acorn SCSIdriver
SCSI_EEProm = 0x000403C6                               #  +6   &403C6  }
SCSI_Reserve = 0x000403C7                              #  +7   &403C7
SCSI_List = 0x000403C8                                 #  +8   &403C8
SCSI_TargetControl = 0x000403C9                        #  +9   &403C9  } Not supported by Acorn SCSIDriver
SCSI_LogVersion = 0x00041080
SCSI_LogList = 0x00041081

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/SCSIFS
SCSIFS_DiscOp = 0x00040980                             #  &40980
SCSIFS_NOP1 = 0x00040981                               #  &40981
SCSIFS_Drives = 0x00040982                             #  &40982
SCSIFS_FreeSpace = 0x00040983                          #  &40983
SCSIFS_NOP2 = 0x00040984                               #  &40984
SCSIFS_DescribeDisc = 0x00040985                       #  &40985
SCSIFS_TestReady = 0x00040986                          #  &40986
SCSIFS_NOP3 = 0x00040987                               #  &40987
SCSIFS_NOP4 = 0x00040988                               #  &40988
SCSIFS_NOP5 = 0x00040989                               #  &40989
SCSIFS_NOP6 = 0x0004098A                               #  &4098a
SCSIFS_NOP7 = 0x0004098B                               #  &4098b
SCSIFS_MiscOp = 0x0004098C                             #  &4098c
SCSIFS_SectorDiscOp = 0x0004098D                       #  &4098d
SCSIFS_NOP8 = 0x0004098E                               #  &4098e
SCSIFS_NOP9 = 0x0004098F                               #  &4098f
SCSIFS_NOP10 = 0x00040990                              #  &40990
SCSIFS_NOP11 = 0x00040991                              #  &40991
SCSIFS_FreeSpace64 = 0x00040992                        #  &40992

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Shell
Shell_Create = 0x000405C0
Shell_Destroy = 0x000405C1

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Sound
Sound_Configure = 0x00040140
Sound_Enable = 0x00040141
Sound_Stereo = 0x00040142
Sound_Speaker = 0x00040143
Sound_Mode = 0x00040144
Sound_LinearHandler = 0x00040145
Sound_SampleRate = 0x00040146
Sound_Volume = 0x00040180
Sound_SoundLog = 0x00040181
Sound_LogScale = 0x00040182
Sound_InstallVoice = 0x00040183
Sound_RemoveVoice = 0x00040184
Sound_AttachVoice = 0x00040185
Sound_ControlPacked = 0x00040186                       #  was 'Sound' but not in module!
Sound_Tuning = 0x00040187
Sound_Pitch = 0x00040188
Sound_Control = 0x00040189
Sound_AttachNamedVoice = 0x0004018A
Sound_ReadControlBlock = 0x0004018B
Sound_WriteControlBlock = 0x0004018C
Sound_QInit = 0x000401C0
Sound_QSchedule = 0x000401C1
Sound_QRemove = 0x000401C2
Sound_QFree = 0x000401C3
Sound_QSDispatch = 0x000401C4
Sound_QTempo = 0x000401C5
Sound_QBeat = 0x000401C6
Sound_QInterface = 0x000401C7

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Squash
Squash_Compress = 0x00042700
Squash_Decompress = 0x00042701

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Super
Super_Sample90 = 0x00040D80                            #  &40D80  internal use only (by Font Manager)
Super_Sample45 = 0x00040D81                            #  &40D81  internal use only (by Font Manager)

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Switcher
TaskManager_TaskNameFromHandle = 0x00042680
TaskManager_EnumerateTasks = 0x00042681
TaskManager_Shutdown = 0x00042682                      #  Switcher 0.60 onwards
TaskManager_StartTask = 0x00042683

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/TaskWindow
TaskWindow_TaskInfo = 0x00043380                       #  43380

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Territory
Territory_Number = 0x00043040
Territory_Register = 0x00043041
Territory_Deregister = 0x00043042
Territory_NumberToName = 0x00043043
Territory_Exists = 0x00043044
Territory_AlphabetNumberToName = 0x00043045
Territory_SelectAlphabet = 0x00043046
Territory_SetTime = 0x00043047
Territory_ReadCurrentTimeZone = 0x00043048
Territory_ConvertTimeToUTCOrdinals = 0x00043049
Territory_ReadTimeZones = 0x0004304A
Territory_ConvertDateAndTime = 0x0004304B
Territory_ConvertStandardDateAndTime = 0x0004304C
Territory_ConvertStandardDate = 0x0004304D
Territory_ConvertStandardTime = 0x0004304E
Territory_ConvertTimeToOrdinals = 0x0004304F
Territory_ConvertTimeStringToOrdinals = 0x00043050
Territory_ConvertOrdinalsToTime = 0x00043051
Territory_Alphabet = 0x00043052
Territory_AlphabetIdentifier = 0x00043053
Territory_SelectKeyboardHandler = 0x00043054
Territory_WriteDirection = 0x00043055
Territory_CharacterPropertyTable = 0x00043056
Territory_LowerCaseTable = 0x00043057
Territory_UpperCaseTable = 0x00043058
Territory_ControlTable = 0x00043059
Territory_PlainTable = 0x0004305A
Territory_ValueTable = 0x0004305B
Territory_RepresentationTable = 0x0004305C
Territory_Collate = 0x0004305D
Territory_ReadSymbols = 0x0004305E
Territory_ReadCalendarInformation = 0x0004305F
Territory_NameToNumber = 0x00043060
Territory_TransformString = 0x00043061                 #  &43061
Territory_ConvertTextToString = 0x00043075             #  &43075

# Generated from /Users/charles/projects/RO/riscos/Export/Hdr/Interface/Wimp
Wimp_Initialise = 0x000400C0                           #  &400C0
Wimp_CreateWindow = 0x000400C1                         #  &400C1
Wimp_CreateIcon = 0x000400C2                           #  &400C2
Wimp_DeleteWindow = 0x000400C3                         #  &400C3
Wimp_DeleteIcon = 0x000400C4                           #  &400C4
Wimp_OpenWindow = 0x000400C5                           #  &400C5
Wimp_CloseWindow = 0x000400C6                          #  &400C6
Wimp_Poll = 0x000400C7                                 #  &400C7
Wimp_RedrawWindow = 0x000400C8                         #  &400C8
Wimp_UpdateWindow = 0x000400C9                         #  &400C9
Wimp_GetRectangle = 0x000400CA                         #  &400CA
Wimp_GetWindowState = 0x000400CB                       #  &400CB
Wimp_GetWindowInfo = 0x000400CC                        #  &400CC
Wimp_SetIconState = 0x000400CD                         #  &400CD
Wimp_GetIconState = 0x000400CE                         #  &400CE
Wimp_GetPointerInfo = 0x000400CF                       #  &400CF
Wimp_DragBox = 0x000400D0                              #  &400D0
Wimp_ForceRedraw = 0x000400D1                          #  &400D1
Wimp_SetCaretPosition = 0x000400D2                     #  &400D2
Wimp_GetCaretPosition = 0x000400D3                     #  &400D3
Wimp_CreateMenu = 0x000400D4                           #  &400D4
Wimp_DecodeMenu = 0x000400D5                           #  &400D5
Wimp_WhichIcon = 0x000400D6                            #  &400D6
Wimp_SetExtent = 0x000400D7                            #  &400D7
Wimp_SetPointerShape = 0x000400D8                      #  &400D8
Wimp_OpenTemplate = 0x000400D9                         #  &400D9
Wimp_CloseTemplate = 0x000400DA                        #  &400DA
Wimp_LoadTemplate = 0x000400DB                         #  &400DB
Wimp_ProcessKey = 0x000400DC                           #  &400DC
Wimp_CloseDown = 0x000400DD                            #  &400DD
Wimp_StartTask = 0x000400DE                            #  &400DE
Wimp_ReportError = 0x000400DF                          #  &400DF
Wimp_GetWindowOutline = 0x000400E0                     #  &400E0
Wimp_PollIdle = 0x000400E1                             #  &400E1
Wimp_PlotIcon = 0x000400E2                             #  &400E2
Wimp_SetMode = 0x000400E3                              #  &400E3
Wimp_SetPalette = 0x000400E4                           #  &400E4
Wimp_ReadPalette = 0x000400E5                          #  &400E5
Wimp_SetColour = 0x000400E6                            #  &400E6
Wimp_SendMessage = 0x000400E7                          #  &400E7
Wimp_CreateSubMenu = 0x000400E8                        #  &400E8
Wimp_SpriteOp = 0x000400E9                             #  &400E9
Wimp_BaseOfSprites = 0x000400EA                        #  &400EA
Wimp_BlockCopy = 0x000400EB                            #  &400EB
Wimp_SlotSize = 0x000400EC                             #  &400EC
Wimp_ReadPixTrans = 0x000400ED                         #  &400ED
Wimp_ClaimFreeMemory = 0x000400EE                      #  &400EE
Wimp_CommandWindow = 0x000400EF                        #  &400EF
Wimp_TextColour = 0x000400F0                           #  &400F0
Wimp_TransferBlock = 0x000400F1                        #  &400F1
Wimp_ReadSysInfo = 0x000400F2                          #  &400F2
Wimp_SetFontColours = 0x000400F3                       #  &400F3
Wimp_GetMenuState = 0x000400F4                         #  &400F4        Wimp 2.18 onwards
Wimp_RegisterFilter = 0x000400F5                       #  &400F5        Wimp 2.85 onwards
Wimp_AddMessages = 0x000400F6                          #  &400F6        Wimp 2.95 onwards
Wimp_RemoveMessages = 0x000400F7                       #  &400F7        Wimp 3.05 onwards
Wimp_SetColourMapping = 0x000400F8                     #  &400F8
Wimp_TextOp = 0x000400F9                               #  &400F9        Wimp 3.23 onwards
Wimp_SetWatchdogState = 0x000400FA                     #  &400FA        Wimp 3.22 onwards
Wimp_Extend = 0x000400FB                               #  &400FB
Wimp_ResizeIcon = 0x000400FC                           #  &400FC
Wimp_AutoScroll = 0x000400FD                           #  &400FD        Wimp 4.00 onwards

# EOF
