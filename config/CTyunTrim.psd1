@{
    SchemaVersion = '1.0'
    ProfileName   = 'MinimalInterop'
    Description   = 'Remove CTyun management, repair, update and optional feature layers while preserving the tested interoperability core.'

    SupportedBuilds = @(
        26100,
        26200
    )

    Roots = @{
        CTyun       = 'C:\Program Files (x86)\ctyun'
        PublicData  = 'C:\Users\Public\Documents\mirror'
        Cloudbase   = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
        Drivers     = 'C:\Windows\System32\drivers'
        PublicDesk  = 'C:\Users\Public\Desktop'
    }

    CoreFingerprint = @{
        ProfileVersion = 'ctyun-win11-26100-clipa-2.1.0.0'

        Services = @(
            @{ Name = 'BalloonService';     ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\drivers\Balloon\blnsvr.exe' },
            @{ Name = 'clink_service';      ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\64\clink_service.exe' },
            @{ Name = 'clipa';              ExpectedImage = 'C:\Program Files (x86)\ctyun\clipa\clipa.win.exe'; ExpectedFileVersion = '2.1.0.0' },
            @{ Name = 'cloudshare_service'; ExpectedImage = 'C:\Program Files (x86)\ctyun\cloudshare\cloudshare_service.exe' }
        )

        Drivers = @(
            @{ Name = 'CLINKAC';          ExpectedImage = 'C:\Windows\System32\drivers\CLINKAC.sys' },
            @{ Name = 'ClinkMouseFilter'; ExpectedImage = 'C:\Windows\System32\drivers\ClinkMouseFilter.sys' },
            @{ Name = 'WinDivertScanner'; ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\res\WinDivertProxy-Port\WinDivert64.sys' }
        )
    }

    Preserve = @{
        Services = @(
            'BalloonService',
            'clink_service',
            'clipa',
            'cloudshare_service'
        )

        Drivers = @(
            'CLINKAC',
            'ClinkMouseFilter',
            'WinDivertScanner'
        )

        Paths = @(
            'C:\Program Files (x86)\ctyun\clink\64',
            'C:\Program Files (x86)\ctyun\clink\drivers\Balloon',
            'C:\Program Files (x86)\ctyun\clink\res\WinDivertProxy-Port',
            'C:\Program Files (x86)\ctyun\clink\res\clink_dect',
            'C:\Program Files (x86)\ctyun\clink\res\share_space',
            'C:\Program Files (x86)\ctyun\cloudshare',
            'C:\Program Files (x86)\ctyun\clipa',
            'C:\Program Files (x86)\ctyun\dokan\dokan2.dll'
        )

        RequiredPaths = @(
            'C:\Program Files (x86)\ctyun\clink\64',
            'C:\Program Files (x86)\ctyun\clink\drivers\Balloon',
            'C:\Program Files (x86)\ctyun\clink\res\WinDivertProxy-Port',
            'C:\Program Files (x86)\ctyun\cloudshare',
            'C:\Program Files (x86)\ctyun\clipa',
            'C:\Program Files (x86)\ctyun\dokan\dokan2.dll'
        )
    }

    ExecutionGuards = @(
        'ExternalLaunch.exe',
        'CloudUpdate.exe',
        'ecloud_img_conf.exe',
        'TaskAgentDetect.exe',
        'TaskLaunch.exe',
        'ecloud_Launch_FullSetup_103010306.exe'
    )

    ScheduledTasks = @(
        @{ Name = 'check_report_img_onstart';   TaskPath = '\'; ExpectedImage = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\exe\ecloud_img_conf.exe' },
        @{ Name = 'check_report_img_daily';     TaskPath = '\'; ExpectedImage = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\exe\ecloud_img_conf.exe' },
        @{ Name = 'check_report_img_random';    TaskPath = '\'; ExpectedImage = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\exe\ecloud_img_conf.exe' },
        @{ Name = 'ecloud_update_agent_detect'; TaskPath = '\'; ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskAgentDetect.exe' },
        @{ Name = 'ecloud_update_task_launch';  TaskPath = '\'; ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\Mirror\Launch\TaskLaunch.exe' }
    )

    Processes = @(
        'AppMarketSvc',
        'cloud-printer-client',
        'cloud-printer-client-service',
        'clinkte_service',
        'clinktetool',
        'clinkteTray',
        'CtyunDesktopMaster',
        'CtyunDesktopMasterSrv',
        'CtyunDesktopDrtSrv',
        'ecloudAiAssistant',
        'ecloudAppManager',
        'CloudUpdate',
        'ExternalLaunch',
        'TaskAgentDetect',
        'TaskLaunch',
        'ecloud_img_conf'
    )

    Services = @(
        @{ Name = 'AppMarketSvc';              ExpectedImage = 'C:\Program Files (x86)\ctyun\AppMarketSvc\AppMarketSvc.exe' },
        @{ Name = 'CloudPrinterClientService'; ExpectedImage = 'C:\Program Files (x86)\ctyun\CloudPrinterClient\bin\cloud-printer-client-service.exe' },
        @{ Name = 'clinkte_service';           ExpectedImage = 'C:\Program Files (x86)\ctyun\clink\Config\FileCrypto\64\clinkte_service.exe' },
        @{ Name = 'cloud-sync-server';         ExpectedImage = 'C:\Program Files (x86)\ctyun\cloud-sync-server\cloud-sync-server.exe' },
        @{ Name = 'cloudbase-init';            ExpectedImage = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\OpenStackService.exe' },
        @{ Name = 'cloudbase-init-unattend';   ExpectedImage = 'C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\OpenStackService.exe' }
    )

    DriverServices = @(
        @{ Name = 'dokan2';       ExpectedImage = 'C:\Program Files (x86)\ctyun\dokan\dokan2.sys' },
        @{ Name = 'CLINKTE';      ExpectedImage = 'C:\Windows\System32\drivers\CLINKTE.sys' },
        @{ Name = 'CLINKTELOG';   ExpectedImage = 'C:\Windows\System32\drivers\CLINKTELOG.sys' },
        @{ Name = 'CLINKFS';      ExpectedImage = 'C:\Windows\System32\drivers\CLINKFS.sys' },
        @{ Name = 'cloudshareAC'; ExpectedImage = 'C:\Windows\System32\drivers\cloudshareAC.sys' }
    )

    RunValues = @(
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'ecloudAiAssistant' },
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'CtyunDesktopMasterClient' },
        @{ Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Name = 'electron.app.CtyunLaptopManager' },
        @{ Hive = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run'; Name = 'ecloudAiAssistant' },
        @{ Hive = 'HKCU'; Key = 'Software\Microsoft\Windows\CurrentVersion\Run'; Name = 'CtyunDesktopMasterClient' }
    )

    Directories = @(
        'C:\Program Files (x86)\ctyun\AppMarketSvc',
        'C:\Program Files (x86)\ctyun\ecloudAiAssistant',
        'C:\Program Files (x86)\ctyun\ecloudAiAssistantUpdateLauncher',
        'C:\Program Files (x86)\ctyun\CtyunDesktopMasterClient',
        'C:\Program Files (x86)\ctyun\ecloudAppManager',
        'C:\Program Files (x86)\ctyun\PrinterManager',
        'C:\Program Files (x86)\ctyun\CloudPrinterClient',
        'C:\Program Files (x86)\ctyun\CloudPrinterUsbDk',
        'C:\Program Files (x86)\ctyun\ecloudDisk',
        'C:\Program Files (x86)\ctyun\cloud-sync-server',
        'C:\Program Files (x86)\ctyun\FirewallNetwork',
        'C:\Program Files (x86)\ctyun\CertUpdate',
        'C:\Program Files (x86)\ctyun\clink\Mirror',
        'C:\Program Files (x86)\ctyun\clink\eduMonitor',
        'C:\Program Files (x86)\ctyun\clink\help',
        'C:\Program Files (x86)\ctyun\clink\Config\FileCrypto',
        'C:\Program Files (x86)\ctyun\clink\res\screenrecord',
        'C:\Program Files (x86)\ctyun\clink\res\DrawArea',
        'C:\Program Files (x86)\ctyun\clink\res\WinDivertProxy',
        'C:\Program Files (x86)\ctyun\clink\res\AutoCAD',
        'C:\Program Files (x86)\ctyun\clink\res\ZWCAD',
        'C:\Program Files (x86)\ctyun\clink\res\GstarCAD',
        'C:\Program Files (x86)\ctyun\clink\res\EClassroom',
        'C:\Program Files\Cloudbase Solutions\Cloudbase-Init'
    )

    Files = @(
        'C:\Program Files (x86)\ctyun\dokan\dokan2.sys',
        'C:\Windows\System32\drivers\CLINKTE.sys',
        'C:\Windows\System32\drivers\CLINKTELOG.sys',
        'C:\Windows\System32\drivers\CLINKFS.sys',
        'C:\Windows\System32\drivers\cloudshareAC.sys'
    )

    EncodedFiles = @(
        @{ Parent = 'C:\Users\Public\Desktop'; Utf8NameBase64 = '5aSp57+85LqR55S16ISR5biu5Yqp5omL5YaMLmxuaw==' }
    )

    PublicDataDirectories = @(
        'C:\Users\Public\Documents\mirror\AppMarketSvc',
        'C:\Users\Public\Documents\mirror\AppSdkLogs',
        'C:\Users\Public\Documents\mirror\CloudPrinter',
        'C:\Users\Public\Documents\mirror\CloudUpdateLogs',
        'C:\Users\Public\Documents\mirror\CtyunDesktopMaster',
        'C:\Users\Public\Documents\mirror\ecloudAiAssistant',
        'C:\Users\Public\Documents\mirror\ecloudAppManager',
        'C:\Users\Public\Documents\mirror\FileCrypto',
        'C:\Users\Public\Documents\mirror\Launch',
        'C:\Users\Public\Documents\mirror\PrinterJobLog',
        'C:\Users\Public\Documents\mirror\endpoint_log',
        'C:\Users\Public\Documents\mirror\Patch\CloudDisk',
        'C:\Users\Public\Documents\mirror\Patch\dokan',
        'C:\Users\Public\Documents\mirror\Patch\ecloudAiAssistant',
        'C:\Users\Public\Documents\mirror\Patch\ecloudAppSdk',
        'C:\Users\Public\Documents\mirror\Patch\ecloudClinkFileCrypto',
        'C:\Users\Public\Documents\mirror\Patch\ecloudClinkVirtualPrinter',
        'C:\Users\Public\Documents\mirror\Patch\ecloudCloudPrinterClient',
        'C:\Users\Public\Documents\mirror\Patch\ecloudCloudSync',
        'C:\Users\Public\Documents\mirror\Patch\ecloudCloudUpdate',
        'C:\Users\Public\Documents\mirror\Patch\ecloudCtyunDesktopMasterClient',
        'C:\Users\Public\Documents\mirror\Patch\ecloudLaunch',
        'C:\Users\Public\Documents\mirror\Patch\PrinterManager'
    )

    PublicDataPreserve = @(
        'C:\Users\Public\Documents\mirror\ClinkAgent',
        'C:\Users\Public\Documents\mirror\cloudshare',
        'C:\Users\Public\Documents\mirror\Patch\ecloudClinkAgent',
        'C:\Users\Public\Documents\mirror\Patch\ecloudCloudShare',
        'C:\Users\Public\Documents\mirror\Patch\ecloudClinkAppControl',
        'C:\Users\Public\Documents\mirror\clink_agent.json',
        'C:\Users\Public\Documents\mirror\ctmeta.log',
        'C:\Users\Public\Documents\mirror\device_bind.ini'
    )

    WsusPolicy = @{
        MachineKey = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        Values = @(
            @{ Name = 'WUServer';                  Type = 'String'; Value = 'https://127.0.0.1' },
            @{ Name = 'WUStatusServer';            Type = 'String'; Value = 'https://127.0.0.1' },
            @{ Name = 'UpdateServiceUrlAlternate'; Type = 'String'; Value = 'https://127.0.0.1' }
        )
        AuKey = 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        AuValues = @(
            @{ Name = 'UseWUServer'; Type = 'DWord'; Value = 1 },
            @{ Name = 'NoAutoUpdate'; Type = 'DWord'; Value = 1 }
        )
        PreserveValues = @(
            'ExcludeWUDriversInQualityUpdate',
            'UpdateNotificationLevel'
        )
    }

    KnownCertificates = @(
        @{ Store = 'Cert:\LocalMachine\Root';             Thumbprint = '458248412225BE670E2FE6025A45CD5A896BC81B'; SubjectContains = 'www.chinatelecom.com.cn' },
        @{ Store = 'Cert:\LocalMachine\Root';             Thumbprint = '422B95B06119B2DA4CFEDBAA3FFFD3D3A3A92E6B'; SubjectContains = 'O=ctyun' },
        @{ Store = 'Cert:\LocalMachine\TrustedPublisher'; Thumbprint = 'F8D045831F0AE192C9BFAF80BBD669040308C904'; SubjectContainsBase64 = '5aSp57+85LqR56eR5oqA5pyJ6ZmQ5YWs5Y+4' },
        @{ Store = 'Cert:\LocalMachine\TrustedPublisher'; Thumbprint = 'B8339737AFD37AB0F9AAB2FE2BC77F0D28C3D9EA'; SubjectContainsBase64 = '5Lit5Zu955S15L+h6IKh5Lu95pyJ6ZmQ5YWs5Y+45LqR6K6h566X5YiG5YWs5Y+4' },
        @{ Store = 'Cert:\LocalMachine\TrustedPublisher'; Thumbprint = 'A7E9CECBDB719570BEFB5AF6D32948280738E598'; SubjectContainsBase64 = '5Lit5Zu955S15L+h6IKh5Lu95pyJ6ZmQ5YWs5Y+45LqR6K6h566X5YiG5YWs5Y+4' },
        @{ Store = 'Cert:\LocalMachine\TrustedPublisher'; Thumbprint = '4DA2321D9673218DFFDF44558873CC8D7762A37D'; SubjectContainsBase64 = '5Lit5Zu955S15L+h6IKh5Lu95pyJ6ZmQ5YWs5Y+45LqR6K6h566X5YiG5YWs5Y+4' }
    )

    CertificateAuditPattern = 'chinatelecom|ctyun'

    CertificateAuditTermsBase64 = @(
        '5aSp57+85LqR',
        '5Lit5Zu955S15L+h'
    )

    FirewallPrograms = @(
        'C:\Program Files (x86)\ctyun\clink\mirror\cloudupdate\jre\bin\java.exe'
    )

    DiscoverOnlyPaths = @(
        'C:\Program Files\ctyun-client',
        'C:\Program Files (x86)\ecloud'
    )
}
