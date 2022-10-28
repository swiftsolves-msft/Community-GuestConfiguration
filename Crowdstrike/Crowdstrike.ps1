configuration Crowdstrike

{ 
    Import-DscResource -ModuleName PSDSCResources
    Node localhost
    {
        Service CrowdstrikeFalconAgent
        {
            Name        = "CSFalconService"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Present"
        }
    }
}