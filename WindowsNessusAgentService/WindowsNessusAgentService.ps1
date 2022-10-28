configuration WindowsNessusAgentService
{
    Import-DscResource -ModuleName PSDSCResources
    Node localhost
    {

        Service TenableNessusAgent
        {
            Name        = "Tenable Nessus Agent"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Present"
        }
    }
}