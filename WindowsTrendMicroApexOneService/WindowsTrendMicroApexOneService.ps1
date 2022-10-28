configuration WindowsTrendMicroApexOneService
{
    Import-DscResource -ModuleName PSDSCResources
    Node localhost
    {

        Service ApexOneNTRealTimeScan
        {
            Name        = "ntrtscan"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Present"
        }
    }
}