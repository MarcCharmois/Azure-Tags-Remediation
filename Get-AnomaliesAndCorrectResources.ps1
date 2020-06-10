#-----------------------------------------------

#This script generates 2 .csv files: 

#One .csv file is listing all the anomalies for a tag called XXX (one line for resource with missing tag, wrong tag, ect.)
#we asume that the tag value is a JSON string and that the JSON has to be valid and has to correspond to the company rules
#(all attributes present, all the attributes values compliant with company rules)

#for each anomaly will tell what to do. Action will be specify in the "Mode" column of the .csv file: 
    #"create" tells the remediation script to create a tag 
    #"format" tells the remdiation script to format the tag
    #"Investigate" tells the script to do nothing and warns the user that there is not enough information 
    #to create a tag or format an existing one

#The other .cv file is listing correct resources, (one line for one resource with all required tags and well formatted tags)

#To remediate the tags, you need first to generate the .csv of the anomalies with this script
#then execute the remediation script with the anomalies .csv file as an input
#-----------------------------------------------


param (
    $subscriptionId

)

############################## Main Script part 1 ############################################

#script is use for a specific subscription
select-azSubscription -subscriptionId $subscriptionId

#Get the context for qualifying the ouput .csv file
$context = Get-AzContext
$contextName = $context.Name
$contextName = $contextName -replace " ", ""
$contextName = $contextName -replace "/", "-"
$environmentType=""
$subscriptionName =""

#Context can be linked to an environment or a country, a region, a Busines Unit, etc...

#samples:
if ($contextName -like "*DEV*") {
    $contextName = "Dev-Env"
    $environmentType ="DEV"
    $subscriptionName = "DEV subscription"
}
if ($contextName -like "*UAT*") {
    $contextName = "UAT-ENV"
    $environmentType ="UAT"
    $subscriptionName = "UAT subscription"
}


if ($contextName -like "*Noram*") {

    $contextName = "North-America"
    $environmentType ="UAT"
    $subscriptionName = "Noram UAT"
}

if ($contextName -like "*Marketing*") {

    $contextName = "Marketing"
    $environmentType ="PRD"
    $subscriptionName = "Marketing PRD"
}


}

############################## End of Main Script part 1 ############################################

############################## Script Functions ############################################

#As the syntax for getting the resource name is different wether the item is a resource or a resource group
#we use a specific resource to get the name of a resource
function get-assetName($type, $resource) {
    if ($type -like "*RG*") {

        return $resource.resourceGroupName
    }
    else {
        return $resource.name
    }


#will check if the resource is correct or not
function checkItem($type, $resource, $resourceGroup, $envType) {
    #array of all the anomalies
    #will be used to generate a .csv file at the end of the script
    $anomaly = @{ }
    #array of all the correct resources
    #will be used to generate a .csv file at the end of the script
    $correctTag = @{ }

    #Mode for the remdiation
    $createMode = "create" #create a missing tag
    $formatMode = "format" #format a not well formatted tag
    $investigateMode = "investigate" #tell the remediation script there is nothing to do and the user to get more information
    
    Write-Host ("environment type: " + $envType)
    write-host ((get-assetName $type $resource) + "  found...") 
    write-host ("Type : " + $type )
    Write-Output ("resource id:")
    Write-Output $resource.resourceId

    if ($type -notlike "*RG*") {
        Write-Output ("resourceGroup id:")
        Write-Output $resourceGroup.resourceId

        $RGtags = new-object PSCustomObject -Property $resourceGroup.Tags
        #Get the xxx tag at the Resource Group level
        $RGxxxTag = $RGtags.xxx
        Write-Output ("resource group xxx tag:")
        Write-Output $RGxxxTag

    }
    
    #When remediating, the syntax is different wether you have at least one tag or not tag at all. 
    #So you have to check if you have at least one tag already created or no tags at all
    if (($resource.Tags -eq $null) -or ($resource.Tags -eq "")) {
        Write-Output ('no tag at all for this asset($resource.Tags -eq $null)')
        if ($type -like "*RG*") {
            $anomaly = @{
                Policy = "no-XXX-Tag"
                Subscription = $subscriptionName
                Rule = "Cloud Resources must have a XXX tag set"
                DetectedValue = 'no tags at all'
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceName = $resource.Name
                ResourceId    = $resource.ResourceId
                WrongTag      = ""
                Mode          = $investigateMode
                AppliSponsor  = ""
                AppliOwner    = ""
                ResourceType  = $resource.resourceType
            }
            $global:anomalies += $anomaly
            return
        }
    }

    #Get the tags at the json format to display
    $jsonTags = $resource.Tags | ConvertTo-Json
    Write-Output("json Tags:")
    Write-Output ($jsonTags)
    #checking again if there is at least one tag
    if ($resource.Tags.Count -eq 0) {
        Write-Output ('no tag at all for this asset ($resource.Tags empty hashtable)')
        if ($type -like "*RG*") {
            $anomaly = @{
                Policy = "no-XXX-tag"
                Subscription = $subscriptionName
                DetectedValue = 'no tags at all'
                Rule = "Cloud Resources must have a xxx tag set"
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceName = $resource.Name
                ResourceId    = $resource.ResourceId
                WrongTag      = ""
                Mode          = $investigateMode
                AppliSponsor  = ""
                AppliOwner    = ""
                ResourceType  = $resource.resourceType
            }
            $global:anomalies += $anomaly
            return
        }
    }

    $tags = new-object PSCustomObject -Property $resource.Tags
    #for having all the tags :
    #write-output $tags
    #XXX
    write-output ($tags)
    $applicationTag = $tags.applicationName
    $ApplicationSponsor = $tags.ApplicationSponsor
    $ApplicationOwner = $tags.ApplicationOwner
    $ApplicationBilling = $tags.Billing
    $envTypeTag = $tags.EnvironmentType

    if ($applicationTag -ne $null -and $applicationTag) {
        write-output ("applicationName : " + $applicationTag)
    }
    $XXXTag = ""
    #In Azure tag is case sensitive so we have to check if the tag starts with lowercase or uppercase
    #to be sure to get the tag if it exists
    $XXXTag1 = $tags.Xxx
    $XXXTag2 = $tags.xxx 

    if (($XXXTag1 -ne $null) -and $XXXTag1) {
        $XXXTag = $XXXTag1
    }
    if (($XXXTag2 -ne $null) -and $XXXTag2) {
        $XXXTag = $XXXTag2
    }


    if ($XXXTag -ne $null) {
        #checking if the JSON of the tag is valid
        try {
            $oxxxTag = $XXXTag | ConvertFrom-Json 
        }
        catch {
            #The JSON of the tag is not valid
            write-output ("XXX tag json of this resourcegroup cannot be parsed")
            $anomaly = @{
                Policy = "XXX-tag-not-well-formed"
                Subscription = $subscriptionName
                Rule = "XXX tag not well formed"
                DetectedValue = 'XXX tag cannot be parsed'
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceName = $resource.Name
                ResourceId    = $resource.ResourceId
                WrongTag      = $XXXTag
                Mode          = $formatMode
                AppliSponsor  = $ApplicationSponsor
                AppliOwner    = $ApplicationOwner
                AppliTag      = $applicationTag
                AppliBilling  = $ApplicationBilling
                ResourceType  = $resource.resourceType
                EnvironmentType = $envTypeTag
            }
            $global:anomalies += $anomaly
            write-host("----------------")
            return
        }
        if (! $XXXTag) {
            write-output ("this resourcegroup has a XXX tag empty")

            if (($RGXXXTag -ne $null) -and $RGXXXTag) {
                #the resource has not the tag but ist RG has the tag
                write-output ("RG xxx tag found")
                write-output $RGXXXTag
                $resourceGroupeName = $resource.resourceGroupName

                $resourceGroup = Get-AzResourceGroup -Name $resourceGroupeName
                $RgTags = $resourceGroup.Tags

                $RgAppliTag = $RGtags.ApplicationName
                $RgAppliSponsorTag = $RGtags.ApplicationSponsor
                $RgAppliOwnerTag = $RGtags.ApplicationOwner
                $RgAppliBillingTag = $RGtags.Billing

                $anomaly = @{
                    Policy="no-XXX-tag"
                    Subscription = $subscriptionName
                    DetectedValue = 'XXX tag empty'
                    Rule = "Cloud Resources must have a XXX tag set"
                    ResourceGroup = $resourceGroup.ResourceGroupName
                    ResourceName = $resource.Name
                    ResourceId    = $resource.ResourceId
                    RGxxxTag      = $RGXXXTag
                    Mode          = $createMode
                    AppliTag      = $RgAppliTag
                    AppliSponsor  = $RgAppliSponsorTag
                    AppliOwner    = $RgAppliOwnerTag
                    AppliBilling  = $RgAppliBillingTag
                    ResourceType  = $resource.resourceType
                    EnvironmentType = $envTypeTag
                }
                $global:anomalies += $anomaly
                return
            }
            else {
                #no xxx tag and no xxx tag at the RG level
                write-output ("RG xxx tag not found")
                write-output $RGXXXTag
                write-output ("and its RG has no xxx tag neither")
                $anomaly = @{
                    Policy="no-XXX-tag"
                    Subscription = $subscriptionName
                    DetectedValue = 'XXX tag missing'
                    Rule = "Cloud Resources must have a XXX tag set"
                    ResourceGroup = $resourceGroup.ResourceGroupName
                    ResourceName = $resource.Name
                    ResourceId    = $resource.ResourceId
                    RGxxxTag      = "no RG xxx tag neither" 
                    Mode          = $investigateMode
                    AppliTag      = $applicationTag
                    AppliSponsor  = $ApplicationSponsor
                    AppliOwner    = $ApplicationOwner
                    AppliBilling  = $ApplicationBilling
                    ResourceType  = $resource.resourceType
                    EnvironmentType = $envTypeTag
                }
                $global:anomalies += $anomaly
                return
            }
            
            write-host("----------------")
            return
        }
        else {
            write-output("not empty and parsable xxx tag found!")
            write-output ("XXX tag : " + $XXXTag)
        }
    }
    else {

        if (($RGXXXTag -ne $null) -and $RGXXXTag) {
            write-output ("but its RG has a xxx tag:")
            write-output $RGXXXTag
            $anomaly = @{
                Policy="no-XXX-tag"
                Subscription = $subscriptionName
                DetectedValue = 'XXX tag missing'
                Rule = "Cloud Resources must have a XXX tag set"
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceName = $resource.Name
                ResourceId    = $resource.ResourceId
                RGxxxTag      = $RGXXXTag
                Mode          = $createMode
                AppliTag      = $applicationTag
                AppliSponsor  = $ApplicationSponsor
                AppliOwner    = $ApplicationOwner
                AppliBilling  = $ApplicationBilling
                ResourceType  = $resource.resourceType
                EnvironmentType = $envTypeTag
            }
            $global:anomalies += $anomaly
            return
        }
        else {
            write-output ("and its RG has no xxx tag neither")
            $anomaly = @{
                Policy="no-XXX-tag"
                Subscription = $subscriptionName
                DetectedValue = 'XXX tag missing'
                Rule = "Cloud Resources must have a XXX tag set"
                ResourceGroup = $resourceGroup.ResourceGroupName
                ResourceName = $resource.Name
                ResourceId    = $resource.ResourceId
                RGxxxTag      = "no RG xxx tag neither" 
                Mode          = $investigateMode
                AppliTag      = $applicationTag
                AppliSponsor  = $ApplicationSponsor
                AppliOwner    = $ApplicationOwner
                AppliBilling  = $ApplicationBilling
                ResourceType  = $resource.resourceType
                EnvironmentType = $envTypeTag
            }
            $global:anomalies += $anomaly
            return
        }
        write-host("----------------")
        return
    }

    $isCorrect = $true
    #checking value of the json
    #the A value cannot be greater than 4
    if ($oxxxTag.A -gt 4) {
        Write-host ("A attribute out of range")
        $isCorrect = $false
        $anomaly = @{
            Policy ="XXX-tag-out-of-range"
            Subscription = $subscriptionName
            Rule = "A attribute is out-of-range"
            DetectedValue = 'A:' + $oxxxTag.A
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId    = $resource.ResourceId
            WrongTag      = $XXXTag
            Mode          = $formatMode
            AppliTag      = $applicationTag
            AppliSponsor  = $ApplicationSponsor
            AppliOwner    = $ApplicationOwner
            AppliBilling  = $ApplicationBilling
            ResourceType  = $resource.resourceType
            EnvironmentType = $envTypeTag
        }
        $global:anomalies += $anomaly
    }

    #checking another attribute that has to be integer
    if ($oxxxTag.B -isnot [int]) {
        Write-host ("B attribute format wrong")
        $isCorrect = $false
        $anomaly = @{
            Policy ="XXX-tag-not-well-formed"
            Subscription = $subscriptionName
            Rule = "XXX tag not well formed"
            DetectedValue = 'B:' + $oxxxTag.B
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId    = $resource.ResourceId
            WrongTag      = $XXXTag
            Mode          = $formatMode
            AppliTag      = $applicationTag
            AppliSponsor  = $ApplicationSponsor
            AppliOwner    = $ApplicationOwner
            AppliBilling  = $ApplicationBilling
            ResourceType  = $resource.resourceType
            EnvironmentType = $envTypeTag
        }
        $global:anomalies += $anomaly
    }

    #check for the C attribute that cannot be null
    if (!$oxxxTag.C -or (!$oxxxTag.C -eq $null)) {
        $anomaly = @{
            Ploicy="tag-missing-attribute"
            Subscription = $subscriptionName
            Rule ="XXX tag must have an xxxOps attribute"
            DetectedValue = 'C attribute is missing'
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId    = $resource.ResourceId
            WrongTag      = $XXXTag
            Mode          = $formatMode
            AppliTag      = $applicationTag
            AppliSponsor  = $ApplicationSponsor
            AppliOwner    = $ApplicationOwner
            AppliBilling  = $ApplicationBilling
            ResourceType  = $resource.resourceType
            EnvironmentType = $envTypeTag
        }
        $global:anomalies += $anomaly
    }

#more complex checks
    #the D attribute cannot be 1 for App Gateways
    if ($resource.resourceType -like "*applicationGateways*" -and $oxxxTag.D -eq 1) {
        Write-host ("App Gateway not well qualified")
        $isCorrect = $false
        $anomaly = @{
            Policy ="tag-incoherent"
            Subscription = $subscriptionName
            DetectedValue = "App Gateway not well qualified (D attribute of XXX tag)"
            Rule="Attributes of the XXX tag must be coherent with the asset configuration"
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId    = $resource.ResourceId
            WrongTag      = $XXXTag
            Mode          = $formatMode
            AppliTag      = $applicationTag
            AppliSponsor  = $ApplicationSponsor
            AppliOwner    = $ApplicationOwner
            AppliBilling  = $ApplicationBilling
            ResourceType  = $resource.resourceType
            EnvironmentType = $envTypeTag
        }
        $global:anomalies += $anomaly
    }

    #The attribute E caanot be 1 for a specific environment
    if($envTypeTag -notlike "*PRD*" -and $oxxxTag.E -eq 1){
        Write-host ("Tag EnvironmentType value is not PRD but E is set to 1")
        $isCorrect = $false
        $anomaly = @{
            Policy ="tag-incoherent"
            Rule="Attributes of the XXX tag must be coherent with the asset configuration"
            Subscription = $subscriptionName
            DetectedValue = "Tag EnvironmentType value is not PRD but E is set to 1"
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId    = $resource.ResourceId
            WrongTag      = $XXXTag
            Mode          = $formatMode
            AppliTag      = $applicationTag
            AppliSponsor  = $ApplicationSponsor
            AppliOwner    = $ApplicationOwner
            AppliBilling  = $ApplicationBilling
            ResourceType  = $resource.resourceType
            EnvironmentType = $envTypeTag
        }
        $global:anomalies += $anomaly

    }


    if (! $isCorrect) {
        Write-host "XXX Tag:"
        Write-host ($XXXTag)
        Write-host ("object xxx tag:")
        Write-Output $oxxxTag
    }
    else {
        write-host ( "item " + $index + " is correct")
        Write-host "XXX Tag:"
        Write-host ($XXXTag)
        $XXXTag = $oxxxTag | ConvertTo-JSON -Compress
        if ($type -like "*RG*") {
            $resourceType = "resourceGroup"
        }
        else {
            $resourceType = $resource.resourceType
        }
        #all checks passed getting a correct item for a line in the correct resources .csv
        $correctTag = @{
            Subscription = $subscriptionName
            ResourceGroup = $resourceGroup.ResourceGroupName
            ResourceName = $resource.Name
            ResourceId   = $resource.resourceId
            ResourceType = $resourceType
            CorrectTag   = $XXXTag
            AppliTag     = $applicationTag
            AppliSponsor = $ApplicationSponsor
            AppliOwner   = $ApplicationOwner
            AppliBilling = $ApplicationBilling
            EnvironmentType = $envTypeTag
        }
        
        $global:correct += $correctTag
        #Write-Output $global:correct
    }
    write-host("----------------")
    
    #write-output ($anomalies | ConvertTo-Json)
}

############################## End of Script Functions ############################################


############################## Main Script part 2 ############################################

Write-Host ''
$index = 0
$global:anomalies = @()
$global:correct = @()


$ResourceGroups = Get-AzResourceGroup



ForEach ($RG in $ResourceGroups) {
    $index ++
    #exceptions
    
    #Trick to not process anomalies linked to a specific RG
    if ($RG.resourceGroupName -like "*databricks*") {
        continue
    }

    try {
        write-output ( "processing item " + $index)

        $splitResourceId = $RG.ResourceId -Split "/resourceGroups/"
        Write-Output $splitResourceId[1]
        if ($splitResourceId[1].IndexOf('/') -lt 0) {
            write-output("this entry is for a resource group. Processing this entry...")
            checkItem "RG" (Get-AzResourceGroup -Id $RG.ResourceId) $RG $environmentType
            write-output("----------------")
        }
        
        $Resources = Get-AzResource -ResourceGroupName $RG.ResourceGroupName 

        #trick to exclude anomalies linked to specific resource types
        foreach ($res in $Resources) {
            
            if ($res.resourceType -like "*networkWatchers/flowLogs*") {
                continue
            }
            if ($res.resourceType -like "*Microsoft.Sql/virtualClusters*") {
                continue
            }
            
            if ($res.resourceId -like "*microsoft.insights*") {
                continue
            }
            if ($res.resourceId -like "*sendgrid*") {
                continue
            }
 
            $index ++
            write-output ( "procesing item " + $index)
            write-output("this entry is for a resource. Processing this entry...")
            checkItem "resource" $res $RG $environmentType
            write-output("----------------")
        } 
    }
    catch {
        write-output ("error processing a resource....")
        write-output $index
        write-output $item.ResourceId
        write-output $_
    }
}


if ($global:anomalies.Count -gt 0) {
    $sortedArray = $global:anomalies | Sort-Object { $_.DetectedValue }
    $(Foreach ($x in $sortedArray) {
            New-object psobject -Property $x
        }) | Select-Object "Policy", "Subscription","ResourceGroup", "ResourceName", "Rule", "DetectedValue", "ResourceType", "ResourceId", "Mode", "RGxxxTag", "WrongTag", "AppliTag", "AppliSponsor", "AppliOwner", "AppliBilling", "EnvironmentType" | Export-Csv ("fix--anomalies-" + $contextName + ".csv") -Delimiter ";" -NoTypeInformation
}
else {
    Write-Output("No anomaly was found!")
}

if ($global:correct.Count -gt 0) {
    $(Foreach ($x in $global:correct) {
            New-object psobject -Property $x
        }) | Select-Object "Subscription","ResourceGroup", "ResourceName", "ResourceType", "ResourceId", "CorrectTag", "AppliTag", "AppliSponsor", "AppliOwner", "AppliBilling", "EnvironmentType" | Export-Csv ("-correctTags-" + $contextName + ".csv") -Delimiter ";" -NoTypeInformation
}
else {
    Write-Output("Correct Tags file empty!")
}
############################## End of Main Script part 2 ############################################