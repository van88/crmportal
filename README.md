# CrmPortal
Dynamics CRM custom MVC portal starter project.

## Why?
Although powerful, the out of the box Dynamics Portal or AdxStudio customisation flexibility is quite limited.
For a complex Dynamics CRM customer portal, a custom built ASP MVC web site might be a better choice. 
This project is intended to be a starter template with a custom Asp Identity user store implemented.
User credentials are stored in Contact entity.
User roles, logins, claims are stored in appropriate custom entities.

## How to use
1. Import CrmSolution\CrmPortal_1_0_0_0.zip into your Dynamics 365 CRM instance. 
Dynamics 365 CRM version 8.2 or later is required.

2. Create a connectionstrings.secrets.config file in CrmPortal folder or edit the web.config file with the following:
 ```<language>
  <connectionStrings>
    <clear/>
    <add name="CrmConnection" connectionString="AuthType=Office365; Server=https://*****.api.crm6.dynamics.com; Username=*****; Password=*****;" />
   </connectionStrings>
```
Note: in this example the connection string is for Office 365, for on-premise or IFD see examples in the web.config file
