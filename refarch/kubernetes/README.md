# Azure Kubernetes Reference Architecture

This reference architecture is ideal for enterprises that need to proxy one or more applications that do not use Windows Integrated Authentication and already use Azure Kubernetes Service. This reference architecture is a 100% infrastructure as code model.

## High Availability

The default deployment is highly available across 3 fault domains in a single data center. The entire deployment can be zone redundant across 3 data centers in a region, but this is completely dependent on your prerequisites being zone redundant. To be zone redundant:

* The AKS management and node pool must be [zone redundant](https://docs.microsoft.com/en-us/azure/aks/availability-zones).
* The Application Gateway used by the Azure Kubernetes Application Gateway Ingress Controller must be zone redundant.
* The Kubernetes Storage Class specified in the configuration of this deployment must be zone redundant. 
* There must be sufficient space in the cluster for the Kubernetes scheduler to achieve max spread across zones.

If you need redundancy across multiple Azure regions, deploy this Chart to multiple regions. The regions can be run behind shared host names using Azure Traffic Manager.

## Networking Options

The reference architecture can be deployed to the public internet with an Azure Application Gateway (public mode). An internal corporate network only option (private mode) will be added in a future revision.

Public mode uses your cluster's Azure Application Gateway Ingress Controller to expose an HTTPS endpoint on a public IP on the internet. OAKProxy should be configured to listen on an HTTP endpoint.

# Prerequisites

* An [Azure Kubernetes Service](https://docs.microsoft.com/en-us/azure/aks/) cluster with [Azure CNI](https://docs.microsoft.com/en-us/azure/aks/configure-azure-cni) and 3 or more nodes.
* Network access to the applications that will be proxied (i.e. they are either in the same cluster or routable via the Azure CNI attached VNet).
* [Azure Kubernetes Application Gateway Ingress Controller](https://github.com/Azure/application-gateway-kubernetes-ingress) must be installed in the cluster.
* A configured Kubernetes Storage Class for shared access that meets or exceeds the availability level of your deployment (e.g. Azure Files ZRS).
* A certificate trusted by your clients or publicly for all of the hostnames this deployment will handle must be stored in a Kubernetes Secret of type: `kubernetes.io/tls`.
* A DNS zone where CNAME records for each proxied application can be created.
* An OAKProxy configuration file.
* An OpenID Connect identity provider (Azure AD is recommended).

## Storage Class

For a zone redundant deployment an example Storage class using Azure Files follows:

```yaml
kind: StorageClass
apiVersion: storage.k8s.io/v1
metadata:
  name: azurefileszrs
provisioner: kubernetes.io/azure-file
parameters:
  skuName: Standard_ZRS
```

See the [AKS documentation](https://docs.microsoft.com/en-us/azure/aks/azure-files-dynamic-pv) for more information about creating a storage class in an RBAC-enabled cluster.

## Key Storage Certificate

A self-signed certificate can be created for encrypting the session keys.

```bash
will@surface:~$ openssl genrsa 2048 > keystorecert.priv.pem
will@surface:~$ openssl req -x509 -new -key keystorecert.priv.pem -out keystorecert.pub.pem
will@surface:~$ openssl pkcs12 -export -in keystorecert.pub.pem -inkey keystorecert.priv.pem -out keystorecert.pfx
```

The password for the pfx file should be stored in a Kubernetes secret with a key: `password`.

## OAKProxy Configuration

OAKProxy configuration is extensively documented with examples in the [OAKProxy documentation](https://github.com/wpbrown/oakproxy/blob/master/docs/README.md).

For this reference architecture _do not_ specify the `Server.KeyManagement` section in your configuration file. This is automatically configured on the container to use a persistent volume and certificate.

A minimal template for a public mode deployment follows:
```yaml
Server:
  Urls: 'http://*:8080'
  UseAzureApplicationGateway: true

IdentityProviders:
- # Your Identity Provider

Authenticators:
- # Your authenticators. For this reference architecture, at least 
  # one Kerberos authenticator would be expected.

Applications:
- # Your applications.
```

# Deployment

Once all the prerequisites are in place deployment is straightforward with Helm. In the examples below the following artifacts exist from the prerequisite setup:

Name | Type | Description
--- | --- | ---
`azurefileszrs` | Kubernetes Storage Class | The name of your shared storage with sufficient redundancy for your deployment.
`oakproxykeystorecert` | Kubernetes Secret | An opaque secret with a key `password`. This is the password to the pfx supplied in `keyStorage.certificate`
`keystorecert.pfx` | File | A PKCS12 self-signed certificate (binary file) for encrypted the stored session keys.
`oakproxy.yml` | File | Your OAKProxy configuration file.
`oakproxyhttps` | Kubernetes Secret | A `kubernetes.io/tls` secret with the certificate for the public hostname.
`billingapp.contoso.com` | DNS Record | A CNAME record that maps to the Azure Application Gateway.
`aks-agw-pip` | Azure Public IP | The IP assigned to the Azure Application Gateway.

1. You can either create a YAML file with your settings or directly configure the deployment on the CLI as shown below:
   ```bash
   will@surface:~$ helm repo add oakproxy https://github.com/wpbrown/oakproxy/releases/download/helm
   will@surface:~$ helm repo update
   will@surface:~$ helm install oakproxy/oakproxy \
     --set keyStorage.storageClass=azurefileszrs \
     --set keyStorage.secretName=oakproxykeystorecert \
     --set-file keyStorage.certificate=<(base64 -w0 keystorecert.pfx) \
     --set-file oakproxyConfiguration=oakproxy.yml \
     --set ingress.hosts[0]=billingapp.contoso.com \
     --set ingress.tls[0].secretName=oakproxyhttps \
     --set ingress.tls[0].hosts[0]=billingapp.contoso.com
   ```

2. Get the DNS FQDN for the Application Gateway that is used by your AKS cluster's ingress controller.
   ```bash
   will@surface:~$ az network public-ip show -g aks-managed-rg -n aks-agw-pip --query 'dnsSettings.fqdn'
   ```

   Update the public CNAME records for your proxied application hostnames to point to the FQDN retrieved above.

Installation is complete. Test the application. In this example the application would be live at `https://billingapp.contoso.com/`.