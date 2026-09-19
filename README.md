# Advanced-Api-Access-control-in-cloud-native-environment
In this project we compares security approaches in controlled and shared environments to improve API protection, authentication, and authorization.

## Motivation:
Modern cloud-native applications rely heavily on APIs and microservices, making API access control a critical security challenge. This thesis investigates advanced API access control in two environments:

1- Controlled environments: Kubernetes Network Policies and service meshes such as Istio provide fine-grained network security, mTLS, and zero-trust access control.

2- Shared/uncontrolled environments: Identity Providers (IdPs) using OAuth 2.0 provide centralized authentication and authorization through access tokens, SSO, MFA, and conditional access.

## Method:

### 1- Controlled Environment:

![Control Scenrio](full.png)


I set up an Istio service mesh within the Kubernetes cluster to control communication between the services.
I configured the client to access /server1 through HTTP while restricting access to /server2.
Istio authorization policies were used to allow the permitted request and block the unauthorized request.
This allowed me to verify that access between the services was controlled according to the defined policies.

![ControlledEnvironment](ControlledEnvironment.png)


### 2- Uncontrolled Environment
