# Project overview

This is a simple terraform configuration to deploy EKS cluster with a single node to an existing VPC.  
All of the configuration is defined in main.tf. It will also create s3 bucket and a service account in kubernetes so your pods can access the created s3 account.

### How to use this code

1. use the dockerfile provided within the solution to build the image: `docker build -t my-image .` and run it while mounting this code inside the container: `docker run -it -v $localPath:/workspace my-image`. 
2. perform `terraform init` followed by `apply` and set terraform variables (access_key and secret_key) that will be used by terraform to authenticate:

```
terraform apply -var="access_key=xxx" -var="secret_key=yyy"
```

or create a variables file (which would jsut be a tfvars file with variables defined in it) and point terraform to that file:

```
terraform apply -var-file="testing.tfvars"
```

3. pull kubernetes credentials with aws-cli included in the docker image (or use `amazon/aws-cli` docker image for that, or your local aws-cli) with something like:

```
aws configure
aws eks --region us-east-2 update-kubeconfig --name opsfleet-eks
```

4. create a kubernetes deployment using a regular deployment definition, but specify the service account called `my-serviceaccount` for the setup to work. the deployment has to live in the default namespace:

```
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    run: myapp
  name: myapp
  namespace: default
spec:
  ...
  template:
    ...
    spec:
      serviceAccountName: my-serviceaccount 
      containers:
      - image: amazon/aws-cli
        name: aws-cli
```

5. once your pod is up you can exec into the pod and test connection to the storage account:

```
aws s3 ls s3://opsfleet-eks-pod-assume-bucket
```