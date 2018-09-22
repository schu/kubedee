Example Terraform configuration to setup and run a kubedee cluster on a
Hetzner Cloud VM instance.

Copy `terraform.tfvars.example` to `terraform.tfvars`, add your token
and sshkey name and run terraform:

```
terraform init
terraform apply
```

When applied successfully, the `admin.kubeconfig` for the cluster can
be found in this directory.
