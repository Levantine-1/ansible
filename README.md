# Ansible Playbooks Repository

This repository contains a collection of Ansible playbooks for managing and configuring servers. The playbooks are organized into different categories based on their purpose and functionality.

## Playbook Categories

### OS Configurations (`os_configs`)

Playbooks in this category are responsible for configuring the operating system on the hosts. This includes tasks such as installing and updating basic packages, setting up specific software like Firefox, and deploying SSL certificates. These playbooks ensure that the hosts are set up with the necessary software and configurations to run the services they are intended for.

Run the app.yml to cover all the playbooks in this category.

### Applications (`applications`)

The `applications` category contains playbooks for setting up and configuring specific applications on the hosts. This could include tasks such as installing and configuring web servers, databases, and other application-specific software. These playbooks are used to set up the specific services that the hosts are intended to run.

# Note:
### SSL Certificates:
The SSL certificates are stored in hashicorp vault so the playbook will need access to retrieve the certificates from vault and deploy them to the hosts.