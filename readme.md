# ProShop EKS: End-to-End Cloud-Native Pipeline

This repository contains a containerized MERN (MongoDB, Express, React, Node.js) application orchestrated via **Kubernetes (EKS)** and provisioned with **Terraform**. It implements a full CI/CD lifecycle using **GitHub Actions** and includes a production-grade observability stack.

## 🏗️ Architecture Overview
* **Infrastructure:** AWS EKS (Elastic Kubernetes Service) via Terraform.
* **CI/CD:** GitHub Actions for automated Docker builds and deployment.
* **Database:** MongoDB Atlas (External DBaaS).
* **Monitoring:** Prometheus & Grafana via Helm.
* **Resilience:** Horizontal Pod Autoscaling and self-healing deployments.

---

## 🚀 Deployment Guide

### 1. Infrastructure Provisioning
Navigate to the terraform directory and initialize the provider:
```bash
cd terraform
terraform init
terraform apply --auto-approve

```

### 2. Configure Kubectl

Update your local kubeconfig to point to the new EKS cluster:

```bash
aws eks update-kubeconfig --region <your-region> --name <cluster-name>

```

### 3. CI/CD & Secrets

Ensure the following secrets are configured in GitHub Actions:

* `DOCKER_USERNAME` / `DOCKER_PASSWORD`
* `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
* `MONGO_URI` (Atlas Connection String)

Push to the `main` branch to trigger the automated build and deployment.

### 4. Observability Setup

Install the Prometheus stack using Helm:

```bash
helm repo add prometheus-community [https://prometheus-community.github.io/helm-charts](https://prometheus-community.github.io/helm-charts)
helm install prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

```

Access Grafana:

```bash
kubectl port-forward deployment/prometheus-stack-grafana 3000:3000 -n monitoring
# Default Login: admin / prom-operator

```

---

### Resource Cleanup

To avoid unnecessary AWS costs, destroy the infrastructure when not in use:

```bash
terraform destroy --auto-approve

```

---
