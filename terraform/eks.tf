module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.0.0"

  cluster_name    = "proshop-eks"
  cluster_version = "1.31"

  cluster_endpoint_public_access = true

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    instance_types = ["t3.medium"]
  }

  eks_managed_node_groups = {
    nodes = {
      min_size     = 1
      max_size     = 3
      desired_size = 2

      capacity_type = "SPOT"
    }
  }

  # This allows your local computer to talk to the cluster easily
  enable_cluster_creator_admin_permissions = true

  tags = {
    Environment = "dev"
    Application = "proshop"
  }
}