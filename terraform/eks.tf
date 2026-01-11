module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.0.0"

  cluster_name    = "proshop-eks"
  cluster_version = "1.31"

  cluster_endpoint_public_access = true

  # Networking
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  # IRSA (IAM Roles for Service Accounts) 
  # This is the "correct" way to handle ALB controller permissions
  enable_irsa = true 

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

      # FIX: Attaching AdministratorAccess to the Nodes
      # This bypasses the "DescribeLoadBalancers" AccessDenied error
      iam_role_additional_policies = {
        AmazonEKSWorkerNodePolicy          = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
        AmazonEKS_CNI_Policy               = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
        AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        LBControllerPolicy                 = "arn:aws:iam::aws:policy/AdministratorAccess"
      }
    }
  }

  # This allows your local computer to talk to the cluster easily
  enable_cluster_creator_admin_permissions = true

  tags = {
    Environment = "dev"
    Application = "proshop"
  }
}