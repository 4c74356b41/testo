variable "prefix" {
  type = string
  default = "opsfleet"
}
variable "access_key" {
  type = string
  default = ""
}
variable "secret_key" {
  type = string
  default = ""
}
variable "vpc_id" {
    type = string
    default = "vpc-08dfdb259c51c24ca"
}

provider "aws" {
  region     = "us-east-2"
  access_key = var.access_key
  secret_key = var.secret_key
}
data "aws_subnet_ids" "vpc-subnets" {
  vpc_id = var.vpc_id
}

resource "aws_iam_role" "eks-assume-role" {
  name = "${var.prefix}-eks-assume-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks-assume-role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks-assume-role.name
}

resource "aws_eks_cluster" "eks" {
  name     = "${var.prefix}-eks"
  role_arn = aws_iam_role.eks-assume-role.arn

  vpc_config {
    subnet_ids = data.aws_subnet_ids.vpc-subnets.ids
    security_group_ids = [aws_security_group.eks-cluster-security-group.id]
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.AmazonEKSServicePolicy
  ]
}

resource "aws_security_group" "eks-cluster-security-group" {
  name        = "${var.prefix}-eks-security-group"
  description = "Cluster communication with worker nodes"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "eks-cluster-ingress-443" {
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Allow workstation to communicate with the cluster API Server"
  from_port         = 443
  protocol          = "tcp"
  security_group_id = aws_security_group.eks-cluster-security-group.id
  to_port           = 443
  type              = "ingress"
}

resource "aws_iam_openid_connect_provider" "pod-assume-role" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"] # https://github.com/terraform-providers/terraform-provider-aws/issues/10104
  url             = aws_eks_cluster.eks.identity.0.oidc.0.issuer
}

data "aws_iam_policy_document" "eks_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.pod-assume-role.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:default:my-serviceaccount"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.pod-assume-role.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "pod-assume-role" {
  assume_role_policy = data.aws_iam_policy_document.eks_assume_role_policy.json
  name               = "${var.prefix}-pod-assume-role"
}

resource "aws_iam_policy_attachment" "pod-role-attachment" {
  name       = "${var.prefix}-pod-assume-role-attachment"
  roles      = [ "${aws_iam_role.pod-assume-role.name}" ]
  policy_arn = aws_iam_policy.pod-assume-policy.arn
}

resource "aws_iam_policy" "pod-assume-policy" {
  name        = "${var.prefix}-pod-assume-policy"
  description = "S3 access policy"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "${aws_s3_bucket.bucket.arn}"
        }
    ]
}
POLICY
}

resource "aws_iam_role" "node-role" {
  name = "${var.prefix}-eks-node-group-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node-role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node-role.name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node-role.name
}

resource "aws_eks_node_group" "eks-node-group" {
  cluster_name    = aws_eks_cluster.eks.name
  node_group_name = "${var.prefix}-first"
  node_role_arn   = aws_iam_role.node-role.arn
  subnet_ids      = data.aws_subnet_ids.vpc-subnets.ids

  scaling_config {
    desired_size = 1
    max_size     = 1
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
  ]
}

resource "aws_s3_bucket" "bucket" {
  bucket = "${var.prefix}-eks-pod-assume-bucket"
}

data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.eks.name
  depends_on = [
    aws_eks_cluster.eks
  ]
}

data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks.name
  depends_on = [
    aws_eks_cluster.eks
  ]
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.eks.token
  load_config_file       = false
}

resource "kubernetes_service_account" "eks" {
  metadata {
    name = "my-serviceaccount"
    namespace = "default"
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.pod-assume-role.arn 
    }
  }
  automount_service_account_token = true # https://github.com/terraform-providers/terraform-provider-kubernetes/issues/678
}
