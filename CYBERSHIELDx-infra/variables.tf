variable "aws_region" {
  description = "AWS region for resources"
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t3.micro"
}

variable "ami_id" {
  description = "Ubuntu AMI ID (Ensure it's for your region)"
  default     = "ami-0fc5d935ebf8bc3bc"  # Ubuntu 22.04 LTS (x86_64)
}

variable "key_name" {
  description = "Name of the SSH key pair"
  default     = "my-key"
}

variable "vpc_id" {
  description = "VPC ID where resources will be deployed"
}

variable "subnet_ids" {
  description = "List of subnet IDs for ALB and Auto Scaling Group"
  type        = list(string)
}

variable "alb_security_group" {
  description = "Security group ID for ALB"
}

variable "ec2_security_group" {
  description = "Security group ID for EC2 instances"
}
