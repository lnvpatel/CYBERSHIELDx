output "alb_dns" {
  description = "Load Balancer URL"
  value       = aws_lb.app_alb.dns_name
}

output "asg_name" {
  description = "Auto Scaling Group Name"
  value       = aws_autoscaling_group.app_asg.name
}
