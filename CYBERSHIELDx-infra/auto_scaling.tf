resource "aws_autoscaling_group" "app_asg" {
  name                = "backend-autoscaling-group"
  min_size            = 2
  max_size            = 5
  desired_capacity    = 2
  vpc_zone_identifier = var.subnet_ids
  launch_template {
    id      = aws_launch_template.app_template.id
    version = "$Latest"
  }
}
