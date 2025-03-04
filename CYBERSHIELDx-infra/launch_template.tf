resource "aws_launch_template" "app_template" {
  name          = "backend-launch-template"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  user_data = base64encode(file("${path.module}/userdata.sh"))

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [var.ec2_security_group]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "backend-instance"
    }
  }
}
