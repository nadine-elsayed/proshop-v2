# Create the SNS Topic for Alerts
resource "aws_sns_topic" "proshop_alerts" {
  name = "proshop-service-alerts"
}

# Add your email address to receive the alerts
resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = aws_sns_topic.proshop_alerts.arn
  protocol  = "email"
  endpoint  = "your-email@example.com" # <--- UPDATE THIS
}

# CloudWatch Alarm for Cluster Health (Node CPU)
resource "aws_cloudwatch_metric_alarm" "node_cpu_high" {
  alarm_name          = "proshop-node-cpu-high"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "node_cpu_utilization" # Requires CloudWatch Container Insights
  namespace           = "ContainerInsights"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors EKS node CPU utilization"
  alarm_actions       = [aws_sns_topic.proshop_alerts.arn]

  dimensions = {
    ClusterName = "proshop-eks"
  }
}