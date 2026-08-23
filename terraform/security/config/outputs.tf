output "config_bucket" {
  value = aws_s3_bucket.config_bucket.bucket
}

output "config_recorder" {
  value = aws_config_configuration_recorder.aegiscloud.name
}