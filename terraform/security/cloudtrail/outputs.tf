output "cloudtrail_name" {
  value = aws_cloudtrail.aegiscloud.name
}

output "cloudtrail_bucket" {
  value = aws_s3_bucket.cloudtrail_logs.bucket
}