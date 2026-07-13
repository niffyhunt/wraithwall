resource "docker_container" "app" {
  image = docker_image.wraithwall.name
  name  = "wraithwall-app"
  ports { internal = 8000; external = 8000 }
  env = [
    "DATABASE_URL=postgresql://${var.db_user}:${var.db_pass}@${docker_container.postgres.name}:5432/${var.db_name}",
    "REDIS_URL=redis://${docker_container.redis.name}:6379/0",
    "SECRET_KEY=${var.secret_key}",
  ]
}
resource "docker_container" "redis" {
  image = "redis:7-alpine"; name = "wraithwall-redis"
}
resource "docker_container" "postgres" {
  image = "postgres:16-alpine"; name = "wraithwall-postgres"
  env = ["POSTGRES_USER=${var.db_user}", "POSTGRES_PASSWORD=${var.db_pass}", "POSTGRES_DB=${var.db_name}"]
}
variable "db_user" { default = "wraithwall" }
variable "db_pass" { sensitive = true }
variable "db_name" { default = "wraithwall" }
variable "secret_key" { sensitive = true }
