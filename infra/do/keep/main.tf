terraform {
  required_providers {
    digitalocean = { source = "digitalocean/digitalocean", version = "~> 2.0" }
  }
}
provider "digitalocean" { token = var.do_token }

variable "do_token" {
  type      = string
  sensitive = true
}
variable "region" {
  type    = string
  default = "nyc3"
}
variable "vpc_cidr" {
  type    = string
  default = "10.88.0.0/16"
}

# PERSISTENT identity — created once, never destroyed by `lab down`.
resource "digitalocean_vpc" "lab" {
  name     = "minilab2-vpc"
  region   = var.region
  ip_range = var.vpc_cidr
  lifecycle { prevent_destroy = true }
}

resource "digitalocean_reserved_ip" "vpn" {
  region = var.region
  lifecycle { prevent_destroy = true }
}

output "vpc_id" { value = digitalocean_vpc.lab.id }
output "reserved_ip" { value = digitalocean_reserved_ip.vpn.ip_address }
