module github.com/vaultguard/k8s-controller

go 1.22

require (
	github.com/vaultguard/core v0.0.0
	sigs.k8s.io/controller-runtime v0.18.3
	k8s.io/apimachinery v0.30.1
	k8s.io/client-go v0.30.1
	k8s.io/api v0.30.1
)

replace github.com/vaultguard/core => ../core
