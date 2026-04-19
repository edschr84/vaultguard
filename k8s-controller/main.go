package main

import (
	"flag"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	vaultguardv1alpha1 "github.com/vaultguard/k8s-controller/api/v1alpha1"
	"github.com/vaultguard/k8s-controller/controllers"
	vgwebhook "github.com/vaultguard/k8s-controller/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vaultguardv1alpha1.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		probeAddr            string
		leaderElect          bool
		controllerNamespace  string
		initImage            string
		webhookCertDir       string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Metrics endpoint address")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Health probe endpoint address")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election for HA deployments")
	flag.StringVar(&controllerNamespace, "controller-namespace", "vaultguard-system", "Namespace where credential secrets live")
	flag.StringVar(&initImage, "init-image", vgwebhook.DefaultInitImage, "Init container image for webhook injection")
	flag.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "Directory containing TLS cert and key for the webhook server")
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseDevMode(os.Getenv("DEV") == "true")))
	logger := ctrl.Log.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "vaultguard-controller-leader",
		WebhookServer: webhook.NewServer(webhook.Options{
			CertDir: webhookCertDir,
			Port:    9443,
		}),
	})
	if err != nil {
		logger.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := (&controllers.VaultSecretReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		ControllerNamespace: controllerNamespace,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "unable to create VaultSecret controller")
		os.Exit(1)
	}

	// Register mutating webhook for pods
	mgr.GetWebhookServer().Register("/mutate-v1-pod", &webhook.Admission{
		Handler: &vgwebhook.PodMutator{
			Client:    mgr.GetClient(),
			Dec:       admission.NewDecoder(scheme),
			InitImage: initImage,
		},
	})

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	logger.Info("starting manager",
		"metrics", metricsAddr,
		"probes", probeAddr,
		"leaderElect", leaderElect,
		"controllerNamespace", controllerNamespace,
	)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "problem running manager")
		os.Exit(1)
	}
}
