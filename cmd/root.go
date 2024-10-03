/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"
)

const (
	probeTCPtimeout = 1 * time.Second
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nfqueue",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: doStuff,
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nfqueue.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func doStuff(cmd *cobra.Command, args []string) error {
	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// use protobuf to improve performance
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// override the internal apiserver endpoint to avoid
	// waiting for kube-proxy to install the services rules.
	// If the endpoint is not reachable, fallback the internal endpoint
	controlPlaneEndpoint := os.Getenv("CONTROL_PLANE_ENDPOINT")
	if controlPlaneEndpoint != "" {
		// check that the apiserver is reachable before continue
		// to fail fast and avoid waiting until the client operations timeout
		var ok bool
		for i := 0; i < 5; i++ {
			ok = probeTCP(controlPlaneEndpoint, probeTCPtimeout)
			if ok {
				config.Host = "https://" + controlPlaneEndpoint
				break
			}
			klog.Infof("apiserver not reachable, attempt %d ... retrying", i)
			time.Sleep(time.Second * time.Duration(i))
		}
	}
	// create the clientset to connect the apiserver
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	klog.Infof("connected to apiserver: %s", config.Host)

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	go func() {
		select {
		case <-signalCh:
			klog.Infof("Exiting: received signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informersFactory.Core().V1().Nodes()
	// nodeLister := nodeInformer.Lister()

	// obtain the host and pod ip addresses
	// if both ips are different we are not using the host network
	hostIP, podIP := os.Getenv("HOST_IP"), os.Getenv("POD_IP")
	klog.Infof("hostIP = %s\npodIP = %s\n", hostIP, podIP)
	if hostIP != podIP {
		klog.Warningf(
			"hostIP(= %q) != podIP(= %q) but must be running with host network: ",
			hostIP, podIP,
		)
	}

	// network policies

	nodeName := os.Getenv("NODE_NAME")

	cfg := networkpolicy.Config{
		FailOpen: true,
		QueueID:  100,
		NodeName: nodeName,
	}

	networkPolicyController, err := networkpolicy.NewController(
		clientset,
		informersFactory.Networking().V1().NetworkPolicies(),
		informersFactory.Core().V1().Namespaces(),
		informersFactory.Core().V1().Pods(),
		nodeInformer,
		nil,
		nil,
		nil,
		cfg)
	if err != nil {
		klog.Infof("Error creating network policy controller: %v, skipping network policies", err)
	} else {
		go func() {
			_ = networkPolicyController.Run(ctx)
		}()
	}

	// main control loop
	informersFactory.Start(ctx.Done())
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		// rate limit
		select {
		case <-ctx.Done():
			// grace period to cleanup resources
			time.Sleep(1 * time.Second)
			return nil
		case <-ticker.C:
		}
	}
}

// Modified from agnhost connect command in k/k
// https://github.com/kubernetes/kubernetes/blob/c241a237f9a635286c76c20d07b103a663b1cfa4/test/images/agnhost/connect/connect.go#L66
func probeTCP(address string, timeout time.Duration) bool {
	klog.Infof("probe TCP address %s", address)
	if _, err := net.ResolveTCPAddr("tcp", address); err != nil {
		klog.Warningf("DNS problem %s: %v", address, err)
		return false
	}

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err == nil {
		conn.Close()
		return true
	}
	if opErr, ok := err.(*net.OpError); ok {
		if opErr.Timeout() {
			klog.Warningf("TIMEOUT %s", address)
		} else if syscallErr, ok := opErr.Err.(*os.SyscallError); ok {
			if syscallErr.Err == syscall.ECONNREFUSED {
				klog.Warningf("REFUSED %s", address)
			}
		}
		return false
	}

	klog.Warningf("OTHER %s: %v", address, err)
	return false
}
