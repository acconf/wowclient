package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/acconf/wowclient/internal/wclient"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceAppName = "WireGuardonWsTunnelForWindows"

type myService struct {
	params *wclient.StartupArgs
	client *wclient.WoWClient
}

func (s *myService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	if err := s.startLogic(); err != nil {
		s.stopLogic()
		changes <- svc.Status{State: svc.Stopped}
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		req := <-r
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			s.stopLogic()
			changes <- svc.Status{State: svc.Stopped}
			return
		default:
			return
		}
	}
}

func (s *myService) startLogic() error {
	var err error
	s.client, err = wclient.Startup(s.params)
	if err != nil {
		return err
	}
	return nil
}

func (s *myService) stopLogic() {
	if s.client != nil {
		wclient.Shutdown(s.client)
	}
}

func main() {
	configFile := flag.String("config", "", "Path to the configuration file.")

	isService, err := svc.IsWindowsService()
	if err != nil {
		isService = false
	}

	if isService {
		flag.Parse()
		runAsService(*configFile)
	} else {
		if len(os.Args) < 2 {
			printUsage()
			return
		}
		cmd := strings.ToLower(os.Args[1])
		switch cmd {
		case "run":
			if len(os.Args) != 3 {
				fmt.Println("Usage: run <config_file_path>")
				printUsage()
				return
			}
			err = runService(os.Args[2])
		case "install":
			if len(os.Args) != 4 {
				fmt.Println("Usage: install <service_name> <config_file_path>")
				printUsage()
				return
			}
			err = installService(os.Args[2], os.Args[3])
		case "remove":
			if len(os.Args) != 3 {
				fmt.Println("Usage: remove <service_name>")
				printUsage()
				return
			}
			err = removeService(os.Args[2])
		default:
			err = nil
		}
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}
}

func runAsService(configPath string) bool {
	if configPath == "" {
		return false
	}

	srvArgs, err := loadServiceConfig(configPath)
	if err != nil {
		return false
	}

	instance := &myService{}
	instance.params = srvArgs
	if err = svc.Run(serviceAppName, instance); err != nil {
		return false
	}
	return true
}

func printUsage() {
	fmt.Printf("Usage: %s <command>\n", os.Args[0])
	fmt.Println(" command:")
	fmt.Println("  install <ServiceName> <Path-To-Config-File>  Install windows service.")
	fmt.Println("  remove  <ServiceName>                        Remove windows service.")
	fmt.Println("  run     <Path-To-Config-File>                Execute as CLI.")
}

func installService(serviceName, configFile string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	absConfigFile, err := filepath.Abs(configFile)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("ERROR: service is exists '%s'", serviceName)
	}
	commandArgs := []string{"--config", absConfigFile}
	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceName,
		StartType:   mgr.StartManual,
	}, commandArgs...)
	if err != nil {
		return fmt.Errorf("ERROR: create service fail. %w", err)
	}
	defer s.Close()
	return nil
}

func removeService(serviceName string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("ERROR: service not found %s", serviceName)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("ERROR: check service status fail. %w", err)
	}
	if status.State == svc.Running {
		_, err = s.Control(svc.Stop)
		if err != nil {
			return fmt.Errorf("ERROR: stop service fail. %w", err)
		}
		time.Sleep(1 * time.Second)
	}
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("ERROR: delete service fail. %w", err)
	}
	return nil
}

func runService(configPath string) error {

	srvArgs, err := loadServiceConfig(configPath)
	if err != nil {
		return err
	}
	wclient.RunCmd(srvArgs)
	return nil
}
func loadServiceConfig(path string) (*wclient.StartupArgs, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	conf := &wclient.StartupArgs{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&conf)
	return conf, err
}
