
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64" # ОС Ubuntu 22.04 LTS
  config.vm.hostname = "nir"
	config.vm.define "nir"

   # Задаем статический IP для доступа к Firefly API (порт 5000) и просмотра HTML отчетов
  config.vm.network "private_network", ip: "192.168.56.10"

  # Настройка ресурсов VirtualBox
  config.vm.provider "virtualbox" do |vb|
    vb.name = "SmartScan_Env"
    vb.memory = "8192" # 8 ГБ ОЗУ (необходимо для работы Mythril и локальной сети Fabric)
    vb.cpus = 4        # 4 ядра для параллельного фаззинга
    vb.gui = false
    # Включаем вложенную виртуализацию, если планируется запускать Docker внутри
    vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
  end

  # Синхронизация папки проекта с хост-машиной
  # Текущая директория хоста будет доступна в /vagrant на гостевой машине
  config.vm.synced_folder ".", "/vagrant"

  # Скрипт инициализации, который выполнится при первом vagrant up
  config.vm.provision "shell", inline: <<-SHELL
    echo "[*] Starting provisioning..."
    
    # Копируем скрипт инициализации и даем права
    cp /vagrant/init.sh /home/vagrant/init.sh
    chmod +x /home/vagrant/init.sh
    
    # Запускаем скрипт установки от имени пользователя vagrant
    su - vagrant -c "bash /home/vagrant/init.sh"
    
    echo "[+] Provisioning complete. Type 'vagrant ssh' to access the environment."
  SHELL
end

