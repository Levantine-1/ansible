stop_services(){
        echo "$(date) - Stopping Services"
        # pm2 stop /opt/theia/rabbitMQ/rbt.py --interpreter python3
        # pm2 stop /opt/theia/frontend/py/app.py --interpreter python3
        # pm2 stop "tailon -b localhost:1337 -f /opt/theia/logs/* /var/log/apache2/*.log /var/log/syslog /var/log/auth.log /var/log/dmesg /var/log/rabbitmq/log/crash.log /var/log/rabbitmq/*.log" -n tailon
        pm2 stop app rbt tailon
}

start_services(){
        echo "$(date) = Starting Services"
        # pm2 start /opt/theia/rabbitMQ/rbt.py --interpreter python3
        #pm2 start /opt/theia/frontend/py/app.py --interpreter python3
        # pm2 start "tailon -b localhost:1337 -f /opt/theia/logs/* /var/log/apache2/*.log /var/log/syslog /var/log/auth.log /var/log/dmesg /var/log/rabbitmq/log/crash.log /var/log/rabbitmq/*.log" -n tailon
        pm2 start tailon rbt app
}

main_function(){
        stop_services
        start_services
}

main_function >> /home/automation/app_maintenance.log
