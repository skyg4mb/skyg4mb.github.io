Aqui describire el proceso de creacion de un laboratorio de analisis de malware con cuckoo, en caso de que se presenten errores dire como los vo solucionando.

Para la instalacion de cuckoo utilizare una maquina virtual de Ubuntu 18.04 server:

Lo primero que  configurare sera la instalcion de las priincipales dependencias.

sudo apt install python python-pip python-dev libffi-dev libssl-dev virtualbox virtualbox-guest-additions-iso virtualbox-dkms libjpeg-dev zlib1g-dev swig ssdeep tcpdump mongodb volatility -y

"recuerden que la maquina debe tener conexion a red" , personalmente prefiero conectarme a la pagina mediante ssh y trabajar directamente en mi maquina y no en la maquina virtual.

sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

sudo pip install -U weasyprint==0.42.2

sudo pip install -U cuckoo


aqui obtenemos un error 

pyrsistent requires Python '>=3.5' but the running Python is 2.7.17

la forma de solucionarlo:

pip install pyrsistent==0.16.1

luego sudo apt install python3-pip

y

pip3 install pyrsistent==0.16.1

sudo pip install -U cuckoo

con ubuntu 18.04 se presentan muchos problemas con esa libreria, mejor 20.04

En ubuntu 20.04 hay que hacer unos procedimientos adicionales para python-pip y volatility

cambio de planes a elastic 

inicio de instalacion en ubuntu 20.04, al parece deben estar activas algunas propiedades de seguridad de elastic.


