if [ $# -le 0 ];

then
  echo "No Argument or illegal argument was passed, you must enter a correct IP to be bocked"

else
  curl https://raw.githubusercontent.com/Actariss/Stage-2024-AR-TrendM-Pfsense/master/AR_Pfsense.py > AR_Pfsense.py
  chmod +x ./AR_Pfsense.py
  python3 ./AR_Pfsense.py "$1"
fi


