# change [yourname_server] to yourname server
scp backend/app.py backend/config.py backend/HelperFunction.py backend/SchedulerFunction.py backend/.env setup.sh backend/requirements.txt [yourname_server]:~/eagle/backend
scp -r backend/api  [yourname_server]:~/eagle/backend
ssh [yourname_server] 'sudo systemctl restart gunicorn && systemctl status gunicorn'


