docker run -d -it --rm --name ajh-website -p 8080:8080 \
  -v "/home/rpi2b/AJH-website/AJH-Website/.env:/app/.env" \
  -v "/home/rpi2b/AJH-website/AJH-Website/instance:/app/instance" \
  -v "/home/rpi2b/AJH-website/AJH-Website:/app/src" \
  ajh-website_web \
  python /app/src/server.py



