FROM nginx:alpine
RUN echo '<html><body style="background: #282c34; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: sans-serif;"> \
          <h1>Decodx09 EKS Cluster is Live</h1> \
          </body></html>' > /usr/share/nginx/html/index.html
EXPOSE 80