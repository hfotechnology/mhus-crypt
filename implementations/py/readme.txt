

docker run -it --name python -v .../py:/x python:3

docker start -ia python
docker exec -it python /bin/bash

docker rm python

---

docker run -it --name python2 -v .../py:/x python:2

docker start -ia python2
docker exec -it python2 /bin/bash

docker rm python2
