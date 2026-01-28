# CI-CD

The goal was to learn how to setup a, albiet basic, jenkins pipeline. The pipeline has a few steps:

- Deploy a Pod that runs a custom 'docker in docker' image
- Downloads this repository
- Builds the project, tags the new image with the build number and pushes it to github.
- After pushing the image, the image/version number is then subsitituted into the deployment file in /kubernetes for the frontend with some env var magic and YQ
  - This works for now, but ideally id also setup something for the backend with the same logic
- After the new image is added to the deployment manifest push it back to github
  - This is done so the 'CD' portion of the pipeline (currently ArgoCD) can pickup the changes to the deployment and deploy a pod with the new version of the portfolio application
